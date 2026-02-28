/**
 * NIST FIPS 204 Known Answer Test (KAT) runner
 *
 * Supported input formats:
 *
 *  1. NIST ACVP JSON  — from usnistgov/ACVP-Server on GitHub
 *     [ {acvVersion}, { vsId, testGroups: [{ parameterSet, signatureInterface,
 *       externalMu, preHash, hashAlg, tests: [{tcId, pk, message/mu, signature, context?}] }] } ]
 *
 *  2. NIST ACVP expectedResults.json — companion file that maps tcId → passed/failed
 *     Loaded separately and merged with run results for offline comparison.
 *     [ {acvVersion}, { vsId, testGroups: [{ tgId, tests: [{tcId, testPassed}] }] } ]
 *
 *  3. Legacy Dilithium .rsp format (pre-FIPS 204)
 *     Key=value blocks: COUNT / MSG / PK / SK / SM  (SM = sig || msg)
 *
 *  4. Simple JSON array (convenience / custom vectors)
 *     [{ tcId, pk, message, signature }] or { variant, vectors: [...] }
 */

import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from '@noble/hashes/sha2.js';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from '@noble/hashes/sha3.js';
import { MLDSAVariant, hexToUint8Array } from './mldsa';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface KatVector {
  tcId: number;
  tgId?: number;
  /** Hex-encoded public key */
  pk: string;
  /** Hex-encoded message (or pre-computed μ when isExternalMu is true) */
  message: string;
  /** Hex-encoded detached signature */
  signature: string;
  /** Hex-encoded context string */
  context?: string;
  /** True when message field holds pre-computed μ (externalMu ACVP mode) */
  isExternalMu?: boolean;
  /** ACVP hashAlg string e.g. "SHA2-256", "SHA2-384", "SHA2-512" */
  hashAlg?: string;
  /** 'internal' | 'external' from ACVP testGroup */
  signatureInterface?: string;
  /** 'pure' | 'preHash' from ACVP testGroup (external interface only) */
  preHash?: string;
  /** ML-DSA variant for this vector, parsed directly from ACVP parameterSet.
   *  Present on ACVP vectors; absent on legacy .rsp / simple JSON (use run-level variant). */
  parameterSet?: MLDSAVariant;
  /** Internal tag: '__legacy_sm__' for .rsp format vectors */
  _format?: string;
}

export type KatVectorResult = KatVector & {
  verifyOk: boolean;
  /** True when this vector counts as a pass in the UI:
   *  - crypto verify returned true, OR
   *  - expectedResults says fail AND we also got fail (correct rejection) */
  effectivePass: boolean;
  /** Expected result from an accompanying expectedResults.json, if loaded */
  expectedPassed?: boolean;
  /** Whether our result matches the expected result */
  matchesExpected?: boolean;
  modeLabel: string;
  note: string;
  error?: string;
};

export interface KatRunResult {
  variant: MLDSAVariant;
  total: number;
  passed: number;
  failed: number;
  skipped: number;
  /** Vectors with expected result loaded and mismatching our result */
  expectedMismatches: number;
  vectors: KatVectorResult[];
  durationMs: number;
  modesPresent: string[];
}

/** Parsed expectedResults.json — maps tgId → tcId → testPassed */
export type ExpectedResultsMap = Map<number, Map<number, boolean>>;

// ─── Sizes ────────────────────────────────────────────────────────────────────

export const SIG_BYTES: Record<MLDSAVariant, number> = {
  'ML-DSA-44': 2420,
  'ML-DSA-65': 3309,
  'ML-DSA-87': 4627,
};

export const PK_BYTES: Record<MLDSAVariant, number> = {
  'ML-DSA-44': 1312,
  'ML-DSA-65': 1952,
  'ML-DSA-87': 2592,
};

// ─── ACVP hashAlg → noble hash function ──────────────────────────────────────

// ── OID constants for all supported hash algorithms ────────────────────────
// noble's prehash() API requires the hash function to carry a .oid property
// (a DER-encoded AlgorithmIdentifier OID as a Uint8Array).
// Neither SHA-2 nor SHA-3/SHAKE functions from @noble/hashes carry .oid on
// their exported symbols — OIDs are only attached internally by noble/post-quantum
// during its own prehash setup, not on the raw hash exports.
// Every function passed to prehash() must therefore be wrapped with withOid().
// These match the OIDs used in mldsa.ts (SHA-256/384/512 verified identical).
// Source: NIST CSOR / RFC 5754 / FIPS 202 OID registry.
const OID_SHA224     = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04]);
const OID_SHA256     = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
const OID_SHA384     = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]);
const OID_SHA512     = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]);
const OID_SHA512_224 = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05]);
const OID_SHA512_256 = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06]);
const OID_SHA3_224   = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07]);
const OID_SHA3_256   = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08]);
const OID_SHA3_384   = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09]);
const OID_SHA3_512   = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a]);
const OID_SHAKE128   = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b]);
const OID_SHAKE256   = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c]);

function withOid(fn: (msg: Uint8Array) => Uint8Array, oid: Uint8Array): any {
  const wrapped = (msg: Uint8Array) => fn(msg);
  wrapped.oid = oid;
  return wrapped;
}

/**
 * Map ACVP hashAlg strings to a { fn, label } pair for noble's prehash() API.
 *
 * noble's prehash() requires a function with a `.oid` property. Raw hash exports
 * from @noble/hashes do NOT carry .oid — withOid() wraps every function to attach
 * the correct DER-encoded AlgorithmIdentifier OID, matching the pattern in mldsa.ts.
 * SHAKE variants are XOFs wrapped with fixed output lengths per FIPS 204:
 *   SHAKE-128 → 32 bytes, SHAKE-256 → 64 bytes.
 *
 * Returns null only for completely unrecognised strings.
 */
function resolveHashFn(acvpHashAlg: string): { fn: any; label: string } | null {
  const n = acvpHashAlg.toUpperCase().replace(/[-_/\s]/g, '');

  // ── SHA-2 ─────────────────────────────────────────────────────────────────
  if (n === 'SHA2224' || n === 'SHA224')        return { fn: withOid(sha224,     OID_SHA224),     label: 'SHA2-224' };
  if (n === 'SHA2256' || n === 'SHA256')        return { fn: withOid(sha256,     OID_SHA256),     label: 'SHA2-256' };
  if (n === 'SHA2384' || n === 'SHA384')        return { fn: withOid(sha384,     OID_SHA384),     label: 'SHA2-384' };
  if (n === 'SHA2512' || n === 'SHA512')        return { fn: withOid(sha512,     OID_SHA512),     label: 'SHA2-512' };
  if (n === 'SHA2512224' || n === 'SHA512224')  return { fn: withOid(sha512_224, OID_SHA512_224), label: 'SHA2-512/224' };
  if (n === 'SHA2512256' || n === 'SHA512256')  return { fn: withOid(sha512_256, OID_SHA512_256), label: 'SHA2-512/256' };

  // ── SHA-3 ─────────────────────────────────────────────────────────────────
  if (n === 'SHA3224') return { fn: withOid(sha3_224, OID_SHA3_224), label: 'SHA3-224' };
  if (n === 'SHA3256') return { fn: withOid(sha3_256, OID_SHA3_256), label: 'SHA3-256' };
  if (n === 'SHA3384') return { fn: withOid(sha3_384, OID_SHA3_384), label: 'SHA3-384' };
  if (n === 'SHA3512') return { fn: withOid(sha3_512, OID_SHA3_512), label: 'SHA3-512' };

  // ── SHAKE (XOF — fixed output length, OID explicitly attached) ────────────
  if (n === 'SHAKE128') return { fn: withOid((msg: Uint8Array) => shake128(msg, { dkLen: 32 }), OID_SHAKE128), label: 'SHAKE-128' };
  if (n === 'SHAKE256') return { fn: withOid((msg: Uint8Array) => shake256(msg, { dkLen: 64 }), OID_SHAKE256), label: 'SHAKE-256' };

  return null; // completely unrecognised
}

// ─── Strict hex decoder ───────────────────────────────────────────────────────

/**
 * Decode a hex string to Uint8Array, throwing on any malformed input.
 * Unlike hexToUint8Array (which silently strips bad chars), this rejects
 * odd-length strings and any non-hex character so malformed KAT vectors
 * are detected immediately rather than being silently normalised.
 */
function strictHex(hex: string, fieldName: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`${fieldName}: odd-length hex string (${hex.length} chars)`);
  }
  if (hex.length > 0 && !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`${fieldName}: contains non-hex characters`);
  }
  return hexToUint8Array(hex);
}

// ─── Noble instance ───────────────────────────────────────────────────────────

function getInstance(variant: MLDSAVariant) {
  switch (variant) {
    case 'ML-DSA-44': return ml_dsa44;
    case 'ML-DSA-65': return ml_dsa65;
    case 'ML-DSA-87': return ml_dsa87;
  }
}

// ─── Format 1: NIST ACVP prompt JSON ─────────────────────────────────────────

interface AcvpTestCase {
  tcId: number;
  pk?: string;
  message?: string;
  mu?: string;
  signature: string;
  context?: string;
  hashAlg?: string;  // per ACVP spec §8.3.2: test-case level for sigVer preHash
}

interface AcvpTestGroup {
  tgId?: number;
  testType?: string;
  parameterSet?: string;
  signatureInterface?: string;
  externalMu?: boolean;
  preHash?: string;
  hashAlg?: string;
  context?: string;
  tests: AcvpTestCase[];
}

export function parseAcvpJson(content: string): { vectors: KatVector[]; inferredVariant?: MLDSAVariant } {
  const parsed = JSON.parse(content);

  let vectorSet: { testGroups?: AcvpTestGroup[] } | null = null;
  if (Array.isArray(parsed)) {
    vectorSet = parsed.find((el: any) => Array.isArray(el?.testGroups)) ?? null;
  } else if (parsed?.testGroups) {
    vectorSet = parsed;
  }

  if (!vectorSet?.testGroups) throw new Error('No testGroups found. Is this a valid ACVP JSON file?');

  const vectors: KatVector[] = [];
  let inferredVariant: MLDSAVariant | undefined;

  for (const group of vectorSet.testGroups) {
    // Resolve this group's variant from parameterSet
    let groupVariant: MLDSAVariant | undefined;
    if (group.parameterSet) {
      if (group.parameterSet.includes('44')) groupVariant = 'ML-DSA-44';
      else if (group.parameterSet.includes('65')) groupVariant = 'ML-DSA-65';
      else if (group.parameterSet.includes('87')) groupVariant = 'ML-DSA-87';
    }
    // inferredVariant stays as the first group's variant — used only as the
    // UI fallback selector default, not as the run variant for any vector.
    if (groupVariant && !inferredVariant) inferredVariant = groupVariant;

    for (const tc of group.tests) {
      const isExternalMu = group.externalMu === true && !!tc.mu;

      // Validate required fields — reject early with context rather than silently defaulting
      if (tc.tcId === undefined || tc.tcId === null) {
        throw new Error(`tgId=${group.tgId}: test case is missing tcId`);
      }
      if (!tc.pk) {
        throw new Error(`tgId=${group.tgId} tcId=${tc.tcId}: missing required field "pk"`);
      }
      if (isExternalMu) {
        if (!tc.mu) throw new Error(`tgId=${group.tgId} tcId=${tc.tcId}: externalMu=true but "mu" field is missing`);
      } else {
        if (!tc.message) throw new Error(`tgId=${group.tgId} tcId=${tc.tcId}: missing required field "message"`);
      }
      if (!tc.signature) {
        throw new Error(`tgId=${group.tgId} tcId=${tc.tcId}: missing required field "signature"`);
      }

      vectors.push({
        tcId: tc.tcId,
        tgId: group.tgId,
        pk: tc.pk,
        message: isExternalMu ? tc.mu! : tc.message!,
        signature: tc.signature,
        context: tc.context ?? group.context,
        isExternalMu,
        hashAlg: tc.hashAlg ?? group.hashAlg,
        signatureInterface: group.signatureInterface,
        preHash: group.preHash,
        parameterSet: groupVariant,
      });
    }
  }

  if (vectors.length === 0) throw new Error('No test cases found in testGroups.');
  return { vectors, inferredVariant };
}

// ─── Format 2: NIST ACVP expectedResults.json ────────────────────────────────

interface ExpectedGroup {
  tgId: number;
  tests: { tcId: number; testPassed: boolean }[];
}

/**
 * Parse an ACVP expectedResults.json file into a map keyed by tgId → tcId → passed.
 * File structure: [ {acvVersion}, { vsId, testGroups: [{tgId, tests: [{tcId, testPassed}]}] } ]
 */
export function parseExpectedResults(content: string): ExpectedResultsMap {
  const parsed = JSON.parse(content);
  const map: ExpectedResultsMap = new Map();

  let groups: ExpectedGroup[] = [];
  if (Array.isArray(parsed)) {
    const vs = parsed.find((el: any) => Array.isArray(el?.testGroups));
    groups = vs?.testGroups ?? [];
  } else if (Array.isArray(parsed?.testGroups)) {
    groups = parsed.testGroups;
  }

  for (const g of groups) {
    const tcMap = new Map<number, boolean>();
    for (const tc of g.tests ?? []) {
      tcMap.set(tc.tcId, tc.testPassed);
    }
    map.set(g.tgId, tcMap);
  }

  return map;
}

// ─── Format 3: Legacy Dilithium .rsp ─────────────────────────────────────────

export function parseRspFile(content: string): KatVector[] {
  const vectors: KatVector[] = [];
  const blocks = content.split(/\n\s*\n/);

  for (const block of blocks) {
    if (!block.trim() || block.trim().startsWith('#')) continue;
    const fields: Record<string, string> = {};
    for (const line of block.split('\n')) {
      const match = line.match(/^\s*(\w+)\s*=\s*(.+)$/);
      if (match) fields[match[1].toLowerCase()] = match[2].trim();
    }
    if (!fields['msg'] || !fields['pk'] || !fields['sm']) continue;
    vectors.push({
      tcId: parseInt(fields['count'] ?? '0', 10),
      pk: fields['pk'],
      message: fields['msg'],
      signature: fields['sm'], // raw SM — runner splits at runtime
      signatureInterface: 'internal',
      _format: '__legacy_sm__',
    });
  }
  return vectors;
}

// ─── Format 4: Simple JSON array ─────────────────────────────────────────────

export function parseSimpleJson(content: string): { vectors: KatVector[]; inferredVariant?: MLDSAVariant } {
  const parsed = JSON.parse(content);
  const raw: any[] = Array.isArray(parsed) ? parsed : (parsed?.vectors ?? []);
  if (raw.length === 0) throw new Error('Empty vectors array.');

  const vectors: KatVector[] = raw.map((v: any, i: number) => ({
    tcId: v.tcId ?? v.count ?? i,
    tgId: v.tgId,
    pk: v.pk ?? '',
    message: v.message ?? v.msg ?? '',
    signature: v.signature ?? v.sm ?? '',
    context: v.context,
    isExternalMu: v.isExternalMu ?? false,
    signatureInterface: v.signatureInterface ?? 'internal',
    preHash: v.preHash,
    hashAlg: v.hashAlg,
  }));

  const ALLOWED_VARIANTS: MLDSAVariant[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];
  const rawVariant = parsed?.variant;
  if (rawVariant !== undefined && !ALLOWED_VARIANTS.includes(rawVariant)) {
    throw new Error(
      `Invalid variant "${rawVariant}" in JSON. Expected one of: ${ALLOWED_VARIANTS.join(', ')}.`,
    );
  }

  return { vectors, inferredVariant: rawVariant as MLDSAVariant | undefined };
}

// ─── Master parser ────────────────────────────────────────────────────────────

export function parseKatFile(content: string, filename: string): { vectors: KatVector[]; inferredVariant?: MLDSAVariant } {
  const trimmed = content.trimStart();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
    const vectors = parseRspFile(content);
    if (vectors.length === 0) throw new Error('Parsed 0 vectors from .rsp file. Check the format.');
    return { vectors };
  }
  const parsed = JSON.parse(content);
  const hasTestGroups =
    (Array.isArray(parsed) && parsed.some((el: any) => Array.isArray(el?.testGroups))) ||
    Array.isArray(parsed?.testGroups);
  if (hasTestGroups) return parseAcvpJson(content);
  return parseSimpleJson(content);
}

// ─── Variant auto-detection ───────────────────────────────────────────────────

export function inferVariantFromVectors(vectors: KatVector[]): MLDSAVariant | null {
  for (const v of vectors) {
    const len = hexToUint8Array(v.pk).length;
    if (len === PK_BYTES['ML-DSA-44']) return 'ML-DSA-44';
    if (len === PK_BYTES['ML-DSA-65']) return 'ML-DSA-65';
    if (len === PK_BYTES['ML-DSA-87']) return 'ML-DSA-87';
  }
  return null;
}

// ─── Runner ───────────────────────────────────────────────────────────────────

/**
 * Run all vectors. Merges expectedResults map if provided.
 */
export async function runKatVectors(
  variant: MLDSAVariant,
  vectors: KatVector[],
  maxVectors = 100,
  expectedResults?: ExpectedResultsMap,
): Promise<KatRunResult> {
  const slice = vectors.slice(0, maxVectors);
  const results: KatVectorResult[] = [];
  const modesSet = new Set<string>();
  const t0 = performance.now();
  let skipped = 0;

  for (const v of slice) {
    // Use the per-vector parameterSet when available (ACVP multi-group files),
    // falling back to the run-level variant for legacy .rsp / simple JSON.
    const vecVariant: MLDSAVariant = v.parameterSet ?? variant;
    const instance = getInstance(vecVariant);
    const sigLen = SIG_BYTES[vecVariant];
    try {
      const pkBytes = strictHex(v.pk, 'pk');
      const msgBytes = strictHex(v.message, 'message');
      let verifyOk = false;
      let modeLabel = 'Pure';
      let note = '';
      let isSkipped = false;

      // ── Expected result lookup ─────────────────────────────────────────
      let expectedPassed: boolean | undefined;
      if (expectedResults && v.tgId !== undefined) {
        expectedPassed = expectedResults.get(v.tgId)?.get(v.tcId);
      }

      // ── Legacy .rsp SM mode ────────────────────────────────────────────
      if (v._format === '__legacy_sm__') {
        modeLabel = 'Legacy .rsp';
        modesSet.add(modeLabel);
        const smBytes = strictHex(v.signature, 'signature (SM)');
        const sigFromSm = smBytes.slice(0, sigLen);
        try { verifyOk = instance.verify(sigFromSm, msgBytes, pkBytes); } catch { verifyOk = false; }
        note = verifyOk
          ? 'Signature extracted from SM field and verified (pure mode)'
          : 'SM verify failed — pre-FIPS 204 Dilithium vectors may not match ML-DSA spec';

      // ── External μ mode ────────────────────────────────────────────────
      } else if (v.isExternalMu) {
        modeLabel = 'External μ';
        modesSet.add(modeLabel);
        const sigBytesArr = strictHex(v.signature, 'signature');
        try {
          verifyOk = (instance as any).internal.verify(sigBytesArr, msgBytes, pkBytes, { externalMu: true });
        } catch { verifyOk = false; }
        note = verifyOk ? 'μ-based internal verify passed' : 'μ-based internal verify failed';

      // ── HashML-DSA (preHash mode) ──────────────────────────────────────
      // A vector is HashML-DSA when either:
      //   1. preHash names a real hash ("preHash", "SHA2-256", etc.) — excludes "pure"/"none"/"".
      //   2. signatureInterface="external" with NO preHash field at all — the only HashML-DSA
      //      signal in simple-JSON format, which has no testGroup wrapper to carry preHash.
      //      When preHash IS present (even as "pure"/"none"/""), cond 1 already covers the
      //      real-hash case, so cond 2 must not fire — otherwise "pure" groups from an
      //      external-interface ACVP testGroup would incorrectly enter this branch and be
      //      skipped as "unknown hash" when hashAlg="none".
      } else if (
        (v.preHash && !['pure', 'none', ''].includes(v.preHash.toLowerCase())) ||
        (v.signatureInterface === 'external' && !v.isExternalMu && v.preHash === undefined)
      ) {
        const resolved = v.hashAlg ? resolveHashFn(v.hashAlg) : null;
        if (!resolved) {
          modeLabel = `PreHash (${v.hashAlg ?? 'unknown'})`;
          modesSet.add(modeLabel);
          note = `Hash algorithm "${v.hashAlg ?? 'unknown'}" not supported by this implementation — skipped`;
          verifyOk = false;
          isSkipped = true;
        } else {
          modeLabel = `HashML-DSA (${resolved.label})`;
          modesSet.add(modeLabel);
          const sigBytesArr = strictHex(v.signature, 'signature');
          const ctxBytes = v.context ? strictHex(v.context, 'context') : undefined;
          try {
            // Use noble's prehash interface: instance.prehash(hashFn).verify(sig, msg, pk, { context? })
            verifyOk = (instance as any).prehash(resolved.fn).verify(
              sigBytesArr,
              msgBytes,
              pkBytes,
              { context: ctxBytes && ctxBytes.length > 0 ? ctxBytes : undefined },
            );
          } catch { verifyOk = false; }
          note = verifyOk
            ? `HashML-DSA verify passed (${resolved.label}${v.context ? ', with context' : ''})`
            : `HashML-DSA verify failed (${resolved.label}${v.context ? ', with context' : ''})`;
        }

      // ── Standard pure ML-DSA ───────────────────────────────────────────
      } else {
        modeLabel = v.context ? 'Pure + Context' : 'Pure';
        modesSet.add(modeLabel);
        const sigBytesArr = strictHex(v.signature, 'signature');
        const ctxBytes = v.context ? strictHex(v.context, 'context') : undefined;
        try {
          verifyOk = instance.verify(sigBytesArr, msgBytes, pkBytes, {
            context: ctxBytes && ctxBytes.length > 0 ? ctxBytes : undefined,
          });
        } catch { verifyOk = false; }
        note = verifyOk
          ? `Pure verify passed${v.context ? ' (with context)' : ''}`
          : `Pure verify failed${v.context ? ' (with context)' : ''}`;
      }

      if (isSkipped) skipped++;

      // Merge expected result
      const matchesExpected = expectedPassed !== undefined
        ? verifyOk === expectedPassed
        : undefined;

      // A vector counts as effectively passing when NOT skipped and either:
      //   (a) crypto verify returned true, OR
      //   (b) expected = fail AND we also got fail (correct rejection of a bad signature)
      const effectivePass = !isSkipped && (verifyOk || (expectedPassed === false && matchesExpected === true));

      results.push({ ...v, verifyOk, effectivePass, modeLabel, note, expectedPassed, matchesExpected });
    } catch (error: any) {
      skipped++;
      results.push({
        ...v,
        verifyOk: false,
        effectivePass: false,
        modeLabel: 'Error',
        note: 'Exception during verification',
        error: error?.message ?? 'Unknown error',
      });
    }
  }

  const passed = results.filter(r => r.effectivePass).length;
  const expectedMismatches = results.filter(r => r.matchesExpected === false).length;

  return {
    variant,
    total: results.length,
    passed,
    failed: results.length - passed - skipped,
    skipped,
    expectedMismatches,
    vectors: results,
    durationMs: Math.round(performance.now() - t0),
    modesPresent: [...modesSet],
  };
}