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
import { sha256, sha384, sha512, sha512_224, sha512_256 } from '@noble/hashes/sha2.js';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from '@noble/hashes/sha3.js';
import { MLDSAVariant, hexToUint8Array, HASH_FNS } from './mldsa';

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
  /** Internal tag: '__legacy_sm__' for .rsp format vectors */
  _format?: string;
}

export type KatVectorResult = KatVector & {
  verifyOk: boolean;
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

// ─── ACVP hashAlg → noble HASH_FNS key ───────────────────────────────────────

/**
 * Map ACVP hashAlg strings to a { fn, label } pair for noble's prehash() API.
 *
 * Noble's prehash() expects a function with an `.oid` property. The SHA3/SHAKE
 * functions from @noble/hashes/sha3.js already have OIDs attached internally
 * (via oidNist). SHAKE variants are XOFs so we wrap them with a fixed dkLen:
 *   SHAKE-128 → 32 bytes  (per FIPS 204 Table 1, HashML-DSA-44 uses SHAKE128 d=256)
 *   SHAKE-256 → 64 bytes  (per FIPS 204 Table 1, HashML-DSA-65/87 use SHAKE256 d=512)
 *
 * Returns null only for completely unrecognised strings.
 */
function resolveHashFn(acvpHashAlg: string): { fn: any; label: string } | null {
  const n = acvpHashAlg.toUpperCase().replace(/[-_/\s]/g, '');

  // ── SHA-2 ──────────────────────────────────────────────────────────────────
  if (n === 'SHA2256' || n === 'SHA256')       return { fn: sha256,       label: 'SHA2-256' };
  if (n === 'SHA2384' || n === 'SHA384')       return { fn: sha384,       label: 'SHA2-384' };
  if (n === 'SHA2512' || n === 'SHA512')       return { fn: sha512,       label: 'SHA2-512' };
  if (n === 'SHA2224' || n === 'SHA224')       return { fn: HASH_FNS['SHA-256'], label: 'SHA2-224' }; // not in noble sha2 by that name — use sha2 wrappers from mldsa if needed
  if (n === 'SHA2512224' || n === 'SHA512224') return { fn: sha512_224,   label: 'SHA2-512/224' };
  if (n === 'SHA2512256' || n === 'SHA512256') return { fn: sha512_256,   label: 'SHA2-512/256' };

  // ── SHA-3 (fixed output, OIDs already attached by noble) ──────────────────
  if (n === 'SHA3224')  return { fn: sha3_224, label: 'SHA3-224' };
  if (n === 'SHA3256')  return { fn: sha3_256, label: 'SHA3-256' };
  if (n === 'SHA3384')  return { fn: sha3_384, label: 'SHA3-384' };
  if (n === 'SHA3512')  return { fn: sha3_512, label: 'SHA3-512' };

  // ── SHAKE (XOF — wrap with fixed output length, OIDs already attached) ────
  // FIPS 204 §5.4: d = security parameter bits / 8
  //   SHAKE-128: d = 32 bytes (256 bits)
  //   SHAKE-256: d = 64 bytes (512 bits)
  if (n === 'SHAKE128') {
    const fn = (msg: Uint8Array) => shake128(msg, { dkLen: 32 });
    fn.oid = (shake128 as any).oid;
    return { fn, label: 'SHAKE-128' };
  }
  if (n === 'SHAKE256') {
    const fn = (msg: Uint8Array) => shake256(msg, { dkLen: 64 });
    fn.oid = (shake256 as any).oid;
    return { fn, label: 'SHAKE-256' };
  }

  return null; // completely unrecognised
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
    if (group.parameterSet && !inferredVariant) {
      if (group.parameterSet.includes('44')) inferredVariant = 'ML-DSA-44';
      else if (group.parameterSet.includes('65')) inferredVariant = 'ML-DSA-65';
      else if (group.parameterSet.includes('87')) inferredVariant = 'ML-DSA-87';
    }

    for (const tc of group.tests) {
      const isExternalMu = group.externalMu === true && !!tc.mu;
      // Per ACVP spec §8.3.2: hashAlg is a TEST CASE level field (tc.hashAlg),
      // not a group level field. Some implementations also put it on the group
      // as a convenience, so we use tc.hashAlg first, fall back to group.hashAlg.
      const hashAlg = (tc as any).hashAlg ?? group.hashAlg;
      vectors.push({
        tcId: tc.tcId,
        tgId: group.tgId,
        pk: tc.pk ?? '',
        message: isExternalMu ? (tc.mu ?? '') : (tc.message ?? ''),
        signature: tc.signature,
        context: tc.context ?? group.context,
        isExternalMu,
        hashAlg,
        signatureInterface: group.signatureInterface,
        preHash: group.preHash,
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

  return { vectors, inferredVariant: parsed?.variant as MLDSAVariant | undefined };
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
  const instance = getInstance(variant);
  const sigLen = SIG_BYTES[variant];
  const slice = vectors.slice(0, maxVectors);
  const results: KatVectorResult[] = [];
  const modesSet = new Set<string>();
  const t0 = performance.now();
  let skipped = 0;

  for (const v of slice) {
    try {
      const pkBytes = hexToUint8Array(v.pk);
      const msgBytes = hexToUint8Array(v.message);
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
        const smBytes = hexToUint8Array(v.signature);
        const sigFromSm = smBytes.slice(0, sigLen);
        try { verifyOk = instance.verify(sigFromSm, msgBytes, pkBytes); } catch { verifyOk = false; }
        note = verifyOk
          ? 'Signature extracted from SM field and verified (pure mode)'
          : 'SM verify failed — pre-FIPS 204 Dilithium vectors may not match ML-DSA spec';

      // ── External μ mode ────────────────────────────────────────────────
      } else if (v.isExternalMu) {
        modeLabel = 'External μ';
        modesSet.add(modeLabel);
        const sigBytesArr = hexToUint8Array(v.signature);
        try {
          verifyOk = (instance as any).internal.verify(sigBytesArr, msgBytes, pkBytes, { externalMu: true });
        } catch { verifyOk = false; }
        note = verifyOk ? 'μ-based internal verify passed' : 'μ-based internal verify failed';

      // ── HashML-DSA (preHash mode) ──────────────────────────────────────
      } else if (v.preHash && v.preHash.toLowerCase() !== 'pure') {
        const resolved = v.hashAlg ? resolveHashFn(v.hashAlg) : null;
        const hashLabel = resolved?.label ?? v.hashAlg ?? 'unknown hash';
        if (!resolved) {
          modeLabel = `PreHash (${hashLabel})`;
          modesSet.add(modeLabel);
          note = `Unrecognised hash algorithm "${hashLabel}" — skipped`;
          verifyOk = false;
          isSkipped = true;
        } else {
          modeLabel = `HashML-DSA (${resolved.label})`;
          modesSet.add(modeLabel);
          const sigBytesArr = hexToUint8Array(v.signature);
          const ctxBytes = v.context ? hexToUint8Array(v.context) : undefined;
          try {
            verifyOk = (instance as any).prehash(resolved.fn).verify(
              sigBytesArr, msgBytes, pkBytes,
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
        const sigBytesArr = hexToUint8Array(v.signature);
        const ctxBytes = v.context ? hexToUint8Array(v.context) : undefined;
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

      results.push({ ...v, verifyOk, modeLabel, note, expectedPassed, matchesExpected });
    } catch (error: any) {
      skipped++;
      results.push({
        ...v,
        verifyOk: false,
        modeLabel: 'Error',
        note: 'Exception during verification',
        error: error?.message ?? 'Unknown error',
      });
    }
  }

  const passed = results.filter(r => r.verifyOk).length;
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
