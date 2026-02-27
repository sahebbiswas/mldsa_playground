import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { Keccak, shake256 } from '@noble/hashes/sha3.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { Buffer } from 'buffer';

// ─── Types ──────────────────────────────────────────────────────────────────

export type MLDSAVariant = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
export type SignMode = 'pure' | 'hash-ml-dsa';
export type HashAlg = 'SHA-256' | 'SHA-384' | 'SHA-512';

export interface SigningOptions {
  mode: SignMode;
  contextText: string;  // UTF-8 text → encoded to bytes before use
  /** Raw hex-encoded context bytes. When present, takes priority over contextText.
   *  Use this when context is arbitrary binary (e.g. FIPS ACVP KAT vectors). */
  contextRawHex?: string;
  hashAlg: HashAlg;  // only used when mode === 'hash-ml-dsa'
  /**
   * When true, disables extra entropy inside the signer so that ML-DSA signatures
   * are computed deterministically for a given (key, message, context, mode).
   * This is wired through to noble's `extraEntropy: false` SigOpts flag.
   */
  deterministic?: boolean;
  checkLegacyMode?: boolean; // experimental: also check against old CRYSTALS-Dilithium formulation
}

export interface InspectionResult {
  valid: boolean;
  error?: string;
  legacyValid?: boolean;
  legacyMuHex?: string;
  meta?: {
    mode: SignMode;
    hashAlg?: HashAlg;
    contextHex: string;
  };
  details?: {
    variant: MLDSAVariant;
    signatureSize: number;
    publicKeySize: number;
  };
  components?: {
    challengeByteLen: number;
    challengeHex: string;  // c̃ – first N bytes of signature
    mPrimeHex: string;  // M' as constructed per FIPS 204
    trHex: string;  // tr  = SHAKE256(pk,  dkLen=64)
    muHex: string;  // μ   = SHAKE256(tr ∥ M', dkLen=64)
    zPreviewHex: string;  // 32-byte preview of z region
    hPreviewHex: string;  // 32-byte preview of h region (tail)
    reconstructedChallengeHex?: string; // c̃' = SHAKE256(μ ∥ w₁Encode(w'₁))
  };
}

// ─── Constants ───────────────────────────────────────────────────────────────

/** Number of commitment-hash bytes per variant (λ/8). */
const C_TILDE_BYTES: Record<MLDSAVariant, number> = {
  'ML-DSA-44': 32,
  'ML-DSA-65': 48,
  'ML-DSA-87': 64,
};

/** NIST hash functions with `.oid` property required by noble's prehash API. */
const SHA256_OID = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
const SHA384_OID = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]);
const SHA512_OID = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]);

const wrapHash = (fn: any, oid: Uint8Array) => {
  const wrapped = (msg: Uint8Array) => fn(msg);
  wrapped.oid = oid;
  return wrapped;
};

export const HASH_FNS: Record<HashAlg, any> = {
  'SHA-256': wrapHash(sha256, SHA256_OID),
  'SHA-384': wrapHash(sha384, SHA384_OID),
  'SHA-512': wrapHash(sha512, SHA512_OID),
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

export const getMLDSAInstance = (variant: MLDSAVariant) => {
  switch (variant) {
    case 'ML-DSA-44': return ml_dsa44;
    case 'ML-DSA-65': return ml_dsa65;
    case 'ML-DSA-87': return ml_dsa87;
    default: return ml_dsa87;
  }
};

export const hexToUint8Array = (hex: string): Uint8Array => {
  const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '');
  if (cleanHex.length % 2 !== 0) return new Uint8Array();
  try {
    return new Uint8Array(Buffer.from(cleanHex, 'hex'));
  } catch {
    return new Uint8Array();
  }
};

export const uint8ArrayToHex = (arr: Uint8Array): string =>
  Buffer.from(arr).toString('hex');

/**
 * Reconstruct M' exactly as noble does internally per FIPS 204:
 *   Pure:        [0x00, ctx_len, ...ctx, ...msg]
 *   HashML-DSA:  [0x01, ctx_len, ...ctx, ...OID, hash(msg)]
 */
function buildMPrime(
  mode: SignMode,
  ctx: Uint8Array,
  msg: Uint8Array,
  hashAlg: HashAlg,
): Uint8Array {
  if (mode === 'pure') {
    return concatBytes(new Uint8Array([0, ctx.length]), ctx, msg);
  }
  const hashFn = HASH_FNS[hashAlg];
  const hashed = hashFn(msg);
  return concatBytes(new Uint8Array([1, ctx.length]), ctx, (hashFn as any).oid as Uint8Array, hashed);
}

// ─── Public API ───────────────────────────────────────────────────────────────

export const inspectSignature = async (
  variant: MLDSAVariant,
  publicKeyHex: string,
  signatureHex: string,
  message: string | Uint8Array,
  opts: SigningOptions,
): Promise<InspectionResult> => {
  try {
    const instance = getMLDSAInstance(variant);
    const pk = hexToUint8Array(publicKeyHex);
    const sig = hexToUint8Array(signatureHex);
    const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;
    if (opts.contextRawHex !== undefined && opts.contextRawHex.length > 0) {
      if (opts.contextRawHex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(opts.contextRawHex)) {
        throw new Error(`contextRawHex is malformed: must be an even-length hex string, got "${opts.contextRawHex.slice(0, 20)}…"`);
      }
    }
    const contextBytes = opts.contextRawHex !== undefined
      ? hexToUint8Array(opts.contextRawHex)
      : new TextEncoder().encode(opts.contextText);
    const contextHex = uint8ArrayToHex(contextBytes);

    if (pk.length === 0 || sig.length === 0) {
      return { valid: false, error: 'Invalid hex input' };
    }

    // ── Verify ──────────────────────────────────────────────────────────────
    let isValid: boolean;
    let reconstructedChallengeHex: string | undefined;
    const challengeByteLen = C_TILDE_BYTES[variant];

    // Intercept Keccak.prototype.digest to capture the reconstructed challenge (cTilde')
    // We can't patch shake256.create because it's a frozen property in ESM/noble.
    const originalDigest = Keccak.prototype.digest;
    let capturedDigest: Uint8Array | undefined;

    Keccak.prototype.digest = function () {
      const res = originalDigest.apply(this);
      // Captured digest should be the size of the challenge/commitment hash (lambda/8)
      // and it's usually the one called internally by verify() at the end.
      if ((this as any).outputLen === challengeByteLen) {
        capturedDigest = res;
      }
      return res;
    };

    try {
      if (opts.mode === 'pure') {
        isValid = instance.verify(sig, msg, pk, { context: contextBytes.length ? contextBytes : undefined });
      } else {
        const hashFn = HASH_FNS[opts.hashAlg!];
        isValid = (instance as any).prehash(hashFn).verify(sig, msg, pk, {
          context: contextBytes.length ? contextBytes : undefined,
        });
      }
      if (capturedDigest) {
        reconstructedChallengeHex = uint8ArrayToHex(capturedDigest);
      }
    } finally {
      Keccak.prototype.digest = originalDigest;
    }

    // ── Experimental Legacy Check ──────────────────────────────────────────
    let legacyValid: boolean | undefined;
    let legacyMuHex: string | undefined;

    // tr = SHAKE256(pk, dkLen=64)
    const tr = shake256(pk, { dkLen: 64 });
    const trHex = uint8ArrayToHex(tr);

    if (opts.checkLegacyMode) {
      // Legacy CRYSTALS-Dilithium did not prepend M' prefixes or contexts.
      // μ = SHAKE256(tr || msg)
      const legacyMu = shake256(concatBytes(tr, msg), { dkLen: 64 });
      legacyMuHex = uint8ArrayToHex(legacyMu);

      try {
        // internal.verify allows externalMu to bypass getMessage()
        legacyValid = (instance as any).internal.verify(sig, legacyMu, pk, { externalMu: true });
      } catch (e) {
        legacyValid = false;
      }
    }

    // M' reconstruction
    const mPrime = buildMPrime(opts.mode, contextBytes, msg, opts.hashAlg);
    const mPrimeHex = uint8ArrayToHex(mPrime);

    // μ = SHAKE256(tr ∥ M', dkLen=64)
    const mu = shake256(concatBytes(tr, mPrime), { dkLen: 64 });
    const muHex = uint8ArrayToHex(mu);

    // ── SHAKE256 reconstruction metadata ─────────────────────────────────────
    const challengeHex = sig.length >= challengeByteLen
      ? uint8ArrayToHex(sig.slice(0, challengeByteLen))
      : '';
    const zPreviewHex = sig.length > challengeByteLen
      ? uint8ArrayToHex(sig.slice(challengeByteLen, challengeByteLen + 32))
      : '';
    const hPreviewHex = sig.length > 32
      ? uint8ArrayToHex(sig.slice(Math.max(0, sig.length - 32)))
      : '';

    return {
      valid: isValid,
      legacyValid,
      legacyMuHex,
      meta: {
        mode: opts.mode,
        hashAlg: opts.mode === 'hash-ml-dsa' ? opts.hashAlg : undefined,
        contextHex,
      },
      details: {
        variant,
        signatureSize: sig.length,
        publicKeySize: pk.length,
      },
      components: {
        challengeByteLen,
        challengeHex,
        mPrimeHex,
        trHex,
        muHex,
        zPreviewHex,
        hPreviewHex,
        reconstructedChallengeHex,
      },
    };
  } catch (err: any) {
    return { valid: false, error: err.message || 'Inspection failed' };
  }
};

export const generateKeyPair = (variant: MLDSAVariant) => {
  const instance = getMLDSAInstance(variant);
  const { publicKey, secretKey } = instance.keygen();
  return {
    publicKey: uint8ArrayToHex(publicKey),
    privateKey: uint8ArrayToHex(secretKey),
  };
};

export const signMessage = (
  variant: MLDSAVariant,
  privateKeyHex: string,
  message: string | Uint8Array,
  opts: SigningOptions,
): string => {
  const instance = getMLDSAInstance(variant);
  const sk = hexToUint8Array(privateKeyHex);
  const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  if (opts.contextRawHex !== undefined && opts.contextRawHex.length > 0) {
    if (opts.contextRawHex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(opts.contextRawHex)) {
      throw new Error(`contextRawHex is malformed: must be an even-length hex string, got "${opts.contextRawHex.slice(0, 20)}…"`);
    }
  }
  const contextBytes = opts.contextRawHex !== undefined
    ? hexToUint8Array(opts.contextRawHex)
    : new TextEncoder().encode(opts.contextText);
  const ctxOpt: { context?: Uint8Array; extraEntropy?: Uint8Array | false } = {};
  if (contextBytes.length) ctxOpt.context = contextBytes;
  // Deterministic mode: disable noble's extra entropy so signatures are fully deterministic
  if (opts.deterministic) ctxOpt.extraEntropy = false;

  if (opts.mode === 'pure') {
    return uint8ArrayToHex(instance.sign(msg, sk, ctxOpt));
  }
  const hashFn = HASH_FNS[opts.hashAlg!];
  return uint8ArrayToHex((instance as any).prehash(hashFn).sign(msg, sk, ctxOpt));
};

// ─── FIPS 204 Structural Parameters ─────────────────────────────────────────

/**
 * Per-variant structural constants from FIPS 204 Table 1.
 * Used for signature decoding, norm checking and public-key parsing.
 *
 *  λ   = security level (bits)
 *  k   = rows of matrix A  (pk polynomial count)
 *  ℓ   = columns of matrix A (sk polynomial count, z polys in sig)
 *  γ₁  = z-coefficient range: coeff ∈ (−γ₁, γ₁]
 *  γ₂  = low-order rounding range
 *  β   = challenge weight × η  (used for z bound check)
 *  ω   = max number of 1-bits in hint vector h
 *  τ   = number of ±1 entries in challenge c
 *  η   = private-key coefficient range
 *
 * Bit-packing widths:
 *  z_bits  = 1 + ⌈log₂(γ₁)⌉   (bits per z coefficient)
 *  t1_bits = 10                  (bits per t₁ coefficient, always 10)
 */
export interface VariantParams {
  lambda: number; k: number; l: number;
  gamma1: number; gamma2: number; beta: number;
  omega: number; tau: number; eta: number;
  z_bits: number; t1_bits: number;
  sigBytes: number; pkBytes: number; skBytes: number;
}

export const VARIANT_PARAMS: Record<MLDSAVariant, VariantParams> = {
  'ML-DSA-44': { lambda:128, k:4,  l:4,  gamma1:1<<17, gamma2:95232,  beta:78,  omega:80, tau:39, eta:2, z_bits:18, t1_bits:10, sigBytes:2420,  pkBytes:1312,  skBytes:2560  },
  'ML-DSA-65': { lambda:192, k:6,  l:5,  gamma1:1<<19, gamma2:261888, beta:196, omega:55, tau:49, eta:4, z_bits:20, t1_bits:10, sigBytes:3309,  pkBytes:1952,  skBytes:4032  },
  'ML-DSA-87': { lambda:256, k:8,  l:7,  gamma1:1<<19, gamma2:261888, beta:120, omega:75, tau:60, eta:2, z_bits:20, t1_bits:10, sigBytes:4627,  pkBytes:2592,  skBytes:4896  },
};

// ─── Bit-unpacking helpers ───────────────────────────────────────────────────

/**
 * Unpack a tightly bit-packed array into an array of `count` integers,
 * each `bits` wide, little-endian within each byte.
 */
function unpackBits(data: Uint8Array, count: number, bits: number): number[] {
  const out: number[] = [];
  let buf = 0, bufBits = 0, idx = 0;
  for (let i = 0; i < count; i++) {
    while (bufBits < bits && idx < data.length) {
      buf |= data[idx++] << bufBits;
      bufBits += 8;
    }
    out.push(buf & ((1 << bits) - 1));
    buf >>>= bits;
    bufBits -= bits;
  }
  return out;
}

// ─── Signature Analysis ──────────────────────────────────────────────────────

export interface PolyInfo {
  index: number;
  coefficients: number[];        // decoded signed coefficients
  maxAbsCoeff: number;
  normBound: number;             // allowed ∞-norm bound
  withinBound: boolean;
}

export interface HintInfo {
  polyIndex: number;
  oneCount: number;              // number of 1-bits for this polynomial
}

export interface SignatureAnalysis {
  variant: MLDSAVariant;
  totalBytes: number;
  expectedBytes: number;
  lengthOk: boolean;

  // c̃ section
  cTildeBytes: number;
  cTildeHex: string;

  // z section
  zOffsetBytes: number;
  zSizeBytes: number;
  zPolynomials: PolyInfo[];
  zNormOk: boolean;              // all ℓ polys within bound
  zBound: number;                // γ₁ − β

  // h section
  hOffsetBytes: number;
  hSizeBytes: number;
  hHints: HintInfo[];
  hTotalOnes: number;
  hOmega: number;
  hNormOk: boolean;              // total 1-bits ≤ ω
}

export function analyzeSignature(variant: MLDSAVariant, signatureHex: string): SignatureAnalysis {
  const p = VARIANT_PARAMS[variant];
  const sig = hexToUint8Array(signatureHex);

  const cTildeBytes = p.lambda / 8;
  const zBytesPerPoly = (256 * p.z_bits) / 8;      // always integer
  const zTotalBytes = p.l * zBytesPerPoly;
  const hTotalBytes = p.omega + p.k;                // FIPS 204 §7.2 hint encoding

  const zOffset = cTildeBytes;
  const hOffset = cTildeBytes + zTotalBytes;

  const lengthOk = sig.length === p.sigBytes;

  // ── c̃ ────────────────────────────────────────────────────────────────────
  const cTildeHex = uint8ArrayToHex(sig.slice(0, cTildeBytes));

  // ── z polynomials ─────────────────────────────────────────────────────────
  const zBound = p.gamma1 - p.beta;
  const zPolynomials: PolyInfo[] = [];
  let zNormOk = true;

  for (let i = 0; i < p.l; i++) {
    const start = zOffset + i * zBytesPerPoly;
    const slice = sig.slice(start, start + zBytesPerPoly);
    const packed = unpackBits(slice, 256, p.z_bits);
    // Coefficients are stored as γ₁ − z_i so the unsigned value is always ≥ 0
    const coeffs = packed.map(v => p.gamma1 - v);
    const maxAbs = Math.max(...coeffs.map(Math.abs));
    const within = maxAbs < p.gamma1;    // strict: |z_i| < γ₁ (FIPS 204 §3.3 Algorithm 3 step 8)
    if (!within) zNormOk = false;
    zPolynomials.push({ index: i, coefficients: coeffs, maxAbsCoeff: maxAbs, normBound: p.gamma1 - 1, withinBound: within });
  }

  // ── h hint vector ─────────────────────────────────────────────────────────
  const hHints: HintInfo[] = [];
  let hTotalOnes = 0;
  let hNormOk = true;

  if (sig.length >= hOffset + hTotalBytes) {
    const hBytes = sig.slice(hOffset, hOffset + hTotalBytes);
    // FIPS 204 §7.2: first ω bytes are hint positions, last k bytes are per-poly end indices
    const endIndices = Array.from(hBytes.slice(p.omega, p.omega + p.k));
    let prev = 0;
    for (let i = 0; i < p.k; i++) {
      const end = endIndices[i];
      const count = end - prev;
      hTotalOnes += count;
      hHints.push({ polyIndex: i, oneCount: count });
      prev = end;
    }
    if (hTotalOnes > p.omega) hNormOk = false;
  }

  return {
    variant, totalBytes: sig.length, expectedBytes: p.sigBytes, lengthOk,
    cTildeBytes, cTildeHex,
    zOffsetBytes: zOffset, zSizeBytes: zTotalBytes, zPolynomials,
    zNormOk, zBound,
    hOffsetBytes: hOffset, hSizeBytes: hTotalBytes, hHints,
    hTotalOnes, hOmega: p.omega, hNormOk,
  };
}

// ─── Signature Malleability ──────────────────────────────────────────────────

export interface MalleabilityResult {
  byteIndex: number;
  bitIndex: number;
  region: 'c̃' | 'z' | 'h';
  stillValid: boolean;
}

/**
 * Flip each bit in the signature one at a time, re-verify, and return results.
 * Sampling: tests every `stride`-th byte to keep runtime bounded.
 * Returns one result per tested bit (8 per sampled byte).
 */
export async function testMalleability(
  variant: MLDSAVariant,
  publicKeyHex: string,
  signatureHex: string,
  message: Uint8Array,
  opts: SigningOptions,
  stride = 64,
  onProgress?: (pct: number) => void,
): Promise<MalleabilityResult[]> {
  const p = VARIANT_PARAMS[variant];
  const instance = getMLDSAInstance(variant);
  const pk = hexToUint8Array(publicKeyHex);
  const sig = hexToUint8Array(signatureHex);
  const contextBytes = opts.contextRawHex !== undefined
    ? hexToUint8Array(opts.contextRawHex)
    : new TextEncoder().encode(opts.contextText);
  const ctxOpt = contextBytes.length ? { context: contextBytes } : {};

  const cLen = p.lambda / 8;
  const zLen = p.l * (256 * p.z_bits) / 8;

  function regionOf(byteIndex: number): 'c̃' | 'z' | 'h' {
    if (byteIndex < cLen) return 'c̃';
    if (byteIndex < cLen + zLen) return 'z';
    return 'h';
  }

  // Pre-compute sampled byte indices for progress reporting
  const sampledBytes: number[] = [];
  for (let i = 0; i < sig.length; i += stride) sampledBytes.push(i);

  const results: MalleabilityResult[] = [];
  for (let si = 0; si < sampledBytes.length; si++) {
    const byteIdx = sampledBytes[si];
    for (let bit = 0; bit < 8; bit++) {
      const mutated = sig.slice();
      mutated[byteIdx] ^= (1 << bit);
      let stillValid = false;
      try {
        if (opts.mode === 'pure') {
          stillValid = instance.verify(mutated, message, pk, ctxOpt.context ? ctxOpt : undefined);
        } else {
          const hashFn = HASH_FNS[opts.hashAlg!];
          stillValid = (instance as any).prehash(hashFn).verify(mutated, message, pk, ctxOpt.context ? ctxOpt : undefined);
        }
      } catch { stillValid = false; }
      results.push({ byteIndex: byteIdx, bitIndex: bit, region: regionOf(byteIdx), stillValid });
    }
    // Yield every 8 sampled bytes so React can re-render progress updates
    if (onProgress && (si % 8 === 7 || si === sampledBytes.length - 1)) {
      onProgress(Math.round(((si + 1) / sampledBytes.length) * 100));
      await new Promise(resolve => setTimeout(resolve, 0));
    }
  }
  return results;
}

// ─── Public Key Analysis ─────────────────────────────────────────────────────

export interface PublicKeyAnalysis {
  variant: MLDSAVariant;
  totalBytes: number;
  expectedBytes: number;
  lengthOk: boolean;

  // ρ — 32-byte seed for matrix A generation (always 32 bytes)
  rhoHex: string;
  rhoBytes: number;

  // t₁ — compressed polynomial vector (k polys × 256 coeffs × 10 bits)
  t1Bytes: number;
  t1Polynomials: { index: number; coefficients: number[]; minCoeff: number; maxCoeff: number }[];

  // Fingerprints
  shake256Fingerprint: string;    // SHAKE256(pk, dkLen=32) — hex
  sha256Fingerprint: string;      // SHA-256(pk) — hex
  ssh_style: string;              // SHA-256(pk) → base64 — "SHA256:..." like ssh-keygen
}

export function analyzePublicKey(variant: MLDSAVariant, publicKeyHex: string): PublicKeyAnalysis {
  const p = VARIANT_PARAMS[variant];
  const pk = hexToUint8Array(publicKeyHex);

  const lengthOk = pk.length === p.pkBytes;

  // ρ is always the first 32 bytes of the public key (FIPS 204 §7.1)
  const rhoHex = uint8ArrayToHex(pk.slice(0, 32));

  // t₁ follows immediately, packed at 10 bits per coefficient
  const t1Start = 32;
  const t1BytesPerPoly = (256 * 10) / 8;   // 320 bytes per polynomial
  const t1Bytes = p.k * t1BytesPerPoly;

  const t1Polynomials = [];
  for (let i = 0; i < p.k; i++) {
    const start = t1Start + i * t1BytesPerPoly;
    const slice = pk.slice(start, start + t1BytesPerPoly);
    const coefficients = unpackBits(slice, 256, 10);
    const minCoeff = Math.min(...coefficients);
    const maxCoeff = Math.max(...coefficients);
    t1Polynomials.push({ index: i, coefficients, minCoeff, maxCoeff });
  }

  // Fingerprints
  const shake256Fingerprint = uint8ArrayToHex(shake256(pk, { dkLen: 32 }));
  const sha256Raw = sha256(pk);
  const sha256Fingerprint = uint8ArrayToHex(sha256Raw);
  // SSH-style: "SHA256:" + base64(sha256(pk)) without trailing "="
  const ssh_style = 'SHA256:' + Buffer.from(sha256Raw).toString('base64').replace(/=+$/, '');

  return {
    variant, totalBytes: pk.length, expectedBytes: p.pkBytes, lengthOk,
    rhoHex, rhoBytes: 32,
    t1Bytes, t1Polynomials,
    shake256Fingerprint, sha256Fingerprint, ssh_style,
  };
}
