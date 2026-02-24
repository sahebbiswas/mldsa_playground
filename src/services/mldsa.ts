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
    const contextBytes = new TextEncoder().encode(opts.contextText);
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
  const contextBytes = new TextEncoder().encode(opts.contextText);
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
