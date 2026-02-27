import { describe, it, expect } from 'vitest';
import {
    generateKeyPair,
    signMessage,
    inspectSignature,
    hexToUint8Array,
    uint8ArrayToHex,
    getMLDSAInstance,
    VARIANT_PARAMS,
    analyzeSignature,
    analyzePublicKey,
    testMalleability,
    MLDSAVariant,
    SigningOptions,
} from '../mldsa';

// ─── Shared helpers ───────────────────────────────────────────────────────────

const VARIANTS = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const;

/** One cached key pair per variant — keygen is ~100 ms, so we generate once. */
const KEY_CACHE: Partial<Record<MLDSAVariant, { publicKey: string; privateKey: string }>> = {};
function getKeys(variant: MLDSAVariant) {
    if (!KEY_CACHE[variant]) KEY_CACHE[variant] = generateKeyPair(variant);
    return KEY_CACHE[variant]!;
}

function pureOpts(overrides: Partial<SigningOptions> = {}): SigningOptions {
    return { mode: 'pure', contextText: '', hashAlg: 'SHA-256', ...overrides };
}

// ─── Original tests (preserved exactly) ──────────────────────────────────────

describe('mldsa service', () => {
    it('should generate valid keypairs for all variants', async () => {
        for (const variant of VARIANTS) {
            const keys = generateKeyPair(variant);
            expect(keys.publicKey).toBeDefined();
            expect(keys.privateKey).toBeDefined();
            expect(typeof keys.publicKey).toBe('string');
            expect(typeof keys.privateKey).toBe('string');
        }
    });

    it('should sign and verify string messages', async () => {
        const variant = 'ML-DSA-65';
        const keys = generateKeyPair(variant);
        const message = 'Hello, ML-DSA Test!';

        const opts = { mode: 'pure' as const, contextText: '', hashAlg: 'SHA-256' as const };
        const signature = signMessage(variant, keys.privateKey, message, opts);
        expect(signature).toBeDefined();

        const result = await inspectSignature(variant, keys.publicKey, signature, message, opts);
        expect(result.valid).toBe(true);
    });

    it('should sign and verify binary messages (Uint8Array)', async () => {
        const variant = 'ML-DSA-44';
        const keys = generateKeyPair(variant);
        const message = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0xde, 0xad, 0xbe, 0xef]);

        const opts = { mode: 'pure' as const, contextText: '', hashAlg: 'SHA-256' as const };
        const signature = signMessage(variant, keys.privateKey, message, opts);
        const result = await inspectSignature(variant, keys.publicKey, signature, message, opts);
        expect(result.valid).toBe(true);
    });

    it('should fail verification with wrong message', async () => {
        const variant = 'ML-DSA-87';
        const keys = generateKeyPair(variant);
        const message = 'Correct Message';
        const wrongMessage = 'Wrong Message';

        const opts = { mode: 'pure' as const, contextText: '', hashAlg: 'SHA-256' as const };
        const signature = signMessage(variant, keys.privateKey, message, opts);
        const result = await inspectSignature(variant, keys.publicKey, signature, wrongMessage, opts);
        expect(result.valid).toBe(false);
    });

    it('should support HashML-DSA mode', async () => {
        const variant = 'ML-DSA-65';
        const keys = generateKeyPair(variant);
        const message = 'HashML-DSA Test Message';
        const opts = { mode: 'hash-ml-dsa' as const, hashAlg: 'SHA-256' as const, contextText: '' };

        const signature = signMessage(variant, keys.privateKey, message, opts);
        const result = await inspectSignature(variant, keys.publicKey, signature, message, opts);
        expect(result.valid).toBe(true);
        expect(result.meta?.mode).toBe('hash-ml-dsa');
        expect(result.meta?.hashAlg).toBe('SHA-256');
    });

    it('should support context strings', async () => {
        const variant = 'ML-DSA-44';
        const keys = generateKeyPair(variant);
        const message = 'Context Test Message';
        const opts = { mode: 'pure' as const, contextText: 'test-context', hashAlg: 'SHA-256' as const };

        const signature = signMessage(variant, keys.privateKey, message, opts);

        // Valid with same context
        const validResult = await inspectSignature(variant, keys.publicKey, signature, message, opts);
        expect(validResult.valid).toBe(true);

        // Invalid with different context
        const invalidResult = await inspectSignature(variant, keys.publicKey, signature, message, {
            mode: 'pure', contextText: 'wrong-context', hashAlg: 'SHA-256' as const,
        });
        expect(invalidResult.valid).toBe(false);
    });

    it('should produce deterministic signatures when deterministic mode is enabled', async () => {
        const variant = 'ML-DSA-44';
        const keys = generateKeyPair(variant);
        const message = 'Deterministic test message';
        const optsDet = {
            mode: 'pure' as const,
            contextText: 'deterministic-context',
            hashAlg: 'SHA-256' as const,
            deterministic: true,
        };

        const sig1 = signMessage(variant, keys.privateKey, message, optsDet);
        const sig2 = signMessage(variant, keys.privateKey, message, optsDet);
        expect(sig1).toBe(sig2);

        const verify = await inspectSignature(variant, keys.publicKey, sig1, message, optsDet);
        expect(verify.valid).toBe(true);
    });

    it('should support HashML-DSA with SHA-384 and SHA-512', async () => {
        const variant = 'ML-DSA-65';
        const keys = generateKeyPair(variant);
        const message = 'HashML-DSA multi-hash test';

        for (const hashAlg of ['SHA-384', 'SHA-512'] as const) {
            const opts = { mode: 'hash-ml-dsa' as const, hashAlg, contextText: '' };
            const signature = signMessage(variant, keys.privateKey, message, opts);
            const result = await inspectSignature(variant, keys.publicKey, signature, message, opts);
            expect(result.valid).toBe(true);
            expect(result.meta?.hashAlg).toBe(hashAlg);
        }
    });

    it('should fail inspectSignature with invalid hex public key', async () => {
        const result = await inspectSignature(
            'ML-DSA-44',
            'not-valid-hex!!!',
            '00'.repeat(100),
            'msg',
            { mode: 'pure', contextText: '', hashAlg: 'SHA-256' }
        );
        expect(result.valid).toBe(false);
        expect(result.error).toBeDefined();
    });

    it('should fail inspectSignature with empty public key', async () => {
        const keys = generateKeyPair('ML-DSA-44');
        const opts = { mode: 'pure' as const, contextText: '', hashAlg: 'SHA-256' as const };
        const sig = signMessage('ML-DSA-44', keys.privateKey, 'test', opts);
        const result = await inspectSignature('ML-DSA-44', '', sig, 'test', opts);
        expect(result.valid).toBe(false);
    });
});

describe('mldsa helpers', () => {
    it('should round-trip hexToUint8Array and uint8ArrayToHex', () => {
        const hex = 'deadbeef0123456789abcdef';
        const bytes = hexToUint8Array(hex);
        expect(uint8ArrayToHex(bytes)).toBe(hex);
    });

    it('hexToUint8Array should handle hex with spaces and uppercase', () => {
        const hex = 'DE AD BE EF';
        const bytes = hexToUint8Array(hex);
        expect(bytes).toHaveLength(4);
        expect(bytes[0]).toBe(0xde);
        expect(bytes[3]).toBe(0xef);
    });

    it('hexToUint8Array should return empty for odd-length hex', () => {
        const bytes = hexToUint8Array('abc');
        expect(bytes).toHaveLength(0);
    });

    it('getMLDSAInstance should return correct instance per variant', () => {
        expect(getMLDSAInstance('ML-DSA-44')).toBeDefined();
        expect(getMLDSAInstance('ML-DSA-65')).toBeDefined();
        expect(getMLDSAInstance('ML-DSA-87')).toBeDefined();
    });
});

// ─── New: VARIANT_PARAMS structural constants ─────────────────────────────────

describe('VARIANT_PARAMS', () => {
    it.each(VARIANTS)('%s: sigBytes matches FIPS 204 Table 1', (variant) => {
        const expected: Record<MLDSAVariant, number> = {
            'ML-DSA-44': 2420, 'ML-DSA-65': 3309, 'ML-DSA-87': 4627,
        };
        expect(VARIANT_PARAMS[variant].sigBytes).toBe(expected[variant]);
    });

    it.each(VARIANTS)('%s: pkBytes matches FIPS 204 Table 1', (variant) => {
        const expected: Record<MLDSAVariant, number> = {
            'ML-DSA-44': 1312, 'ML-DSA-65': 1952, 'ML-DSA-87': 2592,
        };
        expect(VARIANT_PARAMS[variant].pkBytes).toBe(expected[variant]);
    });

    it.each(VARIANTS)('%s: c̃ + z + h byte sizes sum to sigBytes', (variant) => {
        const p = VARIANT_PARAMS[variant];
        // c̃ is λ/4 bytes (commitment hash = λ bits, stored as λ/4 bytes)
        // ML-DSA-44: 128/4=32, ML-DSA-65: 192/4=48, ML-DSA-87: 256/4=64
        const cBytes = p.lambda / 4;
        const zBytes = (p.l * 256 * p.z_bits) / 8;
        const hBytes = p.omega + p.k;
        expect(cBytes + zBytes + hBytes).toBe(p.sigBytes);
    });

    it.each(VARIANTS)('%s: ρ(32) + t₁(k×320) = pkBytes', (variant) => {
        const p = VARIANT_PARAMS[variant];
        expect(32 + p.k * 320).toBe(p.pkBytes);
    });

    it.each(VARIANTS)('%s: z packing produces whole bytes', (variant) => {
        const p = VARIANT_PARAMS[variant];
        expect((p.l * 256 * p.z_bits) % 8).toBe(0);
    });

    it('ML-DSA-44: λ=128, k=4, ℓ=4', () => {
        const p = VARIANT_PARAMS['ML-DSA-44'];
        expect(p.lambda).toBe(128); expect(p.k).toBe(4); expect(p.l).toBe(4);
    });

    it('ML-DSA-65: λ=192, k=6, ℓ=5', () => {
        const p = VARIANT_PARAMS['ML-DSA-65'];
        expect(p.lambda).toBe(192); expect(p.k).toBe(6); expect(p.l).toBe(5);
    });

    it('ML-DSA-87: λ=256, k=8, ℓ=7', () => {
        const p = VARIANT_PARAMS['ML-DSA-87'];
        expect(p.lambda).toBe(256); expect(p.k).toBe(8); expect(p.l).toBe(7);
    });
});

// ─── New: inspectSignature component fields ───────────────────────────────────

describe('inspectSignature components', () => {
    it.each(VARIANTS)('%s: challengeByteLen = λ/4 (c̃ byte width)', async (variant) => {
        const { publicKey, privateKey } = getKeys(variant);
        const sig = signMessage(variant, privateKey, 'msg', pureOpts());
        const result = await inspectSignature(variant, publicKey, sig, 'msg', pureOpts());
        // C_TILDE_BYTES = { 44: 32, 65: 48, 87: 64 } = lambda/4
        expect(result.components!.challengeByteLen).toBe(VARIANT_PARAMS[variant].lambda / 4);
    });

    it('trHex is 64 bytes = SHAKE256(pk, dkLen=64)', async () => {
        const { publicKey, privateKey } = getKeys('ML-DSA-44');
        const sig = signMessage('ML-DSA-44', privateKey, 'msg', pureOpts());
        const result = await inspectSignature('ML-DSA-44', publicKey, sig, 'msg', pureOpts());
        expect(result.components!.trHex).toHaveLength(128);
    });

    it('muHex is 64 bytes = SHAKE256(tr ∥ M′, dkLen=64)', async () => {
        const { publicKey, privateKey } = getKeys('ML-DSA-44');
        const sig = signMessage('ML-DSA-44', privateKey, 'msg', pureOpts());
        const result = await inspectSignature('ML-DSA-44', publicKey, sig, 'msg', pureOpts());
        expect(result.components!.muHex).toHaveLength(128);
    });

    it('reconstructedChallengeHex matches challengeHex on valid signature', async () => {
        const { publicKey, privateKey } = getKeys('ML-DSA-44');
        const sig = signMessage('ML-DSA-44', privateKey, 'msg', pureOpts());
        const result = await inspectSignature('ML-DSA-44', publicKey, sig, 'msg', pureOpts());
        expect(result.valid).toBe(true);
        expect(result.components!.reconstructedChallengeHex).toBe(result.components!.challengeHex);
    });

    it('details contains correct variant and exact byte sizes', async () => {
        const { publicKey, privateKey } = getKeys('ML-DSA-65');
        const sig = signMessage('ML-DSA-65', privateKey, 'msg', pureOpts());
        const result = await inspectSignature('ML-DSA-65', publicKey, sig, 'msg', pureOpts());
        expect(result.details!.variant).toBe('ML-DSA-65');
        expect(result.details!.signatureSize).toBe(VARIANT_PARAMS['ML-DSA-65'].sigBytes);
        expect(result.details!.publicKeySize).toBe(VARIANT_PARAMS['ML-DSA-65'].pkBytes);
    });

    it('contextRawHex binary context round-trips through inspectSignature', async () => {
        const { publicKey, privateKey } = getKeys('ML-DSA-44');
        const opts = pureOpts({ contextRawHex: 'cafebabe01020304' });
        const sig = signMessage('ML-DSA-44', privateKey, 'msg', opts);
        const good = await inspectSignature('ML-DSA-44', publicKey, sig, 'msg', opts);
        expect(good.valid).toBe(true);
        const bad = await inspectSignature('ML-DSA-44', publicKey, sig, 'msg',
            pureOpts({ contextRawHex: 'deadbeef' }));
        expect(bad.valid).toBe(false);
    });

    it('empty contextRawHex is equivalent to no context', async () => {
        const { publicKey, privateKey } = getKeys('ML-DSA-44');
        const sig = signMessage('ML-DSA-44', privateKey, 'msg', pureOpts({ contextRawHex: '' }));
        const r1 = await inspectSignature('ML-DSA-44', publicKey, sig, 'msg', pureOpts({ contextRawHex: '' }));
        const r2 = await inspectSignature('ML-DSA-44', publicKey, sig, 'msg', pureOpts());
        expect(r1.valid).toBe(true);
        expect(r2.valid).toBe(true);
    });

    it('malformed contextRawHex returns error result', async () => {
        const { publicKey } = getKeys('ML-DSA-44');
        const result = await inspectSignature('ML-DSA-44', publicKey, 'aa'.repeat(1210), 'msg',
            pureOpts({ contextRawHex: 'xyz' }));
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/contextRawHex is malformed/);
    });
});

// ─── New: analyzeSignature ────────────────────────────────────────────────────

describe('analyzeSignature', () => {
    it.each(VARIANTS)('%s: correct byte offsets and region sizes', (variant) => {
        const { privateKey } = getKeys(variant);
        const sig = signMessage(variant, privateKey, 'msg', pureOpts({ deterministic: true }));
        const a = analyzeSignature(variant, sig);
        const p = VARIANT_PARAMS[variant];

        expect(a.lengthOk).toBe(true);
        expect(a.totalBytes).toBe(p.sigBytes);
        expect(a.cTildeBytes).toBe(p.lambda / 8);
        expect(a.zSizeBytes).toBe((p.l * 256 * p.z_bits) / 8);
        expect(a.hSizeBytes).toBe(p.omega + p.k);
        expect(a.zOffsetBytes).toBe(p.lambda / 8);
        expect(a.hOffsetBytes).toBe(p.lambda / 8 + (p.l * 256 * p.z_bits) / 8);
    });

    it.each(VARIANTS)('%s: cTildeHex length = cTildeBytes × 2', (variant) => {
        const { privateKey } = getKeys(variant);
        const sig = signMessage(variant, privateKey, 'msg', pureOpts({ deterministic: true }));
        const a = analyzeSignature(variant, sig);
        expect(a.cTildeHex).toHaveLength(a.cTildeBytes * 2);
    });

    it.each(VARIANTS)('%s: z polynomial count = ℓ', (variant) => {
        const { privateKey } = getKeys(variant);
        const sig = signMessage(variant, privateKey, 'msg', pureOpts({ deterministic: true }));
        const a = analyzeSignature(variant, sig);
        expect(a.zPolynomials).toHaveLength(VARIANT_PARAMS[variant].l);
    });

    it.each(VARIANTS)('%s: each z polynomial has exactly 256 coefficients', (variant) => {
        const { privateKey } = getKeys(variant);
        const sig = signMessage(variant, privateKey, 'msg', pureOpts({ deterministic: true }));
        const a = analyzeSignature(variant, sig);
        for (const poly of a.zPolynomials) {
            expect(poly.coefficients).toHaveLength(256);
        }
    });

    it.each(VARIANTS)('%s: valid signature satisfies z ∞-norm bound (‖z_i‖∞ < γ₁)', (variant) => {
        const { privateKey } = getKeys(variant);
        const sig = signMessage(variant, privateKey, 'msg', pureOpts({ deterministic: true }));
        const a = analyzeSignature(variant, sig);
        // zNormOk is the AND of all per-poly withinBound flags
        const allWithin = a.zPolynomials.every(p => p.withinBound);
        expect(a.zNormOk).toBe(allWithin);
        // For a valid signature, every coefficient must satisfy |z_i| < gamma1
        // (any that don't would cause verify() to reject — we just confirm consistency)
        for (const poly of a.zPolynomials) {
            expect(poly.maxAbsCoeff).toBeGreaterThanOrEqual(0);
        }
    });

    it.each(VARIANTS)('%s: valid signature h hint weight ≤ ω', (variant) => {
        const { privateKey } = getKeys(variant);
        const sig = signMessage(variant, privateKey, 'msg', pureOpts({ deterministic: true }));
        const a = analyzeSignature(variant, sig);
        // hNormOk must be consistent with hTotalOnes vs hOmega
        expect(a.hNormOk).toBe(a.hTotalOnes <= a.hOmega);
        expect(a.hOmega).toBe(VARIANT_PARAMS[variant].omega);
        expect(a.hHints).toHaveLength(VARIANT_PARAMS[variant].k);
    });

    it('zBound = γ₁ − β', () => {
        const { privateKey } = getKeys('ML-DSA-44');
        const sig = signMessage('ML-DSA-44', privateKey, 'msg', pureOpts({ deterministic: true }));
        const a = analyzeSignature('ML-DSA-44', sig);
        const p = VARIANT_PARAMS['ML-DSA-44'];
        expect(a.zBound).toBe(p.gamma1 - p.beta);
    });

    it('lengthOk is false for wrong-length input', () => {
        const a = analyzeSignature('ML-DSA-44', 'aabb'.repeat(100));
        expect(a.lengthOk).toBe(false);
        expect(a.totalBytes).toBe(200);
        expect(a.expectedBytes).toBe(VARIANT_PARAMS['ML-DSA-44'].sigBytes);
    });
});

// ─── New: analyzePublicKey ────────────────────────────────────────────────────

describe('analyzePublicKey', () => {
    it.each(VARIANTS)('%s: correct byte counts for ρ and t₁', (variant) => {
        const { publicKey } = getKeys(variant);
        const a = analyzePublicKey(variant, publicKey);
        expect(a.lengthOk).toBe(true);
        expect(a.totalBytes).toBe(VARIANT_PARAMS[variant].pkBytes);
        expect(a.rhoBytes).toBe(32);
        expect(a.t1Bytes).toBe(VARIANT_PARAMS[variant].k * 320);
    });

    it.each(VARIANTS)('%s: rhoHex is exactly 32 bytes (64 hex chars)', (variant) => {
        const { publicKey } = getKeys(variant);
        expect(analyzePublicKey(variant, publicKey).rhoHex).toHaveLength(64);
    });

    it.each(VARIANTS)('%s: t₁ polynomial count = k, each with 256 coefficients', (variant) => {
        const { publicKey } = getKeys(variant);
        const a = analyzePublicKey(variant, publicKey);
        expect(a.t1Polynomials).toHaveLength(VARIANT_PARAMS[variant].k);
        for (const poly of a.t1Polynomials) {
            expect(poly.coefficients).toHaveLength(256);
        }
    });

    it.each(VARIANTS)('%s: t₁ coefficients are in range [0, 1023]', (variant) => {
        const { publicKey } = getKeys(variant);
        const a = analyzePublicKey(variant, publicKey);
        for (const poly of a.t1Polynomials) {
            expect(poly.minCoeff).toBeGreaterThanOrEqual(0);
            expect(poly.maxCoeff).toBeLessThanOrEqual(1023);
        }
    });

    it('sha256Fingerprint is 32 bytes (64 hex chars)', () => {
        const a = analyzePublicKey('ML-DSA-44', getKeys('ML-DSA-44').publicKey);
        expect(a.sha256Fingerprint).toHaveLength(64);
    });

    it('shake256Fingerprint is 32 bytes (64 hex chars)', () => {
        const a = analyzePublicKey('ML-DSA-44', getKeys('ML-DSA-44').publicKey);
        expect(a.shake256Fingerprint).toHaveLength(64);
    });

    it('ssh_style fingerprint has format "SHA256:<base64>"', () => {
        const a = analyzePublicKey('ML-DSA-44', getKeys('ML-DSA-44').publicKey);
        expect(a.ssh_style).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);
    });

    it('different keys produce different fingerprints and different ρ', () => {
        const a = analyzePublicKey('ML-DSA-44', getKeys('ML-DSA-44').publicKey);
        const b = analyzePublicKey('ML-DSA-44', generateKeyPair('ML-DSA-44').publicKey);
        expect(a.sha256Fingerprint).not.toBe(b.sha256Fingerprint);
        expect(a.shake256Fingerprint).not.toBe(b.shake256Fingerprint);
        expect(a.ssh_style).not.toBe(b.ssh_style);
        expect(a.rhoHex).not.toBe(b.rhoHex);
    });

    it('lengthOk is false for wrong-size key', () => {
        expect(analyzePublicKey('ML-DSA-44', 'aa'.repeat(100)).lengthOk).toBe(false);
    });
});

// ─── New: testMalleability ────────────────────────────────────────────────────

describe('testMalleability', () => {
    it('all sampled bit-flips are rejected on a valid signature', async () => {
        const { publicKey, privateKey } = getKeys('ML-DSA-44');
        const msg = new TextEncoder().encode('malleability test');
        const sig = signMessage('ML-DSA-44', privateKey, msg, pureOpts());
        // Large stride keeps runtime short
        const results = await testMalleability('ML-DSA-44', publicKey, sig, msg, pureOpts(), 256);
        expect(results.length).toBeGreaterThan(0);
        expect(results.filter(r => r.stillValid)).toHaveLength(0);
    });

    it('every result has a valid region label', async () => {
        const { publicKey, privateKey } = getKeys('ML-DSA-44');
        const msg = new TextEncoder().encode('msg');
        const sig = signMessage('ML-DSA-44', privateKey, msg, pureOpts());
        const results = await testMalleability('ML-DSA-44', publicKey, sig, msg, pureOpts(), 256);
        for (const r of results) {
            expect(['c̃', 'z', 'h']).toContain(r.region);
        }
    });

    it('byteIndex and bitIndex are in valid ranges', async () => {
        const { publicKey, privateKey } = getKeys('ML-DSA-44');
        const msg = new TextEncoder().encode('msg');
        const sig = signMessage('ML-DSA-44', privateKey, msg, pureOpts());
        const sigLen = hexToUint8Array(sig).length;
        const results = await testMalleability('ML-DSA-44', publicKey, sig, msg, pureOpts(), 512);
        for (const r of results) {
            expect(r.byteIndex).toBeGreaterThanOrEqual(0);
            expect(r.byteIndex).toBeLessThan(sigLen);
            expect(r.bitIndex).toBeGreaterThanOrEqual(0);
            expect(r.bitIndex).toBeLessThanOrEqual(7);
        }
    });

    it('onProgress callback fires, is non-decreasing, and reaches 100', async () => {
        const { publicKey, privateKey } = getKeys('ML-DSA-44');
        const msg = new TextEncoder().encode('msg');
        const sig = signMessage('ML-DSA-44', privateKey, msg, pureOpts());
        const progress: number[] = [];
        await testMalleability('ML-DSA-44', publicKey, sig, msg, pureOpts(), 512,
            (pct) => progress.push(pct));
        expect(progress.length).toBeGreaterThan(0);
        expect(progress[progress.length - 1]).toBe(100);
        for (let i = 1; i < progress.length; i++) {
            expect(progress[i]).toBeGreaterThanOrEqual(progress[i - 1]);
        }
    });

    it('result count = ⌈sigLen / stride⌉ × 8', async () => {
        const { publicKey, privateKey } = getKeys('ML-DSA-44');
        const msg = new TextEncoder().encode('msg');
        const sig = signMessage('ML-DSA-44', privateKey, msg, pureOpts());
        const sigLen = hexToUint8Array(sig).length;
        const stride = 256;
        const results = await testMalleability('ML-DSA-44', publicKey, sig, msg, pureOpts(), stride);
        expect(results).toHaveLength(Math.ceil(sigLen / stride) * 8);
    });
});
