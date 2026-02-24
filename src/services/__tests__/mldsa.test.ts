import { describe, it, expect } from 'vitest';
import {
    generateKeyPair,
    signMessage,
    inspectSignature,
    hexToUint8Array,
    uint8ArrayToHex,
    getMLDSAInstance,
} from '../mldsa';

describe('mldsa service', () => {
    const variants = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const;

    it('should generate valid keypairs for all variants', async () => {
        for (const variant of variants) {
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
        const invalidResult = await inspectSignature(variant, keys.publicKey, signature, message, { mode: 'pure', contextText: 'wrong-context', hashAlg: 'SHA-256' as const });
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
