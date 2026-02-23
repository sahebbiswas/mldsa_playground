import { describe, it, expect } from 'vitest';
import { generateKeyPair, signMessage, inspectSignature } from '../mldsa';

describe('mldsa service', () => {
    const variants = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const;

    it('should generate valid keypairs for all variants', async () => {
        for (const variant of variants) {
            const keys = await generateKeyPair(variant);
            expect(keys.publicKey).toBeDefined();
            expect(keys.privateKey).toBeDefined();
            expect(typeof keys.publicKey).toBe('string');
            expect(typeof keys.privateKey).toBe('string');
        }
    });

    it('should sign and verify string messages', async () => {
        const variant = 'ML-DSA-65';
        const keys = await generateKeyPair(variant);
        const message = 'Hello, ML-DSA Test!';

        const opts = { mode: 'pure' as const, contextText: '', hashAlg: 'SHA-256' as const };
        const signature = signMessage(variant, keys.privateKey, message, opts);
        expect(signature).toBeDefined();

        const result = await inspectSignature(variant, keys.publicKey, signature, message, opts);
        expect(result.valid).toBe(true);
    });

    it('should sign and verify binary messages (Uint8Array)', async () => {
        const variant = 'ML-DSA-44';
        const keys = await generateKeyPair(variant);
        const message = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0xde, 0xad, 0xbe, 0xef]);

        const opts = { mode: 'pure' as const, contextText: '', hashAlg: 'SHA-256' as const };
        const signature = signMessage(variant, keys.privateKey, message, opts);
        const result = await inspectSignature(variant, keys.publicKey, signature, message, opts);
        expect(result.valid).toBe(true);
    });

    it('should fail verification with wrong message', async () => {
        const variant = 'ML-DSA-87';
        const keys = await generateKeyPair(variant);
        const message = 'Correct Message';
        const wrongMessage = 'Wrong Message';

        const opts = { mode: 'pure' as const, contextText: '', hashAlg: 'SHA-256' as const };
        const signature = signMessage(variant, keys.privateKey, message, opts);
        const result = await inspectSignature(variant, keys.publicKey, signature, wrongMessage, opts);
        expect(result.valid).toBe(false);
    });

    it('should support HashML-DSA mode', async () => {
        const variant = 'ML-DSA-65';
        const keys = await generateKeyPair(variant);
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
        const keys = await generateKeyPair(variant);
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
});
