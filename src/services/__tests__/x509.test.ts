import { describe, it, expect, beforeAll } from 'vitest';
import { parseCertificate, processCertificateBytes, verifyX509Signature, MLDSA_OIDS } from '../x509';
import { generateKeyPair, signMessage, hexToUint8Array } from '../mldsa';

/** PEM certificate for parsing tests - generated via selfsigned in beforeAll */
let TEST_CERT_PEM: string;

beforeAll(async () => {
    const { generate } = await import('selfsigned');
    const pems = await generate([{ name: 'commonName', value: 'test.example.com' }], {
        days: 1,
        keySize: 2048,
    });
    TEST_CERT_PEM = pems.cert;
});

describe('x509 service', () => {
    describe('parseCertificate', () => {
        it('should fail to parse invalid DER data', () => {
            const invalidData = new Uint8Array([0x00, 0x01, 0x02]);
            const result = parseCertificate(invalidData);
            expect(result.valid).toBe(false);
            expect(result.error).toBeDefined();
        });

        it('should fail to parse empty Uint8Array', () => {
            const result = parseCertificate(new Uint8Array(0));
            expect(result.valid).toBe(false);
            expect(result.error).toBeDefined();
        });

        it('should fail to parse empty string', () => {
            const result = parseCertificate('');
            expect(result.valid).toBe(false);
            expect(result.error).toBeDefined();
        });

        it('should fail to parse invalid PEM (garbage base64)', () => {
            const invalidPem = '-----BEGIN CERTIFICATE-----\n!!!invalid!!!\n-----END CERTIFICATE-----';
            const result = parseCertificate(invalidPem);
            expect(result.valid).toBe(false);
            expect(result.error).toBeDefined();
        });

        it('should parse valid PEM certificate and return publicKeyBytes', () => {
            const result = parseCertificate(TEST_CERT_PEM);
            expect(result.valid).toBe(true);
            expect(result.details).toBeDefined();
            expect(result.details!.publicKeyBytes).toBeInstanceOf(Uint8Array);
            expect(result.details!.publicKeyBytes.length).toBeGreaterThan(0);
            expect(result.details!.subject).toContain('test.example.com');
            expect(result.details!.issuer).toBeDefined();
            expect(result.details!.isSelfSigned).toBe(true);
            expect(result.details!.tbsBytes).toBeInstanceOf(Uint8Array);
            expect(result.details!.signatureValueBytes).toBeInstanceOf(Uint8Array);
        });

        it('should parse DER when given Uint8Array of valid cert', () => {
            const der = Buffer.from(
                TEST_CERT_PEM
                    .replace(/-----(BEGIN|END) CERTIFICATE-----/g, '')
                    .replace(/\s/g, ''),
                'base64'
            );
            const result = parseCertificate(new Uint8Array(der));
            expect(result.valid).toBe(true);
            expect(result.details!.publicKeyBytes.length).toBeGreaterThan(0);
        });
    });

    describe('verifyX509Signature', () => {
        it('should export verifyX509Signature function', () => {
            expect(verifyX509Signature).toBeDefined();
            expect(typeof verifyX509Signature).toBe('function');
        });

        it('should verify valid ML-DSA signature (round-trip)', () => {
            const variant = 'ML-DSA-44';
            const keys = generateKeyPair(variant);
            const tbsBytes = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);

            const opts = { mode: 'pure' as const, contextText: '', hashAlg: 'SHA-256' as const };
            const sigHex = signMessage(variant, keys.privateKey, tbsBytes, opts);
            const sigBytes = hexToUint8Array(sigHex);
            const pkBytes = hexToUint8Array(keys.publicKey);

            const valid = verifyX509Signature(tbsBytes, sigBytes, pkBytes, variant);
            expect(valid).toBe(true);
        });

        it('should return false for tampered TBS bytes', () => {
            const variant = 'ML-DSA-65';
            const keys = generateKeyPair(variant);
            const tbsBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
            const tamperedTbs = new Uint8Array([0xde, 0xad, 0xbe, 0xff]);

            const opts = { mode: 'pure' as const, contextText: '', hashAlg: 'SHA-256' as const };
            const sigHex = signMessage(variant, keys.privateKey, tbsBytes, opts);
            const sigBytes = hexToUint8Array(sigHex);
            const pkBytes = hexToUint8Array(keys.publicKey);

            const valid = verifyX509Signature(tamperedTbs, sigBytes, pkBytes, variant);
            expect(valid).toBe(false);
        });

        it('should return false for wrong public key', () => {
            const variant = 'ML-DSA-87';
            const signerKeys = generateKeyPair(variant);
            const wrongKeys = generateKeyPair(variant);
            const tbsBytes = new Uint8Array([0x11, 0x22, 0x33]);

            const opts = { mode: 'pure' as const, contextText: '', hashAlg: 'SHA-256' as const };
            const sigHex = signMessage(variant, signerKeys.privateKey, tbsBytes, opts);
            const sigBytes = hexToUint8Array(sigHex);
            const wrongPkBytes = hexToUint8Array(wrongKeys.publicKey);

            const valid = verifyX509Signature(tbsBytes, sigBytes, wrongPkBytes, variant);
            expect(valid).toBe(false);
        });

        it('should verify for all ML-DSA variants', () => {
            const variants = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const;
            for (const variant of variants) {
                const keys = generateKeyPair(variant);
                const tbsBytes = new Uint8Array([0xaa, 0xbb, 0xcc]);

                const opts = { mode: 'pure' as const, contextText: '', hashAlg: 'SHA-256' as const };
                const sigHex = signMessage(variant, keys.privateKey, tbsBytes, opts);
                const sigBytes = hexToUint8Array(sigHex);
                const pkBytes = hexToUint8Array(keys.publicKey);

                const valid = verifyX509Signature(tbsBytes, sigBytes, pkBytes, variant);
                expect(valid).toBe(true);
            }
        });
    });

    describe('MLDSA_OIDS', () => {
        it('should have expected OID mappings for all variants', () => {
            expect(MLDSA_OIDS['2.16.840.1.101.3.4.3.17']).toBe('ML-DSA-44');
            expect(MLDSA_OIDS['2.16.840.1.101.3.4.3.18']).toBe('ML-DSA-65');
            expect(MLDSA_OIDS['2.16.840.1.101.3.4.3.19']).toBe('ML-DSA-87');
        });
    });

    describe('processCertificateBytes (file upload / drag-drop logic)', () => {
        it('should parse PEM when bytes decode to UTF-8 with PEM header', () => {
            const pemBytes = new TextEncoder().encode(TEST_CERT_PEM);
            const result = processCertificateBytes(pemBytes);
            expect(result.valid).toBe(true);
            expect(result.details!.publicKeyBytes.length).toBeGreaterThan(0);
        });

        it('should parse DER when bytes do not contain PEM header', () => {
            const der = Buffer.from(
                TEST_CERT_PEM.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s/g, ''),
                'base64'
            );
            const result = processCertificateBytes(new Uint8Array(der));
            expect(result.valid).toBe(true);
        });

        it('should fail for invalid bytes', () => {
            const result = processCertificateBytes(new Uint8Array([0x00, 0x01, 0x02]));
            expect(result.valid).toBe(false);
        });
    });

    describe('publicKeyBytes export (certificate feature)', () => {
        it('should return publicKeyBytes suitable for binary export when parse succeeds', () => {
            const result = parseCertificate(TEST_CERT_PEM);
            expect(result.valid).toBe(true);
            const publicKeyBytes = result.details!.publicKeyBytes;
            expect(publicKeyBytes).toBeInstanceOf(Uint8Array);
            // RSA 2048 SubjectPublicKeyInfo is typically ~270 bytes; selfsigned uses 2048-bit RSA
            expect(publicKeyBytes.length).toBeGreaterThan(200);
            expect(publicKeyBytes.length).toBeLessThan(500);
        });
    });
});
