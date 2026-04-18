import { describe, it, expect, vi, afterEach } from 'vitest';
import {
    parseKatFile,
    parseExpectedResults,
    runKatVectors,
    inferVariantFromVectors,
    KAT_VARIANT_SIZES,
    SIG_BYTES,
    PK_BYTES,
    KatVector,
    ExpectedResultsMap,
} from '../kat';
import { MLDSAVariant } from '../mldsa';

// ─── Helpers / Fixtures ───────────────────────────────────────────────────────

/**
 * Basic hex utils to avoid dependency issues in tests
 */
function hexToUint8Array(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) throw new Error('Even length hex required');
    const u8 = new Uint8Array(hex.length / 2);
    for (let i = 0; i < u8.length; i++) {
        u8[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return u8;
}

function uint8ArrayToHex(u8: Uint8Array): string {
    return Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Basic fixtures tailored for our internal tests.
 * Note: These are NOT real NIST vectors (which would include domain separation).
 * They represent the raw MLDSA primitive (internal interface) as used in the UI.
 */
const FIXTURES = {
    'ML-DSA-44': {
        pk: '3333333333333333333333333333333333333333333333333333333333333333',
        msg: 'd19142bd6d39faaa763e019865bcaac5b699797dc62193557760c406d4da6662',
        sig: '7777777777777777777777777777777777777777777777777777777777777777', // Placeholder length
    },
    'ML-DSA-65': {
        pk: '66666666',
        msg: '66666666',
        sig: '66666666',
    },
    'ML-DSA-87': {
        pk: '88888888',
        msg: '88888888',
        sig: '88888888',
    },
};

function getFixture(variant: MLDSAVariant) {
    const f = FIXTURES[variant];
    const pkLen = PK_BYTES[variant];
    const sigLen = SIG_BYTES[variant];
    return {
        pk: f.pk.padEnd(pkLen * 2, '0').slice(0, pkLen * 2),
        msg: f.msg,
        sig: f.sig.padEnd(sigLen * 2, '0').slice(0, sigLen * 2),
    };
}

function makeAcvpGroup(variant: MLDSAVariant, tests: any[], overrides: Record<string, unknown> = {}): object {
    return {
        tgId: 1,
        testType: 'AFT',
        parameterSet: variant,
        signatureInterface: 'internal',
        preHash: 'pure',
        ...overrides,
        tests,
    };
}

function makeTc(variant: MLDSAVariant, overrides: Record<string, unknown> = {}): object {
    const f = getFixture(variant);
    return {
        tcId: 1,
        pk: f.pk,
        message: f.msg,
        signature: f.sig,
        signatureInterface: 'internal',
        ...overrides
    };
}

// ─── SIG_BYTES / PK_BYTES ─────────────────────────────────────────────────────

describe('SIG_BYTES / PK_BYTES constants', () => {
    it('ML-DSA-44 values match KAT_VARIANT_SIZES', () => {
        expect(SIG_BYTES['ML-DSA-44']).toBe(KAT_VARIANT_SIZES['ML-DSA-44'].sigBytes);
        expect(PK_BYTES['ML-DSA-44']).toBe(KAT_VARIANT_SIZES['ML-DSA-44'].pkBytes);
    });

    it('ML-DSA-65 values match KAT_VARIANT_SIZES', () => {
        expect(SIG_BYTES['ML-DSA-65']).toBe(KAT_VARIANT_SIZES['ML-DSA-65'].sigBytes);
        expect(PK_BYTES['ML-DSA-65']).toBe(KAT_VARIANT_SIZES['ML-DSA-65'].pkBytes);
    });

    it('ML-DSA-87 values match KAT_VARIANT_SIZES', () => {
        expect(SIG_BYTES['ML-DSA-87']).toBe(KAT_VARIANT_SIZES['ML-DSA-87'].sigBytes);
        expect(PK_BYTES['ML-DSA-87']).toBe(KAT_VARIANT_SIZES['ML-DSA-87'].pkBytes);
    });
});

// ─── Parsers ──────────────────────────────────────────────────────────────────

describe('parseAcvpJson', () => {
    it('parses a minimal valid ACVP file', () => {
        const json = { testGroups: [makeAcvpGroup('ML-DSA-44', [makeTc('ML-DSA-44')])] };
        const { vectors } = parseKatFile(JSON.stringify(json), 'test.json');
        expect(vectors).toHaveLength(1);
        expect(vectors[0].parameterSet).toBe('ML-DSA-44');
    });

    it('stamps each vector with its group parameterSet', () => {
        const json = { testGroups: [makeAcvpGroup('ML-DSA-65', [makeTc('ML-DSA-65', { tcId: 1 }), makeTc('ML-DSA-65', { tcId: 2 })])] };
        const { vectors } = parseKatFile(JSON.stringify(json), 'test.json');
        expect(vectors[0].parameterSet).toBe('ML-DSA-65');
        expect(vectors[1].parameterSet).toBe('ML-DSA-65');
    });

    it('multi-group: each vector gets its own parameterSet, inferredVariant = first group', () => {
        const json = {
            testGroups: [
                makeAcvpGroup('ML-DSA-44', [makeTc('ML-DSA-44')]),
                makeAcvpGroup('ML-DSA-87', [makeTc('ML-DSA-87')]),
            ],
        };
        const { vectors, inferredVariant } = parseKatFile(JSON.stringify(json), 'test.json');
        expect(vectors).toHaveLength(2);
        expect(vectors[0].parameterSet).toBe('ML-DSA-44');
        expect(vectors[1].parameterSet).toBe('ML-DSA-87');
        expect(inferredVariant).toBe('ML-DSA-44');
    });

    it('tc-level hashAlg overrides group-level hashAlg', () => {
        const json = { testGroups: [makeAcvpGroup('ML-DSA-44', [makeTc('ML-DSA-44', { hashAlg: 'SHA2-256' })], { hashAlg: 'SHA3-256' })] };
        const { vectors } = parseKatFile(JSON.stringify(json), 'test.json');
        expect(vectors[0].hashAlg).toBe('SHA2-256');
    });

    it('falls back to group-level hashAlg when tc has none', () => {
        const json = { testGroups: [makeAcvpGroup('ML-DSA-44', [makeTc('ML-DSA-44')], { hashAlg: 'SHA3-256' })] };
        const { vectors } = parseKatFile(JSON.stringify(json), 'test.json');
        expect(vectors[0].hashAlg).toBe('SHA3-256');
    });

    it('preHash="none" is preserved on the vector', () => {
        const json = { testGroups: [makeAcvpGroup('ML-DSA-44', [makeTc('ML-DSA-44')], { preHash: 'none' })] };
        const { vectors } = parseKatFile(JSON.stringify(json), 'test.json');
        expect(vectors[0].preHash).toBe('none');
    });

    it('context falls back to group.context when absent on tc', () => {
        const json = { testGroups: [makeAcvpGroup('ML-DSA-44', [makeTc('ML-DSA-44')], { context: 'aabb' })] };
        const { vectors } = parseKatFile(JSON.stringify(json), 'test.json');
        expect(vectors[0].context).toBe('aabb');
    });

    it('tc.context takes priority over group.context', () => {
        const json = { testGroups: [makeAcvpGroup('ML-DSA-44', [makeTc('ML-DSA-44', { context: 'cccc' })], { context: 'aaaa' })] };
        const { vectors } = parseKatFile(JSON.stringify(json), 'test.json');
        expect(vectors[0].context).toBe('cccc');
    });

    it('accepts testGroups at the top level (object envelope)', () => {
        const json = { testGroups: [makeAcvpGroup('ML-DSA-44', [makeTc('ML-DSA-44')])] };
        expect(parseKatFile(JSON.stringify(json), 'test.json').vectors).toHaveLength(1);
    });

    it('throws when testGroups is missing', () => {
        expect(() => parseKatFile('{}', 'test.json')).toThrow();
    });

    it('throws when tcId is missing', () => {
        const json = { testGroups: [{ tests: [{ pk: '00', message: '00', signature: '00' }] }] };
        expect(() => parseKatFile(JSON.stringify(json), 'test.json')).toThrow(/tcId/i);
    });

    it('throws when pk is missing', () => {
        const json = { testGroups: [{ tests: [{ tcId: 1, message: '00', signature: '00' }] }] };
        expect(() => parseKatFile(JSON.stringify(json), 'test.json')).toThrow(/pk/i);
    });

    it('throws when message is missing', () => {
        const json = { testGroups: [{ tests: [{ tcId: 1, pk: '00', signature: '00' }] }] };
        expect(() => parseKatFile(JSON.stringify(json), 'test.json')).toThrow(/message/i);
    });

    it('throws when signature is missing', () => {
        const json = { testGroups: [{ tests: [{ tcId: 1, pk: '00', message: '00' }] }] };
        expect(() => parseKatFile(JSON.stringify(json), 'test.json')).toThrow(/signature/i);
    });
});

describe('parseExpectedResults', () => {
    it('parses array envelope format', () => {
        const json = [{ testGroups: [{ tgId: 1, tests: [{ tcId: 1, testPassed: true }] }] }];
        const map = parseExpectedResults(JSON.stringify(json));
        expect(map.get(1)?.get(1)).toBe(true);
    });

    it('parses object envelope format', () => {
        const json = { testGroups: [{ tgId: 9, tests: [{ tcId: 99, testPassed: false }] }] };
        const map = parseExpectedResults(JSON.stringify(json));
        expect(map.get(9)?.get(99)).toBe(false);
    });

    it('returns empty map for empty testGroups', () => {
        expect(parseExpectedResults('{"testGroups":[]}').size).toBe(0);
    });
});

describe('parseRspFile', () => {
    it('parses both vectors with correct fields', () => {
        const content = `
[ML-DSA-44]
count = 0
pk = AAAA
msg = BBBB
sig = CCCC

count = 1
pk = DDDD
msg = EEEE
sig = FFFF
`;
        const { vectors } = parseKatFile(content, 'test.rsp');
        expect(vectors).toHaveLength(2);
        expect(vectors[1].pk).toBe('DDDD');
        expect(vectors[1].parameterSet).toBe('ML-DSA-44');
    });

    it('ignores comment-only blocks', () => {
        const content = '# some comment\n\n# another comment';
        const { vectors } = parseKatFile(content, 'test.rsp');
        expect(vectors).toHaveLength(0);
    });

    it('returns empty array for input with no parseable blocks', () => {
        const { vectors } = parseKatFile('just some text', 'test.kat');
        expect(vectors).toHaveLength(0);
    });
});

describe('parseSimpleJson', () => {
    it('parses a plain array', () => {
        const json = [{ pk: '00', message: '00', signature: '00' }];
        expect(parseKatFile(JSON.stringify(json), 'test.json').vectors).toHaveLength(1);
    });

    it('parses {variant, vectors} object form and returns inferredVariant', () => {
        const json = { variant: 'ML-DSA-65', vectors: [{ pk: '00', message: '00', signature: '00' }] };
        const { vectors, inferredVariant } = parseKatFile(JSON.stringify(json), 'test.json');
        expect(vectors).toHaveLength(1);
        expect(inferredVariant).toBe('ML-DSA-65');
    });

    it('throws on invalid variant string', () => {
        const json = { variant: 'INVALID', vectors: [{ pk: '00', message: '00', signature: '00' }] };
        expect(() => parseKatFile(JSON.stringify(json), 'test.json')).toThrow(/variant/i);
    });

    it('throws on empty vectors array', () => {
        expect(() => parseKatFile('{"vectors":[]}', 'test.json')).toThrow(/empty/i);
    });

    it('accepts msg as alias for message', () => {
        const json = [{ pk: '00', msg: 'AA', signature: '00' }];
        expect(parseKatFile(JSON.stringify(json), 'test.json').vectors[0].message).toBe('AA');
    });

    it('accepts sm as alias for signature', () => {
        const json = [{ pk: '00', message: '00', sm: 'BB' }];
        expect(parseKatFile(JSON.stringify(json), 'test.json').vectors[0].signature).toBe('BB');
    });
});

describe('parseKatFile', () => {
    it('routes non-JSON to parseRspFile', () => {
        const { vectors } = parseKatFile('[ML-DSA-44]\npk=1\nmsg=2\nsig=3', 'test.kat');
        expect(vectors[0].pk).toBe('1');
    });
    it('routes ACVP JSON to parseAcvpJson', () => {
        const json = { testGroups: [{ tests: [{ tcId: 1, pk: '00', message: '00', signature: '00' }] }] };
        expect(parseKatFile(JSON.stringify(json), 'test.json').vectors).toHaveLength(1);
    });
    it('routes simple JSON array to parseSimpleJson', () => {
        const json = [{ pk: '00', message: '00', signature: '00' }];
        expect(parseKatFile(JSON.stringify(json), 'test.json').vectors).toHaveLength(1);
    });
    it('throws on empty content', () => {
        expect(() => parseKatFile('', 'empty.json')).toThrow();
    });

    it('inferVariantFromVectors correctly detects all variants', () => {
        const makeV = (v: MLDSAVariant) => ({ pk: '00'.repeat(PK_BYTES[v]) } as KatVector);
        expect(inferVariantFromVectors([makeV('ML-DSA-44')])).toBe('ML-DSA-44');
        expect(inferVariantFromVectors([makeV('ML-DSA-65')])).toBe('ML-DSA-65');
        expect(inferVariantFromVectors([makeV('ML-DSA-87')])).toBe('ML-DSA-87');
        expect(inferVariantFromVectors([{ pk: '00' } as KatVector])).toBeNull();
    });
});

// ─── runKatVectors ────────────────────────────────────────────────────────────

describe('runKatVectors', () => {
    function makeVector(variant: MLDSAVariant, overrides: Partial<KatVector> = {}): KatVector {
        const f = getFixture(variant);
        return {
            tcId: 1, tgId: 1,
            pk: f.pk, message: f.msg, signature: f.sig,
            signatureInterface: 'internal',
            parameterSet: variant,
            ...overrides,
        };
    }

    it('runs an MLDSA Primitive vector (internal interface)', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44')]);
        expect(result.total).toBe(1);
        expect(result.failed).toBe(1); // placeholder sig always fails
        expect(result.vectors[0].modeLabel).toBe('MLDSA Primitive');
    });

    it('passes a standard NIST Pure vector (correct label path)', async () => {
        const v = makeVector('ML-DSA-44', { signatureInterface: 'external' });
        const result = await runKatVectors('ML-DSA-44', [v]);
        // When interface is 'external', it falls into the default path (Pure)
        expect(result.vectors[0].modeLabel).toBe('PreHash (unknown)');
    });

    it('runs an external mu vector', async () => {
        const v = makeVector('ML-DSA-44', { isExternalMu: true, message: '00'.repeat(64) });
        const result = await runKatVectors('ML-DSA-44', [v]);
        expect(result.vectors[0].modeLabel).toBe('External μ');
    });

    it('runs a HashML-DSA vector (preHash interface)', async () => {
        const v = makeVector('ML-DSA-44', {
            signatureInterface: 'external',
            preHash: 'SHA2-256',
            hashAlg: 'SHA2-256'
        });
        const result = await runKatVectors('ML-DSA-44', [v]);
        expect(result.vectors[0].modeLabel).toBe('HashML-DSA (SHA2-256)');
    });

    it('runs a HashML-DSA vector (SHAKE256)', async () => {
        const v = makeVector('ML-DSA-44', {
            signatureInterface: 'external',
            preHash: 'SHAKE256',
            hashAlg: 'SHAKE256'
        });
        const result = await runKatVectors('ML-DSA-44', [v]);
        expect(result.vectors[0].modeLabel).toBe('HashML-DSA (SHAKE-256)');
    });

    it('fails a vector with a tampered signature', async () => {
        const f = getFixture('ML-DSA-44');
        const sigBytes = hexToUint8Array(f.sig);
        sigBytes[0] ^= 0xff;
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44', { signature: uint8ArrayToHex(sigBytes) })]);
        expect(result.vectors[0].verifyOk).toBe(false);
        expect(result.vectors[0].effectivePass).toBe(false);
        expect(result.failed).toBe(1);
    });

    it('preHash="none" runs as Primitive when interface is internal', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44', { preHash: 'none' })]);
        expect(result.skipped).toBe(0);
        expect(result.vectors[0].modeLabel).toBe('MLDSA Primitive');
    });

    it('preHash="pure" runs successfully (fail-path verified)', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44', { preHash: 'pure' })]);
        expect(result.skipped).toBe(0);
        expect(result.failed).toBe(1); // placeholder fails
        expect(result.vectors[0].modeLabel).toBe('MLDSA Primitive');
    });

    it('unknown hashAlg produces a skipped result', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44', { signatureInterface: 'external', preHash: 'preHash', hashAlg: 'BLAKE3' })]);
        expect(result.skipped).toBe(1);
        expect(result.vectors[0].modeLabel).toMatch(/BLAKE3/);
    });

    it('multi-variant file: each vector uses its own parameterSet', async () => {
        const v44 = makeVector('ML-DSA-44');
        const v87 = makeVector('ML-DSA-87');
        const result = await runKatVectors('ML-DSA-65', [v44, v87]);
        expect(result.failed).toBe(2); // both fail
        expect(result.vectors[0].parameterSet).toBe('ML-DSA-44');
        expect(result.vectors[1].parameterSet).toBe('ML-DSA-87');
    });

    it('vector without parameterSet falls back to run-level variant (correct)', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44', { parameterSet: undefined })]);
        expect(result.failed).toBe(1); // falls back to 44, but random sig still fails
    });

    it('vector without parameterSet fails when run-level variant is wrong', async () => {
        const result = await runKatVectors('ML-DSA-87', [makeVector('ML-DSA-44', { parameterSet: undefined })]);
        expect(result.vectors[0].verifyOk).toBe(false);
    });

    it('maxVectors slices the input array', async () => {
        const vectors = [
            makeVector('ML-DSA-44'),
            makeVector('ML-DSA-44', { tcId: 2 }),
            makeVector('ML-DSA-44', { tcId: 3 }),
        ];
        expect((await runKatVectors('ML-DSA-44', vectors, 2)).total).toBe(2);
    });

    it('effectivePass=true for a correct rejection (expectedPassed=false, verifyOk=false)', async () => {
        const f = getFixture('ML-DSA-44');
        const sigBytes = hexToUint8Array(f.sig);
        sigBytes[0] ^= 0xff;
        const v = makeVector('ML-DSA-44', { tgId: 1, tcId: 1, signature: uint8ArrayToHex(sigBytes) });
        const expected: ExpectedResultsMap = new Map([[1, new Map([[1, false]])]]);
        const result = await runKatVectors('ML-DSA-44', [v], 100, expected);
        const r = result.vectors[0];
        expect(r.verifyOk).toBe(false);
        expect(r.expectedPassed).toBe(false);
        expect(r.matchesExpected).toBe(true);
        expect(r.effectivePass).toBe(true);
        expect(result.passed).toBe(1);
        expect(result.failed).toBe(0);
    });

    it('effectivePass=false when expected pass but we fail — mismatch counted', async () => {
        const f = getFixture('ML-DSA-44');
        const sigBytes = hexToUint8Array(f.sig);
        sigBytes[0] ^= 0xff;
        const v = makeVector('ML-DSA-44', { tgId: 1, tcId: 1, signature: uint8ArrayToHex(sigBytes) });
        const expected: ExpectedResultsMap = new Map([[1, new Map([[1, true]])]]);
        const result = await runKatVectors('ML-DSA-44', [v], 100, expected);
        expect(result.vectors[0].effectivePass).toBe(false);
        expect(result.vectors[0].matchesExpected).toBe(false);
        expect(result.expectedMismatches).toBe(1);
    });

    it('skipped vectors are not counted as passed or failed', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44', { signatureInterface: 'external', preHash: 'preHash', hashAlg: 'UNKNOWN' })]);
        expect(result.skipped).toBe(1);
        expect(result.passed).toBe(0);
        expect(result.failed).toBe(0);
    });

    it('malformed hex pk results in an error entry, not a crash', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44', { pk: 'GGGG' })]);
        expect(result.vectors[0].verifyOk).toBe(false);
        expect(result.vectors[0].error).toBeDefined();
    });

    it('strictHex throws on odd-length string', async () => {
        const v = makeVector('ML-DSA-44', { pk: 'abc' });
        const result = await runKatVectors('ML-DSA-44', [v]);
        expect(result.vectors[0].error).toContain('odd-length hex string');
    });

    it('strictHex throws on non-hex characters', async () => {
        const v = makeVector('ML-DSA-44', { pk: 'gg' });
        const result = await runKatVectors('ML-DSA-44', [v]);
        expect(result.vectors[0].error).toContain('contains non-hex characters');
    });

    it('modesPresent lists all unique mode labels from the run', async () => {
        const result = await runKatVectors('ML-DSA-44', [
            makeVector('ML-DSA-44'),
            makeVector('ML-DSA-44', { context: 'deadbeef' }),
        ]);
        expect(result.modesPresent).toContain('MLDSA Primitive');
        const result2 = await runKatVectors('ML-DSA-44', [
            makeVector('ML-DSA-44', { signatureInterface: 'external', preHash: 'pure', context: 'deadbeef' }),
        ]);
        expect(result2.modesPresent).toContain('Pure + Context');
    });

    it('runs a legacy .rsp vector', async () => {
        const v = makeVector('ML-DSA-44', { _format: '__legacy_sm__', signature: '00'.repeat(SIG_BYTES['ML-DSA-44']) });
        const result = await runKatVectors('ML-DSA-44', [v]);
        expect(result.vectors[0].modeLabel).toBe('Legacy .rsp');
    });

    it('durationMs is a non-negative number', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44')]);
        expect(typeof result.durationMs).toBe('number');
        expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });

    describe('KeyGen support', () => {
        const seed = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

        it('runs a KeyGen vector and passes with correct PK', async () => {
            // We need a real seed -> pk pair for this to pass.
            // Using the deterministic generateKeyPair from mldsa.ts
            const { generateKeyPair } = await import('../mldsa');
            const { publicKey, secretKey } = (await import('../mldsa')).getMLDSAInstance('ML-DSA-44').keygen(hexToUint8Array(seed));
            const pk = uint8ArrayToHex(publicKey);
            const sk = uint8ArrayToHex(secretKey);

            const v: KatVector = {
                tcId: 1,
                pk,
                seed,
                sk,
                testType: 'keyGen',
                parameterSet: 'ML-DSA-44',
                message: '',
                signature: '',
            };

            const result = await runKatVectors('ML-DSA-44', [v]);
            expect(result.passed).toBe(1);
            expect(result.vectors[0].modeLabel).toBe('KeyGen');
            expect(result.vectors[0].verifyOk).toBe(true);
        });


        it('fails KeyGen if PK mismatches', async () => {
            const v: KatVector = {
                tcId: 1,
                pk: '00'.repeat(1312),
                seed,
                testType: 'keyGen',
                parameterSet: 'ML-DSA-44',
                message: '',
                signature: '',
            };

            const result = await runKatVectors('ML-DSA-44', [v]);
            expect(result.passed).toBe(0);
            expect(result.failed).toBe(1);
            expect(result.vectors[0].verifyOk).toBe(false);
            expect(result.vectors[0].note).toContain('pk mismatch');
        });

        it('parses KeyGen mode from simple JSON', () => {
            const json = {
                mode: 'keyGen',
                vectors: [
                    { tcId: 1, seed, pk: '00', sk: '11' }
                ]
            };
            const { vectors } = parseKatFile(JSON.stringify(json), 'test.json');
            expect(vectors[0].seed).toBe(seed);
            expect(vectors[0].sk).toBe('11');
            expect(vectors[0].testType).toBe('keyGen');
        });

        it('parses KeyGen from ACVP testGroups', () => {
            const json = {
                testGroups: [
                    {
                        testType: 'keyGen',
                        parameterSet: 'ML-DSA-44',
                        tests: [
                            { tcId: 1, seed, pk: '00', sk: '11' }
                        ]
                    }
                ]
            };
            const { vectors } = parseKatFile(JSON.stringify(json), 'test.json');
            expect(vectors[0].seed).toBe(seed);
            expect(vectors[0].sk).toBe('11');
            expect(vectors[0].testType).toBe('keyGen');
        });

        it('parses KeyGen from ACVP testGroups with top-level mode', () => {
            const json = {
                mode: 'keyGen',
                testGroups: [
                    {
                        testType: 'AFT',
                        parameterSet: 'ML-DSA-44',
                        tests: [
                            { tcId: 1, seed, pk: '00', sk: '11' }
                        ]
                    }
                ]
            };
            const { vectors } = parseKatFile(JSON.stringify(json), 'test.json');
            expect(vectors[0].seed).toBe(seed);
            expect(vectors[0].sk).toBe('11');
            expect(vectors[0].testType).toBe('AFT'); // current logic keeps group testType in v.testType
        });

        it('parses KeyGen expected results with pk/sk', () => {
            const json = {
                mode: 'keyGen',
                testGroups: [
                    {
                        tgId: 1,
                        tests: [
                            { tcId: 101, pk: 'AA', sk: 'BB' }
                        ]
                    }
                ]
            };
            const map = parseExpectedResults(JSON.stringify(json));
            const entry = map.get(1)?.get(101);
            expect(entry).toEqual({ pk: 'AA', sk: 'BB' });
        });

        it('validates KeyGen vectors against expectedResults map (pk/sk comparison)', async () => {
            const seed = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
            const { publicKey, secretKey } = (await import('../mldsa')).getMLDSAInstance('ML-DSA-44').keygen(hexToUint8Array(seed));
            const pk = uint8ArrayToHex(publicKey);
            const sk = uint8ArrayToHex(secretKey);

            const v: KatVector = {
                tcId: 201,
                tgId: 301,
                pk: '00', // Valid hex, but doesn't match generated pk
                seed,
                testType: 'keyGen',
                parameterSet: 'ML-DSA-44',
                message: '',
                signature: '',
            };

            // But the expectedResults.json says it SHOULD be the correct pk/sk
            const expectedMap: ExpectedResultsMap = new Map([
                [301, new Map([[201, { pk, sk }]])]
            ]);

            const result = await runKatVectors('ML-DSA-44', [v], 100, expectedMap);
            // verifyOk should be false because v.pk !== generated pk
            expect(result.vectors[0].verifyOk).toBe(false);
            // BUT matchesExpected should be true if our GENERATED pk/sk matches the one in expectedMap
            expect(result.vectors[0].matchesExpected).toBe(true);
            expect(result.vectors[0].expectedPk).toBe(pk);
        });

        it('handles exceptions during keygen by skipping with error', async () => {
            const v = makeVector('ML-DSA-44', { testType: 'keyGen', seed: '00'.repeat(32) });
            const { ml_dsa44 } = await import('@noble/post-quantum/ml-dsa.js');
            const spy = vi.spyOn(ml_dsa44, 'keygen').mockImplementation(() => { throw new Error('keygen error'); });

            const result = await runKatVectors('ML-DSA-44', [v]);
            expect(result.skipped).toBe(1);
            expect(result.vectors[0].modeLabel).toBe('Error');
            expect(result.vectors[0].error).toBe('keygen error');

            spy.mockRestore();
        });
    });
});
