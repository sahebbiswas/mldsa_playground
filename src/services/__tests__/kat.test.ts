import { describe, it, expect } from 'vitest';
import {
    parseAcvpJson,
    parseExpectedResults,
    parseRspFile,
    parseSimpleJson,
    parseKatFile,
    inferVariantFromVectors,
    runKatVectors,
    SIG_BYTES,
    PK_BYTES,
    KatVector,
    ExpectedResultsMap,
} from '../kat';
import {
    generateKeyPair,
    signMessage,
    hexToUint8Array,
    uint8ArrayToHex,
    VARIANT_PARAMS,
    MLDSAVariant,
} from '../mldsa';

// ─── Live key/signature fixtures ─────────────────────────────────────────────
// Generated once per variant and cached — keygen is ~100 ms each.

const FIXTURE_CACHE: Partial<Record<MLDSAVariant, { pk: string; sk: string; sig: string; msg: string }>> = {};

function getFixture(variant: MLDSAVariant) {
    if (!FIXTURE_CACHE[variant]) {
        // Message must be hex-encoded — runKatVectors passes it through strictHex()
        const msgBytes = new TextEncoder().encode('KAT test message');
        const msgHex = uint8ArrayToHex(msgBytes);
        const { publicKey, privateKey } = generateKeyPair(variant);
        const sig = signMessage(variant, privateKey, msgBytes, {
            mode: 'pure', contextText: '', hashAlg: 'SHA-256', deterministic: true,
        });
        FIXTURE_CACHE[variant] = { pk: publicKey, sk: privateKey, sig, msg: msgHex };
    }
    return FIXTURE_CACHE[variant]!;
}

// ─── ACVP JSON fixture builders ───────────────────────────────────────────────

function makeAcvpJson(groups: object[]): string {
    return JSON.stringify([
        { acvVersion: '1.0' },
        { vsId: 1, testGroups: groups },
    ]);
}

function makeAcvpGroup(
    variant: MLDSAVariant,
    tests: object[],
    overrides: Record<string, unknown> = {},
): object {
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
    return { tcId: 1, pk: f.pk, message: f.msg, signature: f.sig, ...overrides };
}

// ─── SIG_BYTES / PK_BYTES ─────────────────────────────────────────────────────

describe('SIG_BYTES / PK_BYTES constants', () => {
    const variants = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const;

    it.each(variants)('%s values match VARIANT_PARAMS', (v) => {
        expect(SIG_BYTES[v]).toBe(VARIANT_PARAMS[v].sigBytes);
        expect(PK_BYTES[v]).toBe(VARIANT_PARAMS[v].pkBytes);
    });
});

// ─── parseAcvpJson ────────────────────────────────────────────────────────────

describe('parseAcvpJson', () => {
    it('parses a minimal valid ACVP file', () => {
        const json = makeAcvpJson([makeAcvpGroup('ML-DSA-44', [makeTc('ML-DSA-44')])]);
        const { vectors, inferredVariant } = parseAcvpJson(json);
        expect(vectors).toHaveLength(1);
        expect(inferredVariant).toBe('ML-DSA-44');
    });

    it('stamps each vector with its group parameterSet', () => {
        const json = makeAcvpJson([makeAcvpGroup('ML-DSA-65', [makeTc('ML-DSA-65')])]);
        expect(parseAcvpJson(json).vectors[0].parameterSet).toBe('ML-DSA-65');
    });

    it('multi-group: each vector gets its own parameterSet, inferredVariant = first group', () => {
        const json = makeAcvpJson([
            { ...makeAcvpGroup('ML-DSA-44', [makeTc('ML-DSA-44')]), tgId: 1 },
            { ...makeAcvpGroup('ML-DSA-87', [makeTc('ML-DSA-87')]), tgId: 2 },
        ]);
        const { vectors, inferredVariant } = parseAcvpJson(json);
        expect(vectors).toHaveLength(2);
        expect(inferredVariant).toBe('ML-DSA-44');
        expect(vectors[0].parameterSet).toBe('ML-DSA-44');
        expect(vectors[1].parameterSet).toBe('ML-DSA-87');
    });

    it('tc-level hashAlg overrides group-level hashAlg', () => {
        const json = makeAcvpJson([
            makeAcvpGroup('ML-DSA-44', [{ ...makeTc('ML-DSA-44'), hashAlg: 'SHA2-256' }],
                { hashAlg: 'SHA2-512', preHash: 'preHash' }),
        ]);
        expect(parseAcvpJson(json).vectors[0].hashAlg).toBe('SHA2-256');
    });

    it('falls back to group-level hashAlg when tc has none', () => {
        const json = makeAcvpJson([
            makeAcvpGroup('ML-DSA-44', [makeTc('ML-DSA-44')], { hashAlg: 'SHA2-384', preHash: 'preHash' }),
        ]);
        expect(parseAcvpJson(json).vectors[0].hashAlg).toBe('SHA2-384');
    });

    it('preHash="none" is preserved on the vector', () => {
        const json = makeAcvpJson([
            makeAcvpGroup('ML-DSA-44', [makeTc('ML-DSA-44')], { preHash: 'none', hashAlg: 'SHA2-256' }),
        ]);
        expect(parseAcvpJson(json).vectors[0].preHash).toBe('none');
    });

    it('context falls back to group.context when absent on tc', () => {
        const json = makeAcvpJson([
            makeAcvpGroup('ML-DSA-44', [makeTc('ML-DSA-44')], { context: 'aabbccdd' }),
        ]);
        expect(parseAcvpJson(json).vectors[0].context).toBe('aabbccdd');
    });

    it('tc.context takes priority over group.context', () => {
        const json = makeAcvpJson([
            makeAcvpGroup('ML-DSA-44',
                [{ ...makeTc('ML-DSA-44'), context: 'tcctx' }],
                { context: 'groupctx' }),
        ]);
        expect(parseAcvpJson(json).vectors[0].context).toBe('tcctx');
    });

    it('accepts testGroups at the top level (object envelope)', () => {
        const f = getFixture('ML-DSA-44');
        const json = JSON.stringify({
            testGroups: [{
                tgId: 1, parameterSet: 'ML-DSA-44', signatureInterface: 'internal',
                tests: [{ tcId: 1, pk: f.pk, message: f.msg, signature: f.sig }],
            }],
        });
        expect(parseAcvpJson(json).vectors).toHaveLength(1);
    });

    it('throws when testGroups is missing', () => {
        expect(() => parseAcvpJson('{"vsId":1}')).toThrow('No testGroups found');
    });

    it('throws when tcId is missing', () => {
        expect(() => parseAcvpJson(makeAcvpJson([
            makeAcvpGroup('ML-DSA-44', [{ pk: 'aa', message: 'bb', signature: 'cc' }]),
        ]))).toThrow('missing tcId');
    });

    it('throws when pk is missing', () => {
        expect(() => parseAcvpJson(makeAcvpJson([
            makeAcvpGroup('ML-DSA-44', [{ tcId: 1, message: 'bb', signature: 'cc' }]),
        ]))).toThrow('missing required field "pk"');
    });

    it('throws when message is missing', () => {
        expect(() => parseAcvpJson(makeAcvpJson([
            makeAcvpGroup('ML-DSA-44', [{ tcId: 1, pk: 'aa', signature: 'cc' }]),
        ]))).toThrow('missing required field "message"');
    });

    it('throws when signature is missing', () => {
        expect(() => parseAcvpJson(makeAcvpJson([
            makeAcvpGroup('ML-DSA-44', [{ tcId: 1, pk: 'aa', message: 'bb' }]),
        ]))).toThrow('missing required field "signature"');
    });
});

// ─── parseExpectedResults ─────────────────────────────────────────────────────

describe('parseExpectedResults', () => {
    it('parses array envelope format', () => {
        const json = JSON.stringify([
            { acvVersion: '1.0' },
            { vsId: 1, testGroups: [{ tgId: 1, tests: [{ tcId: 1, testPassed: true }, { tcId: 2, testPassed: false }] }] },
        ]);
        const map = parseExpectedResults(json);
        expect(map.get(1)?.get(1)).toBe(true);
        expect(map.get(1)?.get(2)).toBe(false);
    });

    it('parses object envelope format', () => {
        const map = parseExpectedResults(JSON.stringify({
            testGroups: [{ tgId: 5, tests: [{ tcId: 10, testPassed: true }] }],
        }));
        expect(map.get(5)?.get(10)).toBe(true);
    });

    it('returns empty map for empty testGroups', () => {
        expect(parseExpectedResults(JSON.stringify({ testGroups: [] })).size).toBe(0);
    });
});

// ─── parseRspFile ─────────────────────────────────────────────────────────────

describe('parseRspFile', () => {
    const RSP = `
# Dilithium2 KAT

count = 0
seed = 0102030405060708090a
mlen = 3
msg = 010203
pk = aabbcc
sk = ddeeff
smlen = 2423
sm = ffffffff

count = 1
seed = 0a0b0c
mlen = 2
msg = 0405
pk = 112233
sk = 445566
smlen = 2422
sm = 00112233
`.trim();

    it('parses both vectors with correct fields', () => {
        const vectors = parseRspFile(RSP);
        expect(vectors).toHaveLength(2);
        expect(vectors[0].tcId).toBe(0);
        expect(vectors[0].pk).toBe('aabbcc');
        expect(vectors[0].message).toBe('010203');
        expect(vectors[0].signature).toBe('ffffffff');
        expect(vectors[0]._format).toBe('__legacy_sm__');
        expect(vectors[1].tcId).toBe(1);
        expect(vectors[1].pk).toBe('112233');
    });

    it('ignores comment-only blocks', () => {
        const rsp = '# just comments\n\ncount = 0\nmsg = aa\npk = bb\nsk = cc\nsmlen = 1\nsm = dd\n';
        expect(parseRspFile(rsp)).toHaveLength(1);
    });

    it('returns empty array for input with no parseable blocks', () => {
        expect(parseRspFile('# only comments')).toHaveLength(0);
    });
});

// ─── parseSimpleJson ──────────────────────────────────────────────────────────

describe('parseSimpleJson', () => {
    it('parses a plain array', () => {
        const { vectors } = parseSimpleJson(JSON.stringify([{ tcId: 1, pk: 'aa', message: 'bb', signature: 'cc' }]));
        expect(vectors).toHaveLength(1);
        expect(vectors[0].pk).toBe('aa');
    });

    it('parses {variant, vectors} object form and returns inferredVariant', () => {
        const { vectors, inferredVariant } = parseSimpleJson(JSON.stringify({
            variant: 'ML-DSA-44',
            vectors: [{ tcId: 1, pk: 'aa', message: 'bb', signature: 'cc' }],
        }));
        expect(vectors).toHaveLength(1);
        expect(inferredVariant).toBe('ML-DSA-44');
    });

    it('throws on invalid variant string', () => {
        expect(() => parseSimpleJson(JSON.stringify({
            variant: 'ML-DSA-99',
            vectors: [{ pk: 'a', message: 'b', signature: 'c' }],
        }))).toThrow('Invalid variant');
    });

    it('throws on empty vectors array', () => {
        expect(() => parseSimpleJson('[]')).toThrow('Empty vectors array');
    });

    it('accepts msg as alias for message', () => {
        const { vectors } = parseSimpleJson(JSON.stringify([{ tcId: 1, pk: 'aa', msg: 'val', signature: 'cc' }]));
        expect(vectors[0].message).toBe('val');
    });

    it('accepts sm as alias for signature', () => {
        const { vectors } = parseSimpleJson(JSON.stringify([{ tcId: 1, pk: 'aa', message: 'bb', sm: 'sigval' }]));
        expect(vectors[0].signature).toBe('sigval');
    });
});

// ─── parseKatFile ─────────────────────────────────────────────────────────────

describe('parseKatFile', () => {
    it('routes non-JSON to parseRspFile', () => {
        const rsp = 'count = 0\nmsg = aa\npk = bb\nsk = cc\nsmlen = 1\nsm = dd\n';
        expect(parseKatFile(rsp, 'test.rsp').vectors[0]._format).toBe('__legacy_sm__');
    });

    it('routes ACVP JSON to parseAcvpJson', () => {
        const json = makeAcvpJson([makeAcvpGroup('ML-DSA-44', [makeTc('ML-DSA-44')])]);
        expect(parseKatFile(json, 'vectors.json').inferredVariant).toBe('ML-DSA-44');
    });

    it('routes simple JSON array to parseSimpleJson', () => {
        const json = JSON.stringify([{ tcId: 1, pk: 'aa', message: 'bb', signature: 'cc' }]);
        expect(parseKatFile(json, 'simple.json').vectors).toHaveLength(1);
    });

    it('throws on empty .rsp content', () => {
        expect(() => parseKatFile('# empty', 'test.rsp')).toThrow('Parsed 0 vectors');
    });
});

// ─── inferVariantFromVectors ──────────────────────────────────────────────────

describe('inferVariantFromVectors', () => {
    const variants = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const;

    it.each(variants)('%s: recognised from pk size', (v) => {
        const { pk } = getFixture(v);
        expect(inferVariantFromVectors([{ tcId: 0, pk, message: '', signature: '' }])).toBe(v);
    });

    it('returns null for unrecognised pk length', () => {
        expect(inferVariantFromVectors([{ tcId: 0, pk: 'aabb', message: '', signature: '' }])).toBeNull();
    });

    it('returns null for empty array', () => {
        expect(inferVariantFromVectors([])).toBeNull();
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

    it('passes a valid pure vector', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44')]);
        expect(result.total).toBe(1);
        expect(result.passed).toBe(1);
        expect(result.failed).toBe(0);
        expect(result.vectors[0].verifyOk).toBe(true);
        expect(result.vectors[0].effectivePass).toBe(true);
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

    it('preHash="none" runs as pure (not skipped)', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44', { preHash: 'none' })]);
        expect(result.skipped).toBe(0);
        expect(result.vectors[0].modeLabel).toMatch(/Pure/);
    });

    it('preHash="pure" runs as pure and passes', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44', { preHash: 'pure' })]);
        expect(result.skipped).toBe(0);
        expect(result.vectors[0].verifyOk).toBe(true);
    });

    it('unknown hashAlg produces a skipped result', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44', { preHash: 'preHash', hashAlg: 'BLAKE3' })]);
        expect(result.skipped).toBe(1);
        // modeLabel is set to `PreHash (BLAKE3)` when hash is unrecognised
        expect(result.vectors[0].modeLabel).toMatch(/BLAKE3/);
    });

    it('multi-variant file: each vector uses its own parameterSet', async () => {
        const v44 = makeVector('ML-DSA-44');
        const v87 = makeVector('ML-DSA-87');
        // Fallback is ML-DSA-65, but neither vector should use it
        const result = await runKatVectors('ML-DSA-65', [v44, v87]);
        expect(result.vectors[0].verifyOk).toBe(true);
        expect(result.vectors[1].verifyOk).toBe(true);
        expect(result.passed).toBe(2);
    });

    it('vector without parameterSet falls back to run-level variant (correct)', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44', { parameterSet: undefined })]);
        expect(result.vectors[0].verifyOk).toBe(true);
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
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44', { preHash: 'preHash', hashAlg: 'UNKNOWN' })]);
        expect(result.skipped).toBe(1);
        expect(result.passed).toBe(0);
        expect(result.failed).toBe(0);
    });

    it('malformed hex pk results in an error entry, not a crash', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44', { pk: 'GGGG' })]);
        expect(result.vectors[0].verifyOk).toBe(false);
        expect(result.vectors[0].error).toBeDefined();
    });

    it('modesPresent lists all unique mode labels from the run', async () => {
        const result = await runKatVectors('ML-DSA-44', [
            makeVector('ML-DSA-44'),
            makeVector('ML-DSA-44', { context: 'deadbeef' }),
        ]);
        expect(result.modesPresent).toContain('Pure');
        expect(result.modesPresent).toContain('Pure + Context');
    });

    it('durationMs is a non-negative number', async () => {
        const result = await runKatVectors('ML-DSA-44', [makeVector('ML-DSA-44')]);
        expect(typeof result.durationMs).toBe('number');
        expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });
});
