[![CI](https://github.com/sahebbiswas/mldsa_playground/actions/workflows/ci.yml/badge.svg)](https://github.com/sahebbiswas/mldsa_playground/actions/workflows/ci.yml)

# ML-DSA Inspector Playground

A web-based interactive utility for exploring and verifying Post-Quantum Digital Signatures using the **NIST FIPS 204** standard (ML-DSA / CRYSTALS-Dilithium). All cryptographic operations run locally in the browser — no keys or signatures are ever transmitted over the network.

## Features

- **Standardized Variants:** Supports `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87` security levels.
- **Pure ML-DSA & HashML-DSA:** Standard signing plus HashML-DSA with pre-hashing (SHA-256, SHA-384, SHA-512).
- **Deterministic Signatures:** Optional mode that disables extra randomness so identical inputs produce identical signatures — useful for debugging and reproducible test vectors.
- **Context Strings:** Full support for FIPS 204 context strings (up to 255 bytes), including raw binary context (`contextRawHex`) for ACVP KAT interop.
- **Binary Payload Support:** Import/export raw `.bin` files for keys, signatures, and messages in both signing and verification.
- **X.509 Certificates:** Drag-and-drop X.509 certificates (DER, PEM) to parse and cryptographically verify embedded ML-DSA signatures. Extracts Subject, Issuer, Validity, algorithm OID, and embedded public key.
- **KAT Validator:** Run official NIST ACVP test vectors directly in the browser against the live implementation. Supports all FIPS 204 signing interfaces (Pure, HashML-DSA, External μ) and **KeyGen deterministic testing** (seed → pk/sk). Load an optional `expectedResults.json` companion file to compare against NIST's expected outcomes (including Public/Secret Key equality). Run state is fully preserved when switching tabs.
- **Deep Inspection:** Step-by-step SHAKE256 cryptographic reconstruction panel showing how the commitment hash c̃ is derived from inputs per FIPS 204 (tr, M′, μ, c̃, c̃′).
- **🔬 Deeper Signature Analysis:** Three collapsible panels rendered after any verification:
  - *Signature Component Decoder* — byte-layout map of the c̃ / z / h regions with offsets, sizes, a proportional visual bar, full c̃ hex, and per-polynomial hint counts.
  - *Norm & Bound Checker (FIPS 204 §3.3)* — verifies that every z polynomial satisfies `‖z_i‖∞ < γ₁` and that the h hint vector weight is within ω, with per-polynomial bar charts showing proximity to the bound.
  - *Signature Malleability Tester* — flips individual bits across sampled bytes one at a time, re-verifying after each flip. Shows a live progress bar during the run and a region-coloured heatmap of results.
- **🔑 Key Analysis:** Three collapsible panels rendered whenever a public key is present in the Inspector:
  - *Public Key Decoder* — splits the key into ρ (32-byte matrix seed) and t₁ (compressed polynomial vector), with ρ hex display and per-polynomial sparkline coefficient charts.
  - *Key Fingerprints* — SSH-style `SHA256:base64` fingerprint (matching `ssh-keygen -l` format), hex SHA-256, and hex SHAKE256 digests, all copyable with one click.
  - *Variant Size & Security Comparison* — side-by-side table and bar charts comparing all three variants on public key size, private key size, signature size, NIST security level, and classical/quantum security strength.
- **Experimental Legacy Checks:** Optional mode to test whether a signature was produced by the older CRYSTALS-Dilithium standard rather than final FIPS 204.
- **Export & Import:** Keys, signatures, payloads, and X.509-derived public keys via JSON bundles or raw `.bin` files.
- **Automated Tests:** Comprehensive unit test suite using `vitest` covering cryptographic correctness, structural analysis, KAT parsing, and malleability testing with progress callbacks.
- **CI/CD:** GitHub Actions workflow validates build and test integrity on every push.

## Getting Started

### Installation
```bash
npm install
```

### Development
```bash
npm run dev
```

### Testing
```bash
npm run test
```

### Production Build
```bash
npm run build
```

## Deployment

All cryptographic operations run in the browser — this is a purely static SPA with no backend required.

### Vercel / Netlify / Cloudflare Pages
1. Push to a GitHub/GitLab repository.
2. Import into [Vercel](https://vercel.com) or [Netlify](https://netlify.com).
3. The platform auto-detects Vite:
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
4. Click **Deploy**. A `vercel.json` SPA routing config is included in the repository.

## Usage Guide

### 1. Key Generation
1. Navigate to the **Key & Sign Tools** tab and select your ML-DSA variant.
2. Click **Generate New Pair**.
3. Export using **Export .bin** or **Export JSON**.

### 2. Signing a Message
1. Enter your payload in the **Sign Message** section.
2. *(Advanced)* Toggle **Pure ML-DSA** or **Hash ML-DSA** and select a pre-hash algorithm.
3. *(Advanced)* Enter an optional context string, or enable **Deterministic** mode.
4. Click **Sign Payload** and export the result.

### 3. Inspecting & Verifying

1. Navigate to **Inspect Signature** (or click **Send to Inspector** from the signing page or a KAT result row).
2. Paste or import the hex-encoded Public Key, Signature, and Message.
3. Match any Advanced options (mode, hash, context) to how the signature was created.
4. Click **Inspect & Verify**.
5. On success, the **SHAKE256 Cryptographic Reconstruction** panel appears showing all five FIPS 204 derivation steps.

#### Key Analysis Panel
Rendered directly below the public key field whenever a key is present — no verify required:

- **Public Key Structure (ρ + t₁)** — shows the byte layout bar (ρ = 32 B, t₁ = k × 320 B), the full ρ hex with copy button, and per-polynomial sparkline charts of t₁ coefficients (10-bit packed, range 0–1023).
- **Key Fingerprints** — three copyable digests: SSH-style `SHA256:…` (compatible with `ssh-keygen -l`), hex SHA-256, and hex SHAKE256. Use these to confirm key identity without comparing thousands of bytes.
- **Variant Size & Security Comparison** — table and proportional bar charts comparing ML-DSA-44 / 65 / 87 across public key, private key, and signature byte sizes plus NIST level and classical/quantum security estimates. The active variant is highlighted.

#### Deeper Signature Analysis
Rendered at the bottom of the result card after any verification run:

- **Signature Component Decoder** — validates signature length and renders the c̃ / z / h layout bar. Shows region byte offsets, sizes, the full c̃ hex, and per-polynomial h hint counts vs the ω bound.
- **Norm & Bound Checker (FIPS 204 §3.3)** — pass/fail summary for z ∞-norm and h weight. Per-polynomial bar charts show max |coeff| / γ₁; a vertical line marks the γ₁ − β acceptance threshold. Bars turn red if any bound is violated.
- **Malleability Tester** — select a byte stride (16 / 32 / 64 / 128) and click **Run Malleability Test**. A live progress bar tracks completion. Results appear as a region-coloured heatmap (violet = c̃, blue = z, amber = h, red = survived flip), with per-region survival counts and a pass/warn summary verdict.

### 4. X.509 Certificates
1. Navigate to the **X.509 Certificates** tab.
2. Drag-and-drop or upload a certificate file (`.pem`, `.cer`, `.der`, `.crt`).
3. The app decodes the ASN.1 structure and displays Subject, Issuer, Serial, algorithm OID, ML-DSA variant, validity periods, and public key size.
4. Self-signed certificates are automatically verified against their embedded public key. For CA-issued certificates, a secondary input allows importing the issuer's public key (`.bin` or hex).
5. Export the embedded public key as `.bin` for use elsewhere in the app.

### 5. KAT Validator

Runs official NIST ACVP test vectors against the live ML-DSA implementation in the browser. Supports both **Signature Verification (SigVer)** and **Key Generation (KeyGen)** vector sets. All run results persist when you switch to other tabs, so you can investigate vectors via **Send to Inspector** (for SigVer) and return without re-running.

**Getting test vectors:**
1. Visit [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server) on GitHub.
2. Navigate to `vectors/ML-DSA/`.
3. Download `internalProjection.json` and optionally `expectedResults.json`.

**Running the validator:**
1. Navigate to the **KAT Validator** tab.
2. Set **Max Vectors** (e.g. 25 to start — full ACVP files contain hundreds of vectors).
3. Drop or upload `internalProjection.json` (or a legacy `.rsp` file). Each test vector's variant is read from its `parameterSet` field; use **Advanced → Fallback Variant** only if detection fails.
4. *(Optional)* Expand **Advanced** and load `expectedResults.json` for NIST comparison. For KeyGen vectors, the validator compares your implementation's generated `pk` and `sk` against those in the results file.
5. Results appear immediately. Each row shows test case ID, a pass/fail/skip badge, the mode (Pure, Hash, KeyGen, etc.), the ML-DSA variant used for that vector, and — if expected results are loaded — a match/mismatch indicator (`✓` for match, `≠` for mismatch).

**Understanding result badges:**

| Badge | Meaning |
|---|---|
| `PASS` | `ML-DSA.Verify()` returned true |
| `REJECT✓` | Verify returned false *and* NIST expected false — correct rejection of an invalid signature |
| `FAIL` | Verify returned false but was expected to pass (or no expected results loaded) |
| `SKIP` | Hash algorithm unrecognised, or an exception was thrown |

Rows mismatching `expectedResults.json` are highlighted orange. Use the **Show N mismatches** filter to isolate them.

**Multi-variant ACVP files:** Each test vector is verified using the ML-DSA instance indicated by its own `parameterSet` field — not the global fallback — so all parameter sets in a single file are tested independently and correctly.

**Supported signing interfaces:**

| Mode | Description |
|---|---|
| Pure | Standard `ML-DSA.Verify()` |
| Pure + Context | Pure ML-DSA with a binary context string |
| HashML-DSA | Pre-hashed message; SHA2-224/SHA256/384/512, etc. |
| External μ | Pre-computed μ verified via `internal.verify(externalMu: true)` |
| KeyGen | Deterministic key generation: `seed` → `pk` (+ `sk`) |
| Legacy .rsp | Pre-FIPS 204 Dilithium format with `SM = signature ‖ message` |

**Note:** `preHash = "none"` in an ACVP test group is treated identically to `"pure"` — it runs as standard pure ML-DSA, not as a hash-mode vector with an unknown algorithm.

**Drilling down:** Click any result row to expand full hex fields. **Send to Inspector** loads that exact vector into the Inspect tab. For HashML-DSA vectors using SHA3 or SHAKE algorithms (not supported by the Inspector), the button is disabled with an explanatory tooltip.

**Exporting:** Click **Export Results JSON** for a full run dump including `verifyOk`, `effectivePass`, `modeLabel`, `expectedPassed`, `matchesExpected`, and `variant` per vector.

## Test Suite

Tests live in `src/services/mldsa.test.ts` and `src/services/kat.test.ts`.

```bash
npm run test
```

### `mldsa.test.ts`

| Suite | Cases |
|---|---|
| `hexToUint8Array / uint8ArrayToHex` | Round-trip, empty string, lenient non-hex stripping, odd-length input |
| `VARIANT_PARAMS` | sigBytes / pkBytes per variant; c̃+z+h = sigBytes arithmetic; pk = ρ(32) + t₁(k×320) identity; λ/k/ℓ spot-checks for all three variants |
| `generateKeyPair` | Correct key byte lengths per variant; successive calls produce distinct keys |
| Sign + verify (pure) | All three variants; wrong message fails; tampered signature fails; wrong public key fails |
| Context strings | `contextText` round-trip; `contextRawHex` binary round-trip; empty string equals no context; `undefined` falls back to `contextText`; malformed hex returns error |
| HashML-DSA | SHA-256/384/512 round-trips; pure sig rejected under hash mode |
| Deterministic signing | `deterministic: true` → identical output; both calls return valid strings |
| `inspectSignature` components | `challengeByteLen` = λ/8; `trHex` 64 B; `muHex` 64 B; reconstructed c̃′ = c̃ on valid sig; `details` sizes correct; empty pk returns error |
| `analyzeSignature` | Byte layout arithmetic per variant; c̃ hex length; z poly count = ℓ; 256 coefficients per poly; z ∞-norm bound satisfied on valid sig; h hint count ≤ ω; `zBound` = γ₁ − β; wrong-length input flagged |
| `analyzePublicKey` | Byte counts; ρ = 32 B; t₁ poly count = k; 256 coefficients; t₁ range [0, 1023]; SHA-256/SHAKE256 fingerprint lengths; SSH-style format regex; distinct keys → distinct fingerprints and ρ; wrong-size input flagged |
| `testMalleability` | All flips rejected on valid sig; region labels are c̃/z/h; `byteIndex`/`bitIndex` in valid ranges; `onProgress` called, reaches 100, is non-decreasing; result count = ⌈len/stride⌉ × 8 |

### `kat.test.ts`

| Suite | Cases |
|---|---|
| `SIG_BYTES / PK_BYTES` | Cross-checked against `VARIANT_PARAMS` for all three variants |
| `parseAcvpJson` | Minimal valid file; `parameterSet` stamped per vector; multi-group per-variant stamping; `inferredVariant` from first group; `hashAlg` tc-level wins over group; group-level fallback; `preHash="none"` preserved; context inheritance (group fallback, tc override); object envelope; throws on missing tcId / pk / message / signature |
| `parseExpectedResults` | Array envelope; object envelope; empty `testGroups` |
| `parseRspFile` | Field parsing; both vectors; comment blocks ignored; empty input returns `[]` |
| `parseSimpleJson` | Array format; `{variant, vectors}` format; invalid variant throws; empty array throws; `msg` / `sm` field aliases |
| `parseKatFile` | Routes non-JSON to `parseRspFile`; ACVP JSON to `parseAcvpJson`; simple JSON to `parseSimpleJson`; empty `.rsp` throws |
| `inferVariantFromVectors` | All three variants by pk size; unrecognised length → null; empty array → null |
| `runKatVectors` | Valid pure vector passes; tampered sig fails; `preHash="none"` runs as pure (not skipped); `preHash="pure"` passes; unknown hashAlg skipped; multi-variant vectors use own `parameterSet`; missing `parameterSet` uses run-level fallback; wrong fallback variant fails; `maxVectors` slicing; `effectivePass=true` for correct rejection; expected-pass failure → mismatch counted; skipped excluded from pass/fail; malformed hex → error result; `modesPresent` lists all labels; `durationMs` ≥ 0 |

## Underlying Cryptography

- **`@noble/post-quantum`** — ML-DSA-44/65/87 lattice operations and key generation
- **`@noble/hashes`** — SHA-2, SHA-3, SHAKE (required for M′ construction, tr, μ, and all hash pre-images per FIPS 204)
- **`pkijs` / `asn1js`** — X.509 ASN.1 parsing and certificate verification

All operations are performed locally in the browser. No private keys, messages, or signatures are transmitted over the network.