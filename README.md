[![CI](https://github.com/sahebbiswas/mldsa_playground/actions/workflows/ci.yml/badge.svg)](https://github.com/sahebbiswas/mldsa_playground/actions/workflows/ci.yml)

# ML-DSA Inspector Playground

A web-based interactive utility for exploring and verifying Post-Quantum Digital Signatures using the **NIST FIPS 204** standard (ML-DSA / CRYSTALS-Dilithium).

## Features

- **Standardized Variants:** Supports `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87` (default) security levels.
- **Pure ML-DSA & HashML-DSA:** Supports standard signing, as well as HashML-DSA with pre-hashing (SHA-256, SHA-384, SHA-512).
- **Deterministic Signatures (Advanced):** Optional deterministic ML-DSA signing mode that disables extra randomness so identical inputs (key, message, context, mode) yield identical signatures — useful for debugging, reproducible test vectors, and protocol analysis.
- **Context Strings:** Full support for FIPS 204 context strings (up to 255 bytes).
- **Binary Payload Support:** Import raw `.bin` files for payloads/messages in both signing and verification. Features dynamic byte counting and visual HEX badges.
- **X.509 Certificates:** Drag-and-drop or upload X.509 Certificates (DER, PEM) to parse and verify embedded ML-DSA signatures. Supports extracting Subject, Issuer, Validity periods, OID signature variant mapping, and exporting the embedded public key as a raw `.bin` file.
- **KAT Validator [NEW]:** Run NIST FIPS 204 Known Answer Test vectors directly in the browser against the live implementation. Supports all NIST ACVP signing interfaces (Pure, HashML-DSA, External μ) and all FIPS 204 hash algorithms (SHA2-256/384/512, SHA3-224/256/384/512, SHAKE-128/256). Load an optional `expectedResults.json` companion file to compare results against NIST's own expected outcomes, with mismatch highlighting and per-vector drill-down. Each result row includes a **Send to Inspector** button to load that exact vector into the Inspect tab for deeper analysis.
- **Deep Inspection:** Verifies signatures and provides a step-by-step SHAKE256 cryptographic reconstruction panel showing how the commitment hash ($`\tilde{c}`$) is derived.
- **Experimental Legacy Checks:** Includes a testing mode to check if signatures were generated with older CRYSTALS-Dilithium standards rather than final FIPS 204 formulas.
- **Export & Import:** Swap keys, signatures, payloads, and X.509-derived public keys using JSON bundles or raw binary (`.bin`) files.
- **Automated Tests:** Comprehensive unit test suite using `vitest` covering all ML-DSA variants, binary payloads, and X.509 certificate parsing/verification.
- **CI/CD:** Automated GitHub Actions workflow to ensure build stability and test integrity on every push.

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

## Deployment (Web Service)

Because all cryptographic math runs locally in the browser via WebAssembly/JS, this is a purely static Single Page Application (SPA) and requires no backend server.

The easiest way to make this available online is using modern static hosting like **Vercel**, **Netlify**, or **Cloudflare Pages**.

### Deploying to Vercel/Netlify
1. Push this repository to a service like GitHub, GitLab, or Bitbucket.
2. Sign up for [Vercel](https://vercel.com) or [Netlify](https://netlify.com) and import your repository.
3. The platform will automatically detect Vite and configure the build settings:
   - **Framework:** Vite
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
4. Click **Deploy**. You will be given a public URL with HTTPS automatically.

*(Note: A `vercel.json` routing configuration is included in this repository to automatically handle SPA routing).*

## Usage Guide

### 1. Key Generation
1. Navigate to the **Key & Sign Tools** tab.
2. Select your desired ML-DSA variant in the top right.
3. Click **Generate New Pair** to initialize a new public/private key lattice.
4. Use the **Export .bin** or **Export JSON** buttons to securely save your keys for later use.

### 2. Signing a Message
1. In the **Sign Message** section, type the payload you wish to sign.
2. *(Advanced)* Click **Advanced Options** to toggle between **Pure ML-DSA** and **Hash ML-DSA**.
3. *(Advanced)* If using Hash ML-DSA, select your pre-hash algorithm (e.g., SHA-256).
4. *(Advanced)* Enter an optional **Context String** (e.g., `production-v2`).
5. *(Advanced)* Optionally enable **Deterministic ML-DSA signatures** to disable extra randomness and make repeated signatures over the same inputs byte-for-byte identical.
6. Click **Sign Payload**. 
7. You can export the resulting signature as a raw `.bin` file or a `.json` bundle containing the verifying metadata.

### 3. Inspecting & Verifying
1. Navigate to the **Inspect Signature** tab (or click **Send to Inspector** from the signing page or any KAT result row).
2. Input the hex-encoded Public Key, Signature, and Message. Alternatively, use the **Import .bin** buttons.
3. If the signature was created using a context string or HashML-DSA, expand **Verification Options** and match those settings (mode, hash, context).
4. *(Advanced)* If you suspect you have an older non-FIPS signature, check the **Experimental Legacy CRYSTALS-Dilithium verification** box.
5. Click **Inspect & Verify**.
6. If valid, the app will display a **SHAKE256 Cryptographic Reconstruction** panel, breaking down the exact steps FIPS 204 uses to construct the message representative ($\mu$) and the challenge hash ($`\tilde{c}`$).

### 4. X.509 Certificates
1. Navigate to the **X.509 Certificates** tab.
2. Either click the upload card or drag-and-drop a certificate file (.pem, .cer, .der, .crt) onto it.
3. The platform will decode the ASN.1 structure and display the issuer, subject, serial number, algorithm OID / ML-DSA variant, validity periods, and embedded public key size.
4. If the certificate is self-signed with an ML-DSA signature, it will automatically undergo cryptographic verification against its own embedded public key.
5. If the certificate is issued by a different entity, a secondary input will appear allowing you to import the Issuer's raw Public Key (`.bin` or hex) to test the signature.
6. When a certificate parses successfully, you can export the embedded subject public key as a raw `.bin` file for reuse elsewhere in the app.

### 5. KAT Validator
The KAT Validator runs official NIST ACVP test vectors against the live ML-DSA implementation directly in the browser.

**Getting test vectors:**
1. Visit the [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server) repository on GitHub.
2. Navigate to `vectors/ML-DSA/`.
3. Download `internalProjection.json` (the prompt file containing test vectors) and optionally `expectedResults.json` (the companion file with NIST's expected pass/fail outcomes for each test case).

**Running the validator:**
1. Navigate to the **KAT Validator** tab.
2. Set **Max Vectors** to a small number (e.g., 25) to start, as full ACVP files can contain hundreds of test cases.
3. Drop or click to load your `internalProjection.json` (or a legacy `.rsp` file). The variant is auto-detected from the public key size; use the **Advanced → Fallback Variant** selector only if detection fails.
4. *(Optional)* Expand **Advanced** and load `expectedResults.json` to enable comparison against NIST's expected outcomes.
5. Results appear immediately. Each row shows the test case ID, a pass/fail/skip badge, the signing interface mode, and — if expected results are loaded — whether your result matches NIST's.

**Understanding results:**

| Badge | Meaning |
|---|---|
| `PASS` | `ML-DSA.Verify()` returned true |
| `REJECT✓` | Verify returned false *and* NIST expected false — correct rejection of a bad signature |
| `FAIL` | Verify returned false but was expected to pass (or no expected results loaded) |
| `SKIP` | Hash algorithm unrecognised, or an exception was thrown |

Rows with a mismatch against `expectedResults.json` are highlighted in orange with a `≠` indicator. Use the **Show N mismatches** filter to isolate them.

**Supported signing interfaces:**

| Mode | Description |
|---|---|
| Pure | Standard `ML-DSA.Verify()` — separate pk/message/signature fields |
| Pure + Context | Pure ML-DSA with a context string bound to the signature |
| HashML-DSA | Message pre-hashed before verify; supports SHA2-224/256/384/512, SHA2-512/224, SHA2-512/256, SHA3-224/256/384/512, SHAKE-128, SHAKE-256 |
| External μ | Pre-computed message representative μ; verified via `internal.verify(externalMu: true)` |
| Legacy .rsp | Pre-FIPS 204 Dilithium format where `SM = signature ‖ message` |

**Drilling down:**  
Click any result row to expand it and see the full hex fields (public key, message, signature, context). Click **Send to Inspector** to load that exact vector into the **Inspect Signature** tab — useful for understanding both passing and failing cases in detail, including the full SHAKE256 cryptographic reconstruction.

**Exporting results:**  
Click **Export Results JSON** to download the full run output, including `verifyOk`, `effectivePass`, `modeLabel`, `expectedPassed`, and `matchesExpected` fields for every vector.

## Underlying Cryptography

This application utilizes `@noble/post-quantum` for its core lattice math and `@noble/hashes` for the underlying SHA2/SHA3/SHAKE standard required by FIPS 204. All cryptographic operations are performed locally in the browser; no private keys are transmitted over the network.