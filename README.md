# ML-DSA Inspector Playground

A web-based interactive utility for exploring and verifying Post-Quantum Digital Signatures using the **NIST FIPS 204** standard (ML-DSA / CRYSTALS-Dilithium).

## Features

- **Standardized Variants:** Supports `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87` (default) security levels.
- **Pure ML-DSA & HashML-DSA:** Supports standard signing, as well as HashML-DSA with pre-hashing (SHA-256, SHA-384, SHA-512).
- **Context Strings:** Full support for FIPS 204 context strings (up to 255 bytes).
- **Deep Inspection:** Verifies signatures and provides a step-by-step SHAKE256 cryptographic reconstruction panel showing how the commitment hash ($`\tilde{c}`$) is derived.
- **Binary Payload Support [NEW]:** Import raw `.bin` files for payloads/messages in both signing and verification. Features dynamic byte counting and visual HEX badges.
- **X.509 Certificates [NEW]:** Parses and verifies ML-DSA signatures embedded in X.509 Certificates (DER, PEM). Supports extracting Subject, Issuer, Validity periods, and OID signature variance mapping.
- **Deep Inspection:** Verifies signatures and provides a step-by-step SHAKE256 cryptographic reconstruction panel showing how the commitment hash ($`\tilde{c}`$) is derived.
- **Experimental Legacy Checks:** Includes a testing mode to check if signatures were generated with older CRYSTALS-Dilithium standards rather than final FIPS 204 formulas.
- **Export & Import:** Swap keys, signatures, and payloads using JSON bundles or raw binary (`.bin`) files.
- **Automated Tests:** Comprehensive unit test suite using `vitest` covering all cryptographic variants and message types.
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
5. Click **Sign Payload**. 
6. You can export the resulting signature as a raw `.bin` file or a `.json` bundle containing the verifying metadata.

### 3. Inspecting & Verifying
1. Navigate to the **Inspect Signature** tab (or click "Send to Inspector" from the signing page).
2. Input the hex-encoded Public Key, Signature, and Message. Alternatively, use the **Import .bin** buttons.
3. If the signature was created using a context string or HashML-DSA, expand **Verification Options** and match those settings.
4. *(Advanced)* If you suspect you have an older non-FIPS signature, check the **Experimental Legacy CRYSTALS-Dilithium verification** box.
5. Click **Inspect & Verify**.
6. If valid, the app will display a **SHAKE256 Cryptographic Reconstruction** panel, breaking down the exact steps FIPS 204 uses to construct the message representative ($\mu$) and the challenge hash ($`\tilde{c}`$).

### 4. X.509 Certificates
1. Navigate to the **X.509 Certificates** tab.
2. Upload a certificate (.pem, .cer, .der, .crt).
3. The platform will decode the ASN.1 structure and display the issuer, subject, algorithm OID, and validity periods.
4. If the certificate is self-signed, it will automatically undergo cryptographic signature verification against its own embedded public ML-DSA key.
5. If the certificate is issued by a different entity, a secondary input will appear allowing you to import the Issuer's raw Public Key (`.bin` or hex) to test the signature.

## Underlying Cryptography

This application utilizes `@noble/post-quantum` for its core lattice math and `@noble/hashes` for the underlying SHA3/SHAKE256 standard required by FIPS 204. All cryptographic operations are performed locally in the browser; no private keys are transmitted over the network.
