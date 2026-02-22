# ML-DSA Inspector Playground

A web-based interactive utility for exploring and verifying Post-Quantum Digital Signatures using the **NIST FIPS 204** standard (ML-DSA / CRYSTALS-Dilithium).

## Features

- **Standardized Variants:** Supports `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87` (default) security levels.
- **Pure ML-DSA & HashML-DSA:** Supports standard signing, as well as HashML-DSA with pre-hashing (SHA-256, SHA-384, SHA-512).
- **Context Strings:** Full support for FIPS 204 context strings (up to 255 bytes).
- **Deep Inspection:** Verifies signatures and provides a step-by-step SHAKE256 cryptographic reconstruction panel showing how the commitment hash ($`\tilde{c}`$) is derived.
- **Export & Import:** Swap keys and signatures using JSON bundles or raw binary (`.bin`) files.
- **Python Reference:** View equivalent backend integration code using `liboqs-python`.

## Getting Started

**Prerequisites:** Node.js 18+

1. Install dependencies:
   ```bash
   npm install
   ```
2. *(Optional)* If using external APIs or plugins, set your `GEMINI_API_KEY` in `.env.local`.
3. Start the development server:
   ```bash
   npm run dev
   ```
4. Open [http://localhost:3000](http://localhost:3000) in your browser.

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
4. Click **Inspect & Verify**.
5. If valid, the app will display a **SHAKE256 Cryptographic Reconstruction** panel, breaking down the exact steps FIPS 204 uses to construct the message representative ($\mu$) and the challenge hash ($`\tilde{c}`$).

## Underlying Cryptography

This application utilizes `@noble/post-quantum` for its core lattice math and `@noble/hashes` for the underlying SHA3/SHAKE256 standard required by FIPS 204. All cryptographic operations are performed locally in the browser; no private keys are transmitted over the network.
