import { webcrypto } from 'node:crypto';

// JSDOM has limited crypto support. In Node 18+ environment, we can use webcrypto.
if (!globalThis.crypto || !globalThis.crypto.subtle) {
    // @ts-ignore
    globalThis.crypto = webcrypto;
}
