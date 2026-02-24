import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { getMLDSAInstance, HASH_FNS, MLDSAVariant } from './mldsa';

// FIPS 204 Object Identifiers (OIDs) for ML-DSA
export const MLDSA_OIDS = {
    '2.16.840.1.101.3.4.3.17': 'ML-DSA-44',
    '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
    '2.16.840.1.101.3.4.3.19': 'ML-DSA-87',
};

export interface X509ParseResult {
    valid: boolean;
    error?: string;
    cert?: pkijs.Certificate;
    details?: {
        subject: string;
        issuer: string;
        notBefore: Date;
        notAfter: Date;
        serialNumber: string;
        signatureAlgorithmObj: string;
        signatureVariant?: MLDSAVariant;
        isSelfSigned: boolean;
        publicKeyBytes: Uint8Array;
        signatureValueBytes: Uint8Array;
        tbsBytes: Uint8Array; // To Be Signed
    };
}

/**
 * Extracts a readable string from a pkijs RelativeDistinguishedNames group.
 */
function formatRDN(rdn: pkijs.RelativeDistinguishedNames): string {
    const parts: string[] = [];
    for (const typeAndValue of rdn.typesAndValues) {
        let typeName = typeAndValue.type;
        // Map common OIDs to readable strings
        if (typeName === '2.5.4.3') typeName = 'CN';
        else if (typeName === '2.5.4.10') typeName = 'O';
        else if (typeName === '2.5.4.11') typeName = 'OU';
        else if (typeName === '2.5.4.6') typeName = 'C';
        else if (typeName === '2.5.4.8') typeName = 'ST';
        else if (typeName === '2.5.4.7') typeName = 'L';

        parts.push(`${typeName}=${typeAndValue.value.valueBlock.value}`);
    }
    return parts.join(', ');
}

/**
 * Normalizes PEM string to a raw Uint8Array (DER)
 */
function normalizeToDER(input: string | Uint8Array): Uint8Array {
    if (typeof input === 'string') {
        // If it's a PEM string, strip headers and decode base64
        const b64 = input
            .replace(/(-----(BEGIN|END) (CERTIFICATE|PUBLIC KEY)-----)/g, '')
            .replace(/\s+/g, '');
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
    return input;
}

/**
 * Parses an X.509 Certificate and extracts relevant ML-DSA fields
 */
export const parseCertificate = (fileData: string | Uint8Array): X509ParseResult => {
    try {
        const derFormat = normalizeToDER(fileData);

        const asn1 = asn1js.fromBER(derFormat.buffer as ArrayBuffer);
        if (asn1.offset === -1) {
            return { valid: false, error: 'Cannot decode ASN.1 structure. Ensure the file is a valid DER or PEM certificate.' };
        }

        const cert = new pkijs.Certificate({ schema: asn1.result });

        const subject = formatRDN(cert.subject);
        const issuer = formatRDN(cert.issuer);
        const isSelfSigned = subject === issuer;

        // Extract raw TBS and signature bytes
        const tbsBytes = new Uint8Array(cert.tbsView);
        const signatureValueBytes = new Uint8Array(cert.signatureValue.valueBlock.valueHexView);
        const publicKeyBytes = new Uint8Array(cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);

        // Identify algorithm
        const sigAlgOid = cert.signatureAlgorithm.algorithmId;
        const signatureVariant = (MLDSA_OIDS as any)[sigAlgOid] as MLDSAVariant | undefined;

        return {
            valid: true,
            cert,
            details: {
                subject,
                issuer,
                notBefore: cert.notBefore.value,
                notAfter: cert.notAfter.value,
                serialNumber: [...new Uint8Array(cert.serialNumber.valueBlock.valueHexView)]
                    .map(b => b.toString(16).padStart(2, '0')).join(':').toUpperCase(),
                signatureAlgorithmObj: sigAlgOid,
                signatureVariant,
                isSelfSigned,
                publicKeyBytes,
                signatureValueBytes,
                tbsBytes,
            }
        };
    } catch (err: any) {
        return { valid: false, error: err.message || 'Failed to parse certificate' };
    }
};

/**
 * Processes raw certificate bytes (e.g. from file upload or drag-and-drop)
 * and returns parse result. Handles PEM vs DER detection.
 */
export const processCertificateBytes = (bytes: Uint8Array): X509ParseResult => {
    let textAttempt = '';
    try {
        textAttempt = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
        // Not valid UTF-8, treat as DER
    }
    const isPem = textAttempt.includes('-----BEGIN CERTIFICATE-----');
    return parseCertificate(isPem ? textAttempt : bytes);
};

/**
 * Verifies an X509 ML-DSA signature using Noble FIPS 204 implementation
 */
export const verifyX509Signature = (
    tbsBytes: Uint8Array,
    signatureBytes: Uint8Array,
    publicKeyBytes: Uint8Array,
    variant: MLDSAVariant
): boolean => {
    try {
        const instance = getMLDSAInstance(variant);
        // X.509 ML-DSA signatures are pure mode, with no context string
        return instance.verify(signatureBytes, tbsBytes, publicKeyBytes);
    } catch (err) {
        console.error('X.509 verification math failed:', err);
        return false;
    }
};
