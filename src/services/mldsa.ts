import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { Buffer } from 'buffer';

export type MLDSAVariant = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

export interface InspectionResult {
  valid: boolean;
  commitment?: string; 
  error?: string;
  details?: {
    variant: MLDSAVariant;
    signatureSize: number;
    publicKeySize: number;
  };
}

export const getMLDSAInstance = (variant: MLDSAVariant) => {
  switch (variant) {
    case 'ML-DSA-44': return ml_dsa44;
    case 'ML-DSA-65': return ml_dsa65;
    case 'ML-DSA-87': return ml_dsa87;
    default: return ml_dsa65;
  }
};

export const hexToUint8Array = (hex: string): Uint8Array => {
  const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '');
  if (cleanHex.length % 2 !== 0) return new Uint8Array();
  try {
    return new Uint8Array(Buffer.from(cleanHex, 'hex'));
  } catch {
    return new Uint8Array();
  }
};

export const uint8ArrayToHex = (arr: Uint8Array): string => {
  return Buffer.from(arr).toString('hex');
};

export const inspectSignature = async (
  variant: MLDSAVariant,
  publicKeyHex: string,
  signatureHex: string,
  message: string
): Promise<InspectionResult> => {
  try {
    const instance = getMLDSAInstance(variant);
    const pk = hexToUint8Array(publicKeyHex);
    const sig = hexToUint8Array(signatureHex);
    const msg = new TextEncoder().encode(message);

    if (pk.length === 0 || sig.length === 0) {
      return { valid: false, error: 'Invalid hex input' };
    }

    // Standard verification: verify(signature, message, publicKey)
    const isValid = instance.verify(sig, msg, pk);

    return {
      valid: isValid,
      details: {
        variant,
        signatureSize: sig.length,
        publicKeySize: pk.length,
      }
    };
  } catch (err: any) {
    return { valid: false, error: err.message || 'Inspection failed' };
  }
};

export const generateKeyPair = (variant: MLDSAVariant) => {
  const instance = getMLDSAInstance(variant);
  const { publicKey, secretKey } = instance.keygen();
  return {
    publicKey: uint8ArrayToHex(publicKey),
    privateKey: uint8ArrayToHex(secretKey),
  };
};

export const signMessage = (variant: MLDSAVariant, privateKeyHex: string, message: string) => {
  const instance = getMLDSAInstance(variant);
  const sk = hexToUint8Array(privateKeyHex);
  const msg = new TextEncoder().encode(message);
  const signature = instance.sign(msg, sk);
  return uint8ArrayToHex(signature);
};
