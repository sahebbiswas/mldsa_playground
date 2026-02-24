/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Shield,
  Search,
  Key,
  FileText,
  CheckCircle2,
  XCircle,
  Info,
  ChevronRight,
  RefreshCw,
  Copy,
  Terminal,
  Cpu,
  Download,
  Upload,
  AlertTriangle,
  ChevronDown,
  Hash,
  Lock,
  Layers,
  Fingerprint, // Added for X.509
  Dna, // Added for X.509
  FileJson, // Added for X.509
  ArrowRight, // Added for X.509
  FileCheck2, // Added for X.509
  Calendar, // Added for X.509
  Link, // Added for X.509
  User, // Added for X.509
} from 'lucide-react';
import {
  inspectSignature,
  generateKeyPair,
  signMessage,
  hexToUint8Array,
  uint8ArrayToHex,
  MLDSAVariant,
  SignMode,
  HashAlg,
  SigningOptions,
  InspectionResult,
} from './services/mldsa';
import { processCertificateBytes, verifyX509Signature, X509ParseResult } from './services/x509';
import { cn } from './lib/utils';

// ─── Constants ────────────────────────────────────────────────────────────────

const VARIANTS: MLDSAVariant[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];
const HASH_ALGS: HashAlg[] = ['SHA-256', 'SHA-384', 'SHA-512'];

const DEFAULT_SIGNING_OPTS: SigningOptions = {
  mode: 'pure',
  contextText: '',
  hashAlg: 'SHA-256',
};

// ─── Download helpers ─────────────────────────────────────────────────────────

interface KeyBundle { version: 1; variant: MLDSAVariant; publicKey: string; privateKey: string; }
interface SignatureBundle { version: 1; variant: MLDSAVariant; mode: SignMode; hashAlg?: HashAlg; contextText: string; message: string; signature: string; publicKey: string; }

function downloadJSON(filename: string, data: object) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), { href: url, download: filename });
  a.click();
  URL.revokeObjectURL(url);
}

function downloadBinary(filename: string, bytes: Uint8Array) {
  const plain = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  const blob = new Blob([plain], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), { href: url, download: filename });
  a.click();
  URL.revokeObjectURL(url);
}

function readBinFile(file: File): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(new Uint8Array(e.target?.result as ArrayBuffer));
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

// ─── Small UI chips ───────────────────────────────────────────────────────────

function ModeBadge({ mode }: { mode: SignMode }) {
  return (
    <span className={cn(
      'inline-flex items-center gap-1.5 px-2 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wider rounded-sm border',
      mode === 'pure'
        ? 'border-[#141414]/30 text-[#141414]/70'
        : 'border-violet-400 text-violet-700 bg-violet-50',
    )}>
      {mode === 'pure' ? <Lock size={9} /> : <Hash size={9} />}
      {mode === 'pure' ? 'Pure ML-DSA' : 'Hash ML-DSA'}
    </span>
  );
}

function HexPreview({ label, hex, bytes, className }: { label: string; hex: string; bytes?: number; className?: string }) {
  return (
    <div className={cn('space-y-1', className)}>
      <div className="flex justify-between items-center">
        <span className="text-[9px] uppercase font-bold opacity-40 tracking-wider">{label}</span>
        {bytes !== undefined && (
          <span className="text-[9px] font-mono opacity-30">{bytes} bytes</span>
        )}
      </div>
      <div className="p-2 bg-[#141414]/5 font-mono text-[10px] break-all border border-[#141414]/10 leading-relaxed">
        {hex || <span className="opacity-30 italic">—</span>}
      </div>
    </div>
  );
}

// ─── App ─────────────────────────────────────────────────────────────────────

export default function App() {
  const [variant, setVariant] = useState<MLDSAVariant>('ML-DSA-87');

  // ── Inspect tab state ────────────────────────────────────────────────────
  const [publicKey, setPublicKey] = useState('');
  const [signature, setSignature] = useState('');
  const [message, setMessage] = useState('');
  const [result, setResult] = useState<InspectionResult | null>(null);
  const [isInspecting, setIsInspecting] = useState(false);
  const [inspectMode, setInspectMode] = useState<SignMode>('pure');
  const [inspectContext, setInspectContext] = useState('');
  const [inspectHashAlg, setInspectHashAlg] = useState<HashAlg>('SHA-256');
  const [inspectLegacy, setInspectLegacy] = useState(false);
  const [isMessageBinary, setIsMessageBinary] = useState(false);
  const [showAdvancedVerify, setShowAdvancedVerify] = useState(false);
  const [inspectImportError, setInspectImportError] = useState<string | null>(null);

  // Inspect binary import refs
  const inspectPubBinRef = useRef<HTMLInputElement>(null);
  const inspectSigBinRef = useRef<HTMLInputElement>(null);
  const inspectMessageBinRef = useRef<HTMLInputElement>(null);

  // ── Generate / Sign tab state ────────────────────────────────────────────
  const [activeTab, setActiveTab] = useState<'inspect' | 'generate' | 'python' | 'x509'>('inspect');
  const [genKeys, setGenKeys] = useState<{ publicKey: string; privateKey: string } | null>(null);
  const [genMessage, setGenMessage] = useState('Hello, ML-DSA!');
  const [isGenMessageBinary, setIsGenMessageBinary] = useState(false);
  const [genSignature, setGenSignature] = useState('');
  const [signMode, setSignMode] = useState<SignMode>('pure');
  const [signContext, setSignContext] = useState('');
  const [signHashAlg, setSignHashAlg] = useState<HashAlg>('SHA-256');
  const [showAdvancedSign, setShowAdvancedSign] = useState(false);
  const [signDeterministic, setSignDeterministic] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);

  // Key generation binary import refs
  const importInputRef = useRef<HTMLInputElement>(null);
  const importPubBinRef = useRef<HTMLInputElement>(null);
  const importPrivBinRef = useRef<HTMLInputElement>(null);
  const importSigBinRef = useRef<HTMLInputElement>(null);
  const importGenMessageBinRef = useRef<HTMLInputElement>(null);

  // ── X.509 tab state ───────────────────────────────────────────────────────
  const [x509Result, setX509Result] = useState<X509ParseResult | null>(null);
  const [x509VerifyValid, setX509VerifyValid] = useState<boolean | null>(null);
  const [x509IssuerPubHex, setX509IssuerPubHex] = useState('');
  const x509UploadRef = useRef<HTMLInputElement>(null);
  const x509IssuerUploadRef = useRef<HTMLInputElement>(null);
  const [x509DragActive, setX509DragActive] = useState(false);

  // ── Inspect handlers ──────────────────────────────────────────────────────

  const handleInspect = async () => {
    if (!publicKey || !signature || !message) return;
    setIsInspecting(true);
    const opts: SigningOptions = {
      mode: inspectMode,
      contextText: inspectContext,
      hashAlg: inspectHashAlg,
      checkLegacyMode: inspectLegacy,
      // Verification is inherently deterministic; we thread this flag only for
      // symmetry with the signing UI and potential future use.
      deterministic: false,
    };
    const msgInput = isMessageBinary ? hexToUint8Array(message) : message;
    const res = await inspectSignature(variant, publicKey, signature, msgInput, opts);
    setResult(res);
    setIsInspecting(false);
  };

  const handleImportPubKeyBin = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setInspectImportError(null);
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const bytes = await readBinFile(file);
      setPublicKey(uint8ArrayToHex(bytes));
      setResult(null);
    } catch { setInspectImportError('Failed to read binary public key file.'); }
    e.target.value = '';
  };

  const handleImportSigBin = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setInspectImportError(null);
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const bytes = await readBinFile(file);
      setSignature(uint8ArrayToHex(bytes));
      setResult(null);
    } catch { setInspectImportError('Failed to read binary signature file.'); }
    e.target.value = '';
  };

  const handleImportMessageBin = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setInspectImportError(null);
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const bytes = await readBinFile(file);
      setMessage(uint8ArrayToHex(bytes));
      setIsMessageBinary(true);
      setResult(null);
    } catch { setInspectImportError('Failed to read binary message file.'); }
    e.target.value = '';
  };

  // ── Key gen / sign handlers ───────────────────────────────────────────────

  const handleGenerateKeys = () => { setGenKeys(generateKeyPair(variant)); setGenSignature(''); };

  const handleSign = () => {
    if (!genKeys) return;
    const opts: SigningOptions = {
      mode: signMode,
      contextText: signContext,
      hashAlg: signHashAlg,
      deterministic: signDeterministic,
    };
    const msgInput = isGenMessageBinary ? hexToUint8Array(genMessage) : genMessage;
    const sig = signMessage(variant, genKeys.privateKey, msgInput, opts);
    setGenSignature(sig);
  };

  const copyToClipboard = (text: string) => navigator.clipboard.writeText(text);

  // JSON export/import (keys)
  const handleExportKeys = () => {
    if (!genKeys) return;
    downloadJSON(`mldsa-keys-${variant.toLowerCase()}.json`, { version: 1, variant, ...genKeys } as KeyBundle);
  };

  const handleImportKeys = (e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError(null);
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
      try {
        const parsed: KeyBundle = JSON.parse(evt.target?.result as string);
        if (!parsed.publicKey || !parsed.privateKey) throw new Error('Missing key fields');
        if (parsed.variant && parsed.variant !== variant) setVariant(parsed.variant);
        setGenKeys({ publicKey: parsed.publicKey, privateKey: parsed.privateKey });
        setGenSignature('');
      } catch { setImportError('Invalid key bundle file.'); }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  // JSON export (signature)
  const handleExportSignature = () => {
    if (!genSignature || !genKeys) return;
    downloadJSON(`mldsa-signature-${variant.toLowerCase()}.json`, {
      version: 1, variant, mode: signMode,
      hashAlg: signMode === 'hash-ml-dsa' ? signHashAlg : undefined,
      contextText: signContext, message: genMessage,
      signature: genSignature, publicKey: genKeys.publicKey,
    } as SignatureBundle);
  };

  // Binary key exports
  const handleExportPublicKeyBin = () => genKeys && downloadBinary(`mldsa-pubkey-${variant.toLowerCase()}.bin`, hexToUint8Array(genKeys.publicKey));
  const handleExportPrivateKeyBin = () => genKeys && downloadBinary(`mldsa-privkey-${variant.toLowerCase()}.bin`, hexToUint8Array(genKeys.privateKey));
  const handleExportSignatureBin = () => genSignature && downloadBinary(`mldsa-sig-${variant.toLowerCase()}.bin`, hexToUint8Array(genSignature));

  const handleImportPublicKeyBin = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError(null);
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const bytes = await readBinFile(file);
      setGenKeys(prev => prev ? { ...prev, publicKey: uint8ArrayToHex(bytes) } : { publicKey: uint8ArrayToHex(bytes), privateKey: '' });
      setGenSignature('');
    } catch { setImportError('Failed to read binary public key file.'); }
    e.target.value = '';
  };

  const handleImportPrivateKeyBin = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError(null);
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const bytes = await readBinFile(file);
      const privHex = uint8ArrayToHex(bytes);
      setGenKeys(prev => prev ? { ...prev, privateKey: privHex } : { publicKey: '', privateKey: privHex });
      setGenSignature('');
    } catch { setImportError('Failed to read binary private key file.'); }
    e.target.value = '';
  };

  // ── X.509 Handlers ────────────────────────────────────────────────────────

  const loadX509File = async (file: File) => {
    // Read file. If it ends in .pem or .crt it might be text, .der or .cer might be binary.
    // readBinFile handles both well enough since text is just bytes, and we decode it in the service if it's PEM.
    try {
      const bytes = await readBinFile(file);
      const parsed = processCertificateBytes(bytes);
      setX509Result(parsed);
      setX509VerifyValid(null);
      setX509IssuerPubHex('');

      if (parsed.valid && parsed.details?.isSelfSigned && parsed.details.signatureVariant) {
        const isValid = verifyX509Signature(
          parsed.details.tbsBytes,
          parsed.details.signatureValueBytes,
          parsed.details.publicKeyBytes,
          parsed.details.signatureVariant
        );
        setX509VerifyValid(isValid);
      }
    } catch (err: any) {
      setX509Result({ valid: false, error: 'Failed to read file: ' + err.message });
      setX509VerifyValid(null);
    }
  };

  const handleX509Upload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    await loadX509File(file);
    e.target.value = '';
  };

  const handleX509Drop = async (e: React.DragEvent<HTMLButtonElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setX509DragActive(false);
    const file = e.dataTransfer.files?.[0];
    if (!file) return;
    await loadX509File(file);
  };

  const handleX509DragOver = (e: React.DragEvent<HTMLButtonElement>) => {
    e.preventDefault();
    e.stopPropagation();
    if (!x509DragActive) setX509DragActive(true);
  };

  const handleX509DragLeave = (e: React.DragEvent<HTMLButtonElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setX509DragActive(false);
  };

  const handleVerifyX509 = () => {
    if (!x509Result?.details?.signatureVariant || !x509IssuerPubHex) return;
    try {
      const issuerBytes = hexToUint8Array(x509IssuerPubHex);
      const isValid = verifyX509Signature(
        x509Result.details.tbsBytes,
        x509Result.details.signatureValueBytes,
        issuerBytes,
        x509Result.details.signatureVariant
      );
      setX509VerifyValid(isValid);
    } catch (e) {
      setX509VerifyValid(false);
    }
  };

  const handleImportX509IssuerBin = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const bytes = await readBinFile(file);
      setX509IssuerPubHex(uint8ArrayToHex(bytes));
      setX509VerifyValid(null); // Reset verification state
    } catch (e) { }
    e.target.value = '';
  };

  // ────────────────────────────────────────────────────────────────────────────

  const handleImportSignatureBin = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError(null);
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const bytes = await readBinFile(file);
      setGenSignature(uint8ArrayToHex(bytes));
    } catch { setImportError('Failed to read binary signature file.'); }
    e.target.value = '';
  };

  const handleImportGenMessageBin = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError(null);
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const bytes = await readBinFile(file);
      setGenMessage(uint8ArrayToHex(bytes));
      setIsGenMessageBinary(true);
      setGenSignature('');
    } catch { setImportError('Failed to read binary message file.'); }
    e.target.value = '';
  };

  // "Send to Inspector" — also mirrors mode/context/hashAlg
  const sendToInspector = () => {
    setPublicKey(genKeys?.publicKey || '');
    setSignature(genSignature);
    setMessage(genMessage);
    setIsMessageBinary(isGenMessageBinary);
    setInspectMode(signMode);
    setInspectContext(signContext);
    setInspectHashAlg(signHashAlg);
    if (signMode === 'hash-ml-dsa' || signContext) setShowAdvancedVerify(true);
    setInspectLegacy(false);
    setActiveTab('inspect');
    setResult(null);
  };

  // ── Python code ────────────────────────────────────────────────────────────
  const pythonCode = `
# ML-DSA (FIPS 204) Reference Implementation
# Requires: pip install oqs (liboqs-python) or similar

import oqs

def mldsa_utility():
    variant = "${variant.replace('ML-DSA-', 'Dilithium')}"
    sig_alg = oqs.Signature(variant)
    
    # 1. Key Generation
    public_key = sig_alg.generate_keypair()
    private_key = sig_alg.export_secret_key()
    
    # 2. Signing
    message = b"${message || 'Hello, ML-DSA!'}"
    signature = sig_alg.sign(message)
    
    # 3. Verification
    is_valid = sig_alg.verify(message, signature, public_key)
    
    print(f"Valid: {is_valid}")
    print(f"Signature Length: {len(signature)} bytes")

if __name__ == "__main__":
    mldsa_utility()
  `;

  // ── Shared UI sub-components ───────────────────────────────────────────────

  /** A row of tiny action buttons used above hex displays */
  const ActionRow = ({ children }: { children: React.ReactNode }) => (
    <div className="flex gap-3 flex-wrap items-center">{children}</div>
  );

  const TinyBtn = ({ onClick, disabled, className, children, title }: {
    onClick: () => void; disabled?: boolean; className?: string; children: React.ReactNode; title?: string;
  }) => (
    <button
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={cn('text-[10px] flex items-center gap-1 hover:underline disabled:opacity-30', className)}
    >
      {children}
    </button>
  );

  /** Signing / Verify options panel (shared between sign + inspect tabs) */
  const AdvancedOptions = ({
    mode, onModeChange, context, onContextChange, hashAlg, onHashAlgChange, label,
    inspectLegacy, onInspectLegacyChange,
    deterministic, onDeterministicChange,
  }: {
    mode: SignMode; onModeChange: (m: SignMode) => void;
    context: string; onContextChange: (c: string) => void;
    hashAlg: HashAlg; onHashAlgChange: (h: HashAlg) => void;
    label?: string;
    inspectLegacy?: boolean;
    onInspectLegacyChange?: (v: boolean) => void;
    deterministic?: boolean;
    onDeterministicChange?: (v: boolean) => void;
  }) => (
    <div className="space-y-4 p-4 border border-[#141414]/20 bg-[#141414]/3 rounded-sm">
      {label && <p className="text-[10px] uppercase font-bold opacity-40 tracking-wider">{label}</p>}

      {/* Mode toggle */}
      <div className="flex gap-2">
        {(['pure', 'hash-ml-dsa'] as SignMode[]).map((m) => (
          <button
            key={m}
            onClick={() => onModeChange(m)}
            className={cn(
              'px-3 py-1.5 text-[10px] font-mono border transition-colors flex items-center gap-1.5',
              mode === m ? 'bg-[#141414] text-[#E4E3E0] border-[#141414]' : 'border-[#141414]/30 hover:border-[#141414]/60',
            )}
          >
            {m === 'pure' ? <Lock size={9} /> : <Hash size={9} />}
            {m === 'pure' ? 'Pure ML-DSA' : 'Hash ML-DSA'}
          </button>
        ))}
      </div>

      {/* Hash alg selector — only in hash-ml-dsa mode */}
      {mode === 'hash-ml-dsa' && (
        <div className="space-y-1.5">
          <label className="text-[10px] uppercase font-bold opacity-40">Pre-hash Algorithm</label>
          <div className="flex gap-2 flex-wrap">
            {HASH_ALGS.map((h) => (
              <button
                key={h}
                title={`Select ${h} as pre-hash algorithm`}
                onClick={() => onHashAlgChange(h)}
                className={cn(
                  'px-3 py-1 text-[10px] font-mono border transition-colors',
                  hashAlg === h ? 'bg-violet-700 text-white border-violet-700' : 'border-[#141414]/30 hover:border-[#141414]/60',
                )}
              >
                {h}
              </button>
            ))}
          </div>
          <p className="text-[9px] opacity-40 font-mono">
            HashML-DSA pre-hashes the message with the selected algorithm before signing.
          </p>
        </div>
      )}

      {/* Context */}
      <div className="space-y-1.5">
        <label className="text-[10px] uppercase font-bold opacity-40">
          Context String <span className="font-normal normal-case">(optional, UTF-8, max 255 bytes)</span>
        </label>
        <input
          type="text"
          title="Context string to cryptographically bind the signature to specific protocol metadata"
          value={context}
          onChange={(e) => onContextChange(e.target.value)}
          placeholder="e.g. production-v2 or leave empty"
          className="w-full p-2 bg-transparent border border-[#141414]/30 font-mono text-xs focus:outline-none focus:border-[#141414]"
        />
        {context && (
          <p className="text-[9px] font-mono opacity-40">
            Hex: 0x{Array.from(new TextEncoder().encode(context)).map(b => b.toString(16).padStart(2, '0')).join('')}
            {' '}({new TextEncoder().encode(context).length} bytes)
          </p>
        )}
      </div>

      {/* Experimental Legacy Mode Checkbox - if props exist to toggle it */}
      {onInspectLegacyChange && (
        <label className="flex items-center gap-2 mt-4 pt-4 border-t border-[#141414]/10 cursor-pointer">
          <input
            type="checkbox"
            checked={!!inspectLegacy}
            onChange={(e) => onInspectLegacyChange(e.target.checked)}
            className="w-3 h-3 accent-[#141414]"
          />
          <span className="text-[10px] uppercase font-bold opacity-60">
            Experimental: Test legacy CRYSTALS-Dilithium verification
          </span>
        </label>
      )}

      {/* Deterministic signing toggle, when provided */}
      {onDeterministicChange && (
        <label className="flex items-center gap-2 mt-2 cursor-pointer">
          <input
            type="checkbox"
            checked={!!deterministic}
            onChange={(e) => onDeterministicChange(e.target.checked)}
            className="w-3 h-3 accent-[#141414]"
          />
          <span className="text-[10px] uppercase font-bold opacity-60">
            Deterministic ML-DSA signatures (disable extra randomness)
          </span>
        </label>
      )}
    </div>
  );

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#E4E3E0] text-[#141414] font-sans selection:bg-[#141414] selection:text-[#E4E3E0]">

      {/* Header */}
      <header className="border-b border-[#141414] p-6 flex flex-wrap justify-between items-center gap-4">
        <div className="flex items-center gap-3">
          <div className="bg-[#141414] p-2 rounded-sm">
            <Shield className="text-[#E4E3E0] w-6 h-6" />
          </div>
          <div className="flex items-center gap-4">
            <div>
              <h1 className="font-serif italic text-2xl leading-none">ML-DSA Inspector</h1>
              <p className="text-[10px] uppercase tracking-widest opacity-50 mt-1 font-mono">FIPS 204 Post-Quantum Utility</p>
            </div>
            {typeof __APP_VERSION__ !== 'undefined' && (
              <span className="px-2 py-1 bg-[#141414]/10 rounded-sm text-[10px] font-mono font-bold">
                v{__APP_VERSION__}
              </span>
            )}
          </div>
        </div>
        <div className="flex gap-2 flex-wrap">
          {VARIANTS.map((v) => (
            <button
              key={v}
              title={`Switch security parameter to ${v}`}
              onClick={() => setVariant(v)}
              className={cn(
                'px-3 py-1 text-[11px] font-mono border border-[#141414] transition-colors',
                variant === v ? 'bg-[#141414] text-[#E4E3E0]' : 'hover:bg-[#141414]/5',
              )}
            >
              {v}
            </button>
          ))}
        </div>
      </header>

      <main className="max-w-6xl mx-auto p-8 grid grid-cols-1 lg:grid-cols-12 gap-8">

        {/* Sidebar Navigation */}
        <div className="lg:col-span-3 space-y-2">
          {([
            ['inspect', <Search size={18} />, 'Inspect Signature'],
            ['x509', <FileCheck2 size={18} />, 'X.509 Certificates'],
            ['generate', <Key size={18} />, 'Key & Sign Tools'],
            ['python', <Terminal size={18} />, 'Python Reference'],
          ] as const).map(([tab, icon, label]) => (
            <button
              key={tab}
              title={`Navigate to ${label}`}
              onClick={() => setActiveTab(tab)}
              className={cn(
                'w-full flex items-center gap-3 p-4 border border-[#141414] text-left transition-all',
                activeTab === tab ? 'bg-[#141414] text-[#E4E3E0]' : 'hover:bg-[#141414]/5',
              )}
            >
              {icon}
              <span className="font-serif italic">{label}</span>
            </button>
          ))}

          <div className="mt-8 p-4 border border-[#141414]/20 bg-[#141414]/5 rounded-sm">
            <div className="flex items-center gap-2 mb-2 opacity-60">
              <Info size={14} />
              <span className="text-[10px] uppercase font-bold tracking-wider">Technical Note</span>
            </div>
            <p className="text-xs leading-relaxed opacity-70">
              ML-DSA is a module-lattice-based digital signature algorithm standardised in NIST FIPS 204.
              HashML-DSA pre-hashes the message with a NIST hash before signing.
            </p>
          </div>
        </div>

        {/* Main Content */}
        <div className="lg:col-span-9">
          <AnimatePresence mode="wait">

            {/* ── Inspect & Verify Tab ───────────────────────────────────────────── */}
            {activeTab === 'inspect' ? (
              <motion.div
                key="inspect"
                initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}
                className="space-y-6"
              >
                {/* Hidden binary inputs */}
                <input ref={inspectPubBinRef} type="file" accept=".bin,application/octet-stream" onChange={handleImportPubKeyBin} className="hidden" />
                <input ref={inspectSigBinRef} type="file" accept=".bin,application/octet-stream" onChange={handleImportSigBin} className="hidden" />
                <input ref={inspectMessageBinRef} type="file" accept=".bin,application/octet-stream" onChange={handleImportMessageBin} className="hidden" />

                {inspectImportError && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                    className="flex items-center gap-3 p-3 border border-red-400 bg-red-50 text-red-700 text-xs font-mono"
                  >
                    <AlertTriangle size={14} />
                    {inspectImportError}
                    <button onClick={() => setInspectImportError(null)} className="ml-auto opacity-60 hover:opacity-100">✕</button>
                  </motion.div>
                )}

                <div className="grid grid-cols-1 gap-6">

                  {/* Public Key */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <label className="flex items-center gap-2 text-[11px] uppercase font-bold tracking-wider opacity-60">
                        <Key size={14} /> Public Key (Hex)
                        {publicKey && (
                          <span className="ml-2 font-mono text-[9px] bg-[#141414]/10 text-[#141414] px-1.5 py-0.5 rounded-sm">
                            {Math.ceil(publicKey.replace(/[^a-fA-F0-9]/g, '').length / 2)} bytes
                          </span>
                        )}
                      </label>
                      <ActionRow>
                        <TinyBtn title="Import a raw binary public key from a .bin file" onClick={() => { setInspectImportError(null); inspectPubBinRef.current?.click(); }} className="opacity-60 hover:opacity-100">
                          <Upload size={10} /> Import .bin
                        </TinyBtn>
                        <TinyBtn title="Save the current public key as a raw binary .bin file" onClick={() => publicKey && downloadBinary(`mldsa-pubkey-inspect.bin`, hexToUint8Array(publicKey))} disabled={!publicKey} className="opacity-60 hover:opacity-100">
                          <Download size={10} /> Export .bin
                        </TinyBtn>
                      </ActionRow>
                    </div>
                    <textarea
                      title="Paste the hex encoded public key here"
                      value={publicKey}
                      onChange={(e) => { setPublicKey(e.target.value); setResult(null); }}
                      placeholder="Enter hex-encoded public key..."
                      className="w-full h-24 p-4 bg-transparent border border-[#141414] font-mono text-xs focus:outline-none focus:ring-1 focus:ring-[#141414] resize-none"
                    />
                  </div>

                  {/* Signature */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <label className="flex items-center gap-2 text-[11px] uppercase font-bold tracking-wider opacity-60">
                        <Terminal size={14} /> Signature (Hex)
                        {signature && (
                          <span className="ml-2 font-mono text-[9px] bg-[#141414]/10 text-[#141414] px-1.5 py-0.5 rounded-sm">
                            {Math.ceil(signature.replace(/[^a-fA-F0-9]/g, '').length / 2)} bytes
                          </span>
                        )}
                      </label>
                      <ActionRow>
                        <TinyBtn title="Import a raw binary signature from a .bin file" onClick={() => { setInspectImportError(null); inspectSigBinRef.current?.click(); }} className="opacity-60 hover:opacity-100">
                          <Upload size={10} /> Import .bin
                        </TinyBtn>
                        <TinyBtn title="Save the current signature as a raw binary .bin file" onClick={() => signature && downloadBinary(`mldsa-sig-inspect.bin`, hexToUint8Array(signature))} disabled={!signature} className="opacity-60 hover:opacity-100">
                          <Download size={10} /> Export .bin
                        </TinyBtn>
                      </ActionRow>
                    </div>
                    <textarea
                      title="Paste the generated digital signature hex here"
                      value={signature}
                      onChange={(e) => { setSignature(e.target.value); setResult(null); }}
                      placeholder="Enter hex-encoded signature..."
                      className="w-full h-28 p-4 bg-transparent border border-[#141414] font-mono text-xs focus:outline-none focus:ring-1 focus:ring-[#141414] resize-none"
                    />
                  </div>

                  {/* Message */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <label className="flex items-center gap-2 text-[11px] uppercase font-bold tracking-wider opacity-60">
                        <FileText size={14} /> Payload / Message
                        {isMessageBinary && (
                          <span className="ml-2 font-mono text-[9px] bg-violet-600 text-white px-1.5 py-0.5 rounded-sm">HEX</span>
                        )}
                        {message && (
                          <span className="ml-2 font-mono text-[9px] bg-[#141414]/10 text-[#141414] px-1.5 py-0.5 rounded-sm">
                            {isMessageBinary
                              ? Math.ceil(message.replace(/[^a-fA-F0-9]/g, '').length / 2)
                              : new TextEncoder().encode(message).length} bytes
                          </span>
                        )}
                      </label>
                      <ActionRow>
                        <TinyBtn onClick={() => { setIsMessageBinary(false); setMessage(''); setResult(null); }} className="opacity-60 hover:opacity-100">
                          Clear / Reset Text
                        </TinyBtn>
                        <TinyBtn onClick={() => { setInspectImportError(null); inspectMessageBinRef.current?.click(); }} className="opacity-60 hover:opacity-100">
                          <Upload size={10} /> Import .bin
                        </TinyBtn>
                      </ActionRow>
                    </div>
                    <textarea
                      title={isMessageBinary ? "Hex encoded binary message" : "Enter the exact message string that was signed"}
                      value={message}
                      onChange={(e) => {
                        setMessage(e.target.value);
                        setResult(null);
                      }}
                      placeholder={isMessageBinary ? "Paste hex-encoded binary message..." : "Enter the message that was signed..."}
                      className="w-full h-24 p-4 bg-transparent border border-[#141414] font-mono text-xs focus:outline-none focus:ring-1 focus:ring-[#141414] resize-none"
                    />
                  </div>
                </div>

                {/* Advanced Verify Options toggle */}
                <div className="space-y-3">
                  <button
                    onClick={() => setShowAdvancedVerify(v => !v)}
                    className="flex items-center gap-2 text-[11px] uppercase font-bold tracking-wider opacity-50 hover:opacity-80 transition-opacity"
                  >
                    <ChevronDown size={14} className={cn('transition-transform', showAdvancedVerify && 'rotate-180')} />
                    Verification Options
                  </button>
                  {showAdvancedVerify && (
                    <AdvancedOptions
                      label="Mode & Context used during signing"
                      mode={inspectMode} onModeChange={setInspectMode}
                      context={inspectContext} onContextChange={setInspectContext}
                      hashAlg={inspectHashAlg} onHashAlgChange={setInspectHashAlg}
                      // @ts-ignore - passing optional props for the legacy switch
                      inspectLegacy={inspectLegacy} onInspectLegacyChange={setInspectLegacy}
                    />
                  )}
                </div>

                <button
                  title="Run cryptographic ML-DSA algorithms to verify the signature"
                  onClick={handleInspect}
                  disabled={isInspecting || !publicKey || !signature || !message}
                  className="w-full py-4 bg-[#141414] text-[#E4E3E0] font-serif italic text-lg flex items-center justify-center gap-3 hover:opacity-90 disabled:opacity-30 transition-opacity"
                >
                  {isInspecting ? <RefreshCw className="animate-spin" /> : <ChevronRight />}
                  {isInspecting ? 'Analyzing...' : 'Inspect & Verify'}
                </button>

                {/* ── Results ──────────────────────────────────────────────────── */}
                {result && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }}
                    className={cn(
                      'border-2 flex flex-col gap-0 items-start overflow-hidden',
                      result.valid ? 'border-[#141414] bg-white' : 'border-red-500 bg-red-50',
                    )}
                  >
                    {/* Status banner */}
                    <div className="flex gap-6 items-start w-full p-6">
                      <div className="shrink-0">
                        {result.valid
                          ? <CheckCircle2 className="w-12 h-12 text-green-600" />
                          : <XCircle className="w-12 h-12 text-red-600" />
                        }
                      </div>
                      <div className="flex-1 space-y-4">
                        <div>
                          <h3 className="font-serif italic text-xl">
                            {result.valid ? 'Verification Successful' : 'Verification Failed'}
                          </h3>
                          <p className="text-xs opacity-60 font-mono mt-1">
                            {result.valid
                              ? `Signature is cryptographically valid for the provided ${variant} public key.`
                              : result.error || 'Signature does not match the public key and message.'}
                          </p>
                        </div>

                        {/* Meta: mode, context, sizes */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 border-t border-[#141414]/10 pt-4 flex-wrap">
                          {result.meta && (
                            <>
                              <div className="space-y-1 col-span-2 md:col-span-1">
                                <span className="text-[9px] uppercase font-bold opacity-40">Mode</span>
                                <div><ModeBadge mode={result.meta.mode} /></div>
                              </div>
                              {result.meta.hashAlg && (
                                <div className="space-y-1">
                                  <span className="text-[9px] uppercase font-bold opacity-40">Pre-hash</span>
                                  <p className="text-xs font-mono text-violet-700">{result.meta.hashAlg}</p>
                                </div>
                              )}
                              {result.meta.contextHex && (
                                <div className="space-y-1 col-span-2">
                                  <span className="text-[9px] uppercase font-bold opacity-40">Context (hex)</span>
                                  <p className="text-xs font-mono break-all">{result.meta.contextHex}</p>
                                </div>
                              )}
                            </>
                          )}
                          {result.details && (
                            <>
                              <div className="space-y-1">
                                <span className="text-[9px] uppercase font-bold opacity-40">Variant</span>
                                <p className="text-xs font-mono">{result.details.variant}</p>
                              </div>
                              <div className="space-y-1">
                                <span className="text-[9px] uppercase font-bold opacity-40">Sig Size</span>
                                <p className="text-xs font-mono">{result.details.signatureSize} B</p>
                              </div>
                              <div className="space-y-1">
                                <span className="text-[9px] uppercase font-bold opacity-40">PK Size</span>
                                <p className="text-xs font-mono">{result.details.publicKeySize} B</p>
                              </div>
                            </>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* SHAKE256 Reconstruction Panel */}
                    {result.components && (
                      <div className="w-full border-t border-[#141414]/10 bg-[#141414]/3 p-6 space-y-5">
                        <div className="flex items-center gap-2">
                          <Cpu size={14} className="opacity-60" />
                          <span className="text-[10px] uppercase font-bold tracking-wider opacity-60">
                            SHAKE256 Cryptographic Reconstruction
                          </span>
                          {result.meta && (
                            <span className="ml-2">
                              <ModeBadge mode={result.meta.mode} />
                            </span>
                          )}
                        </div>

                        <div className="space-y-3">
                          {/* Step 1: tr */}
                          <div className="p-4 bg-white border border-[#141414]/10 space-y-3">
                            <div className="flex items-center gap-2">
                              <span className="text-[9px] font-mono font-bold bg-[#141414] text-[#E4E3E0] px-1.5 py-0.5">STEP 1</span>
                              <span className="text-[10px] font-mono opacity-70">tr = SHAKE256(pk, dkLen=64)</span>
                            </div>
                            <HexPreview label="Public Key Hash (tr) — 64 bytes" hex={result.components.trHex} bytes={64} />
                          </div>

                          {/* Step 2: M' */}
                          <div className="p-4 bg-white border border-[#141414]/10 space-y-3">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-[9px] font-mono font-bold bg-[#141414] text-[#E4E3E0] px-1.5 py-0.5">STEP 2</span>
                              <span className="text-[10px] font-mono opacity-70">
                                {result.meta?.mode === 'hash-ml-dsa'
                                  ? `M' = [0x01, ctx_len, ctx, OID(${result.meta.hashAlg}), ${result.meta.hashAlg}(msg)]`
                                  : "M' = [0x00, ctx_len, ctx, msg]"}
                              </span>
                            </div>
                            <HexPreview
                              label={`M' — Message representative ${result.meta?.mode === 'hash-ml-dsa' ? '(pre-hashed)' : '(pure)'}`}
                              hex={result.components.mPrimeHex}
                              bytes={Math.round(result.components.mPrimeHex.length / 2)}
                            />
                          </div>

                          {/* Step 3: μ */}
                          <div className="p-4 bg-white border border-[#141414]/10 space-y-3">
                            <div className="flex items-center gap-2">
                              <span className="text-[9px] font-mono font-bold bg-[#141414] text-[#E4E3E0] px-1.5 py-0.5">STEP 3</span>
                              <span className="text-[10px] font-mono opacity-70">μ = SHAKE256(tr ∥ M', dkLen=64)</span>
                            </div>
                            <HexPreview label="Message Representative (μ) — 64 bytes" hex={result.components.muHex} bytes={64} />
                          </div>

                          {/* Step 4: c̃ */}
                          <div className="p-4 bg-white border border-[#141414]/10 space-y-3">
                            <div className="flex items-center gap-2">
                              <span className="text-[9px] font-mono font-bold bg-[#141414] text-[#E4E3E0] px-1.5 py-0.5">STEP 4</span>
                              <span className="text-[10px] font-mono opacity-70">
                                c̃ = sig[0..{result.components.challengeByteLen}] — extracted from signature
                              </span>
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                              <div className="md:col-span-2">
                                <HexPreview
                                  label={`Commitment Hash (c̃) — ${result.components.challengeByteLen} bytes`}
                                  hex={result.components.challengeHex}
                                  bytes={result.components.challengeByteLen}
                                />
                              </div>
                              <div className="space-y-3">
                                <HexPreview label="Response (z) preview [32 B]" hex={result.components.zPreviewHex} />
                                <HexPreview label="Hint (h) preview [tail 32 B]" hex={result.components.hPreviewHex} />
                              </div>
                            </div>
                          </div>

                          {/* Step 5: library result */}
                          <div className={cn(
                            'p-4 border space-y-2',
                            result.valid ? 'border-green-300 bg-green-50' : 'border-red-300 bg-red-50',
                          )}>
                            <div className="flex items-center gap-2">
                              <span className="text-[9px] font-mono font-bold bg-[#141414] text-[#E4E3E0] px-1.5 py-0.5">STEP 5</span>
                              <span className="text-[10px] font-mono opacity-70">
                                c̃' = SHAKE256(μ ∥ w₁Encode(w'₁)) — reconstructed via lattice math
                              </span>
                            </div>
                            {result.components.reconstructedChallengeHex && (
                              <HexPreview
                                label="Reconstructed Commitment Hash (c̃') — computed"
                                hex={result.components.reconstructedChallengeHex}
                                bytes={result.components.challengeByteLen}
                                className="mb-2"
                              />
                            )}
                            <div className="flex items-center gap-3">
                              {result.valid
                                ? <CheckCircle2 size={20} className="text-green-600 shrink-0" />
                                : <XCircle size={20} className="text-red-600 shrink-0" />
                              }
                              <p className="text-xs font-mono">
                                {result.valid
                                  ? 'c̃\' = c̃ ✓  — Reconstructed commitment hash matches. Signature is valid.'
                                  : 'c̃\' ≠ c̃ ✗  — Reconstructed commitment hash does not match. Signature invalid or inputs are mismatched.'}
                              </p>
                            </div>
                            <p className="text-[9px] opacity-50 italic font-mono">
                              The lattice reconstruction (A·z − c·t₁·2^d → UseHint → w'₁) is performed by the noble library. Steps 1–4 above are independently derived from inputs.
                            </p>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Legacy Mode Extra Box */}
                    {result.legacyValid !== undefined && (
                      <div className={cn(
                        'p-4 border space-y-3 mt-4',
                        result.legacyValid ? 'border-orange-300 bg-orange-50' : 'border-[#141414]/10 bg-white',
                      )}>
                        <div className="flex items-center gap-2 border-b border-[#141414]/10 pb-2 mb-2">
                          <Layers size={14} className={result.legacyValid ? 'text-orange-700' : 'opacity-40'} />
                          <span className={cn('text-[10px] uppercase font-bold tracking-wider', result.legacyValid ? 'text-orange-900' : 'opacity-60')}>
                            Legacy CRYSTALS-Dilithium Check
                          </span>
                        </div>

                        <HexPreview
                          label="Legacy μ = SHAKE256(tr ∥ msg)"
                          hex={result.legacyMuHex || ''}
                          bytes={64}
                        />

                        <div className="flex items-center gap-3 pt-2">
                          {result.legacyValid
                            ? <CheckCircle2 size={16} className="text-orange-600 shrink-0" />
                            : <XCircle size={16} className="text-[#141414]/30 shrink-0" />
                          }
                          <p className={cn('text-xs font-mono', result.legacyValid ? 'text-orange-900' : 'opacity-60')}>
                            {result.legacyValid
                              ? 'Legacy Verification Successful. This signature was matched using the old Dilithium 2/3/5 standard formulation (no M\' context).'
                              : 'Legacy Verification Failed. This is expected if the signature was generated under the final FIPS 204 standard.'}
                          </p>
                        </div>
                      </div>
                    )}
                  </motion.div>
                )}
              </motion.div>
            ) : activeTab === 'generate' ? (
              <motion.div
                key="generate"
                initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}
                className="space-y-8"
              >
                {/* Hidden file inputs */}
                <input ref={importInputRef} type="file" accept=".json,application/json" onChange={handleImportKeys} className="hidden" />
                <input ref={importPubBinRef} type="file" accept=".bin,application/octet-stream" onChange={handleImportPublicKeyBin} className="hidden" />
                <input ref={importPrivBinRef} type="file" accept=".bin,application/octet-stream" onChange={handleImportPrivateKeyBin} className="hidden" />
                <input ref={importSigBinRef} type="file" accept=".bin,application/octet-stream" onChange={handleImportSignatureBin} className="hidden" />
                <input ref={importGenMessageBinRef} type="file" accept=".bin,application/octet-stream" onChange={handleImportGenMessageBin} className="hidden" />

                {/* Key Generation */}
                <section className="space-y-4">
                  <div className="flex flex-wrap justify-between items-end gap-3">
                    <div>
                      <h2 className="font-serif italic text-2xl">Key Generation</h2>
                      <p className="text-xs opacity-60">Generate a new {variant} key pair.</p>
                    </div>
                    <div className="flex gap-2 flex-wrap">
                      <button onClick={() => { setImportError(null); importInputRef.current?.click(); }}
                        className="px-4 py-2 border border-[#141414] hover:bg-[#141414] hover:text-[#E4E3E0] transition-colors font-mono text-xs uppercase tracking-widest flex items-center gap-2">
                        <Upload size={12} /> Import JSON
                      </button>
                      <button onClick={handleExportKeys} disabled={!genKeys}
                        className="px-4 py-2 border border-[#141414] hover:bg-[#141414] hover:text-[#E4E3E0] transition-colors font-mono text-xs uppercase tracking-widest flex items-center gap-2 disabled:opacity-30">
                        <Download size={12} /> Export JSON
                      </button>
                      <button onClick={handleGenerateKeys}
                        title="Generate a secure post-quantum lattice keypair"
                        className="px-4 py-2 border border-[#141414] bg-[#141414] text-[#E4E3E0] hover:opacity-80 transition-colors font-mono text-xs uppercase tracking-widest">
                        Generate New Pair
                      </button>
                    </div>
                  </div>

                  {importError && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                      className="flex items-center gap-3 p-3 border border-red-400 bg-red-50 text-red-700 text-xs font-mono">
                      <AlertTriangle size={14} className="shrink-0" />
                      {importError}
                      <button onClick={() => setImportError(null)} className="ml-auto opacity-60 hover:opacity-100">✕</button>
                    </motion.div>
                  )}

                  {genKeys && (
                    <div className="grid grid-cols-1 gap-4">
                      {/* Public Key */}
                      <div className="space-y-2">
                        <div className="flex justify-between items-center flex-wrap gap-2">
                          <span className="flex items-center gap-2 text-[10px] uppercase font-bold opacity-40">
                            Public Key
                            <span className="font-mono text-[9px] bg-[#141414] text-[#E4E3E0] px-1.5 py-0.5 rounded-sm opacity-100">
                              {hexToUint8Array(genKeys.publicKey).length} bytes
                            </span>
                          </span>
                          <ActionRow>
                            <TinyBtn title="Import a raw binary public key" onClick={() => { setImportError(null); importPubBinRef.current?.click(); }} className="opacity-60 hover:opacity-100"><Upload size={10} /> Import .bin</TinyBtn>
                            <TinyBtn title="Export this public key as a .bin file" onClick={handleExportPublicKeyBin} className="opacity-60 hover:opacity-100"><Download size={10} /> Export .bin</TinyBtn>
                            <TinyBtn title="Copy hex to clipboard" onClick={() => copyToClipboard(genKeys.publicKey)}><Copy size={10} /> Copy</TinyBtn>
                          </ActionRow>
                        </div>
                        <div className="p-3 bg-white border border-[#141414] font-mono text-[10px] break-all max-h-24 overflow-y-auto">{genKeys.publicKey}</div>
                      </div>
                      {/* Private Key */}
                      <div className="space-y-2">
                        <div className="flex justify-between items-center flex-wrap gap-2">
                          <span className="flex items-center gap-2 text-[10px] uppercase font-bold opacity-40">
                            Private Key (Secret)
                            <span className="font-mono text-[9px] bg-[#141414] text-[#E4E3E0] px-1.5 py-0.5 rounded-sm opacity-100">
                              {hexToUint8Array(genKeys.privateKey).length} bytes
                            </span>
                          </span>
                          <ActionRow>
                            <TinyBtn title="Import a raw binary private key" onClick={() => { setImportError(null); importPrivBinRef.current?.click(); }} className="opacity-60 hover:opacity-100"><Upload size={10} /> Import .bin</TinyBtn>
                            <TinyBtn title="Export this private key as a secure .bin file" onClick={handleExportPrivateKeyBin} className="opacity-60 hover:opacity-100"><Download size={10} /> Export .bin</TinyBtn>
                            <TinyBtn title="Copy hex to clipboard" onClick={() => copyToClipboard(genKeys.privateKey)}><Copy size={10} /> Copy</TinyBtn>
                          </ActionRow>
                        </div>
                        <div className="p-3 bg-white border border-[#141414] font-mono text-[10px] break-all max-h-24 overflow-y-auto">{genKeys.privateKey}</div>
                      </div>
                    </div>
                  )}
                </section>

                {/* Sign Message */}
                <section className="space-y-4 border-t border-[#141414]/10 pt-8">
                  <div>
                    <h2 className="font-serif italic text-2xl">Sign Message</h2>
                    <p className="text-xs opacity-60">Create a signature using the generated private key.</p>
                  </div>

                  <div className="space-y-4">
                    <div className="space-y-2">
                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <label className="flex items-center gap-2 text-[10px] uppercase font-bold opacity-40">
                          Message to Sign
                          {isGenMessageBinary && (
                            <span className="ml-2 font-mono text-[9px] bg-violet-600 text-white px-1.5 py-0.5 rounded-sm">HEX</span>
                          )}
                          {genMessage && (
                            <span className="font-mono text-[9px] bg-[#141414]/10 text-[#141414] px-1.5 py-0.5 rounded-sm opacity-100">
                              {isGenMessageBinary
                                ? Math.ceil(genMessage.replace(/[^a-fA-F0-9]/g, '').length / 2)
                                : new TextEncoder().encode(genMessage).length} bytes
                            </span>
                          )}
                        </label>
                        <ActionRow>
                          <TinyBtn onClick={() => { setIsGenMessageBinary(false); setGenMessage(''); setGenSignature(''); }} className="opacity-60 hover:opacity-100">
                            Clear / Reset Text
                          </TinyBtn>
                          <TinyBtn onClick={() => { setImportError(null); importGenMessageBinRef.current?.click(); }} className="opacity-60 hover:opacity-100">
                            <Upload size={10} /> Import .bin
                          </TinyBtn>
                        </ActionRow>
                      </div>
                      <textarea
                        title={isGenMessageBinary ? "Hex encoded binary message to sign" : "Type the payload to be mathematically signed"}
                        value={genMessage}
                        onChange={(e) => { setGenMessage(e.target.value); setGenSignature(''); }}
                        placeholder={isGenMessageBinary ? "Paste hex-encoded binary message..." : "Enter message to sign..."}
                        className="w-full h-24 p-4 bg-transparent border border-[#141414] font-mono text-xs focus:outline-none focus:ring-1 focus:ring-[#141414] resize-none"
                      />
                    </div>
                  </div>

                  {/* Advanced signing options */}
                  <div className="space-y-3">
                    <button
                      onClick={() => setShowAdvancedSign(v => !v)}
                      className="flex items-center gap-2 text-[11px] uppercase font-bold tracking-wider opacity-50 hover:opacity-80 transition-opacity"
                    >
                      <ChevronDown size={14} className={cn('transition-transform', showAdvancedSign && 'rotate-180')} />
                      Advanced Options
                      {(signMode === 'hash-ml-dsa' || signContext || signDeterministic) && (
                        <span className="ml-1 px-1.5 py-0.5 bg-violet-100 text-violet-700 text-[9px] rounded-sm font-mono">active</span>
                      )}
                    </button>
                    {showAdvancedSign && (
                      <AdvancedOptions
                        label="Signing Mode & Context"
                        mode={signMode} onModeChange={(m) => { setSignMode(m); setGenSignature(''); }}
                        context={signContext} onContextChange={(c) => { setSignContext(c); setGenSignature(''); }}
                        hashAlg={signHashAlg} onHashAlgChange={(h) => { setSignHashAlg(h); setGenSignature(''); }}
                        deterministic={signDeterministic}
                        onDeterministicChange={(v) => { setSignDeterministic(v); setGenSignature(''); }}
                      />
                    )}
                  </div>

                  <button
                    title="Compute the lattice signature for this payload"
                    onClick={handleSign}
                    disabled={!genKeys}
                    className="w-full py-3 border border-[#141414] bg-[#141414] text-[#E4E3E0] font-serif italic disabled:opacity-30 flex items-center justify-center gap-2"
                  >
                    <Layers size={16} />
                    {signMode === 'hash-ml-dsa' ? `Sign with Hash ML-DSA (${signHashAlg})` : 'Sign Payload'}
                  </button>

                  {genSignature && (
                    <div className="space-y-2">
                      <div className="flex justify-between items-center flex-wrap gap-2">
                        <div className="flex items-center gap-2">
                          <span className="flex items-center gap-2 text-[10px] uppercase font-bold opacity-40">
                            Generated Signature
                            <span className="font-mono text-[9px] bg-[#141414] text-[#E4E3E0] px-1.5 py-0.5 rounded-sm opacity-100">
                              {hexToUint8Array(genSignature).length} bytes
                            </span>
                          </span>
                          <ModeBadge mode={signMode} />
                        </div>
                        <ActionRow>
                          <TinyBtn onClick={sendToInspector} className="text-blue-600">
                            <Search size={10} /> Send to Inspector
                          </TinyBtn>
                          <TinyBtn onClick={() => { setImportError(null); importSigBinRef.current?.click(); }} className="opacity-60 hover:opacity-100">
                            <Upload size={10} /> Import .bin
                          </TinyBtn>
                          <TinyBtn onClick={handleExportSignatureBin} className="text-emerald-700">
                            <Download size={10} /> Export .bin
                          </TinyBtn>
                          <TinyBtn onClick={handleExportSignature} className="text-emerald-700">
                            <Download size={10} /> Export .json
                          </TinyBtn>
                          <TinyBtn onClick={() => copyToClipboard(genSignature)}>
                            <Copy size={10} /> Copy
                          </TinyBtn>
                        </ActionRow>
                      </div>
                      {signContext && (
                        <p className="text-[9px] font-mono opacity-50">
                          Context: &quot;{signContext}&quot; ({new TextEncoder().encode(signContext).length} bytes)
                        </p>
                      )}
                      <div className="p-3 bg-white border border-[#141414] font-mono text-[10px] break-all max-h-32 overflow-y-auto">
                        {genSignature}
                      </div>
                    </div>
                  )}

                  {!genSignature && (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => { setImportError(null); importSigBinRef.current?.click(); }}
                        disabled={!genKeys}
                        className="text-[10px] flex items-center gap-2 px-3 py-1.5 border border-[#141414]/30 hover:border-[#141414] hover:bg-[#141414]/5 transition-colors disabled:opacity-30 font-mono"
                      >
                        <Upload size={10} /> Import Signature .bin
                      </button>
                      <span className="text-[9px] opacity-40 font-mono">Load a previously exported raw signature</span>
                    </div>
                  )}
                </section>
              </motion.div>
            ) : activeTab === 'x509' ? (
              <motion.div
                key="x509"
                initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}
                className="space-y-8"
              >
                <div>
                  <h2 className="font-serif italic text-2xl">X.509 Certificate Verification</h2>
                  <p className="text-xs opacity-60">Parse and verify ML-DSA signatures embedded in X.509 Certificates (.pem, .cer, .der, .crt).</p>
                </div>

                <div className="space-y-4">
                  <input type="file" ref={x509UploadRef} onChange={handleX509Upload} className="hidden" accept=".pem,.cer,.der,.crt" />
                  <button
                    type="button"
                    title="Select an X.509 certificate file to parse its structure and mathematically verify embedded ML-DSA signatures"
                    onClick={() => { setX509Result(null); setX509VerifyValid(null); setX509IssuerPubHex(''); x509UploadRef.current?.click(); }}
                    onDragOver={handleX509DragOver}
                    onDragLeave={handleX509DragLeave}
                    onDrop={handleX509Drop}
                    className={cn(
                      'w-full flex flex-col items-center justify-center p-8 border-2 border-dashed transition-colors gap-3 cursor-pointer',
                      x509DragActive
                        ? 'border-[#141414] bg-[#141414]/5'
                        : 'border-[#141414]/20 hover:border-[#141414]/50 hover:bg-[#141414]/5',
                    )}
                  >
                    <div className="p-3 bg-white rounded-full shadow-sm">
                      <FileCheck2 size={24} className="text-[#141414]" />
                    </div>
                    <div className="text-center">
                      <span className="font-bold block">Upload X.509 Certificate</span>
                      <span className="text-xs opacity-50 font-mono block">Supports DER and PEM formats</span>
                      <span className="text-[10px] opacity-40 font-mono mt-1 block">…or drag &amp; drop the certificate file here</span>
                    </div>
                  </button>
                  {x509Result?.error && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex items-center gap-3 p-3 border border-red-400 bg-red-50 text-red-700 text-xs font-mono">
                      <AlertTriangle size={14} className="shrink-0" /> {x509Result.error}
                    </motion.div>
                  )}
                </div>

                {x509Result?.details && (
                  <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
                    {/* Certificate Details */}
                    <div className="p-6 bg-white border border-[#141414]/10 space-y-6">
                      <div className="flex items-center gap-2 border-b border-[#141414]/10 pb-4">
                        <User size={16} className="opacity-60" />
                        <h3 className="font-serif italic text-lg">Certificate Details</h3>
                        {x509Result.details.isSelfSigned && (
                          <span className="ml-auto px-2 py-0.5 bg-violet-100 text-violet-700 text-[10px] uppercase font-bold tracking-wider">Self-Signed</span>
                        )}
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div className="space-y-4">
                          <div className="space-y-1">
                            <span className="text-[10px] uppercase font-bold tracking-wider opacity-40">Subject</span>
                            <p className="text-sm font-medium">{x509Result.details.subject}</p>
                          </div>
                          <div className="space-y-1">
                            <span className="text-[10px] uppercase font-bold tracking-wider opacity-40">Issuer</span>
                            <p className="text-sm font-medium">{x509Result.details.issuer}</p>
                          </div>
                          <div className="space-y-1">
                            <span className="text-[10px] uppercase font-bold tracking-wider opacity-40">Serial Number</span>
                            <p className="text-xs font-mono break-all bg-[#141414]/5 p-2">{x509Result.details.serialNumber}</p>
                          </div>
                        </div>

                        <div className="space-y-4">
                          <div className="space-y-1">
                            <span className="text-[10px] uppercase font-bold tracking-wider opacity-40 flex items-center gap-1"><Calendar size={12} /> Validity Period</span>
                            <p className="text-xs font-mono">Not Before: {x509Result.details.notBefore.toISOString()}</p>
                            <p className="text-xs font-mono">Not After: {x509Result.details.notAfter.toISOString()}</p>
                          </div>
                          <div className="space-y-1">
                            <span className="text-[10px] uppercase font-bold tracking-wider opacity-40 flex items-center gap-1"><Link size={12} /> Signature Algorithm</span>
                            <p className="text-sm font-medium">
                              {x509Result.details.signatureVariant || <span className="text-red-600">Unknown/Unsupported</span>}
                            </p>
                            <p className="text-[10px] font-mono opacity-50">OID: {x509Result.details.signatureAlgorithmObj}</p>
                          </div>
                          <div className="space-y-1">
                            <span className="text-[10px] uppercase font-bold tracking-wider opacity-40">Public Key Size</span>
                            <p className="text-xs font-mono">{x509Result.details.publicKeyBytes.length} bytes</p>
                            <button
                              type="button"
                              onClick={() => downloadBinary(
                                `x509-pubkey-${(x509Result.details?.signatureVariant || 'unknown').toString().toLowerCase()}.bin`,
                                x509Result.details!.publicKeyBytes
                              )}
                              className="mt-2 inline-flex items-center gap-2 px-3 py-1 border border-[#141414]/30 text-[10px] font-mono uppercase tracking-widest hover:border-[#141414] hover:bg-[#141414]/5 transition-colors"
                            >
                              <Download size={10} />
                              Export Public Key .bin
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Verification Panel */}
                    <div className={cn(
                      'p-6 border space-y-4 transition-colors',
                      x509VerifyValid === true ? 'border-[#141414] bg-white' :
                        x509VerifyValid === false ? 'border-red-400 bg-red-50' : 'border-[#141414]/10 bg-[#141414]/3',
                    )}>
                      <div className="flex items-center gap-3 border-b border-[#141414]/10 pb-4">
                        <Shield className={cn('w-5 h-5', x509VerifyValid === true ? 'text-green-600' : x509VerifyValid === false ? 'text-red-500' : 'opacity-40')} />
                        <h3 className="font-serif italic text-lg">Cryptographic Verification</h3>
                      </div>

                      {/* Verification Results */}
                      {x509VerifyValid !== null ? (
                        <div className="flex gap-4 items-center">
                          {x509VerifyValid ? <CheckCircle2 className="w-8 h-8 text-green-600 shrink-0" /> : <XCircle className="w-8 h-8 text-red-600 shrink-0" />}
                          <div>
                            <p className={cn('font-bold', x509VerifyValid ? 'text-green-700' : 'text-red-700')}>
                              {x509VerifyValid ? 'Signature Valid' : 'Signature Invalid'}
                            </p>
                            <p className="text-xs font-mono opacity-70">
                              {x509VerifyValid
                                ? 'The certificate signature mathematically guarantees the TBS (To-Be-Signed) bytes were signed by the provided public key.'
                                : 'The cryptographic verification failed. The signature does not match the public key & TBS contents.'}
                            </p>
                          </div>
                        </div>
                      ) : (
                        <div className="space-y-3">
                          <p className="text-xs opacity-70">
                            {x509Result.details.isSelfSigned
                              ? 'This certificate is self-signed. Verification should occur automatically.'
                              : 'This certificate is issued by a 3rd party. Please load the issuer\'s ML-DSA public key to verify it.'}
                          </p>
                          {!x509Result.details.isSelfSigned && (
                            <div className="flex gap-2">
                              {/* Secondary upload for Issuer Key */}
                              <input type="file" ref={x509IssuerUploadRef} onChange={handleImportX509IssuerBin} className="hidden" accept=".bin" />
                              <input
                                type="text"
                                placeholder="Paste Issuer Public Key Hex..."
                                value={x509IssuerPubHex}
                                onChange={(e) => setX509IssuerPubHex(e.target.value)}
                                className="flex-1 p-3 bg-white border border-[#141414]/20 font-mono text-xs focus:border-[#141414] focus:outline-none"
                              />
                              <button onClick={() => x509IssuerUploadRef.current?.click()} className="px-4 py-3 bg-[#E4E3E0] border border-[#141414]/20 hover:bg-[#141414]/10 transition-colors">
                                <Upload size={14} />
                              </button>
                            </div>
                          )}
                          {!x509Result.details.isSelfSigned && x509Result.details.signatureVariant && (
                            <button
                              onClick={handleVerifyX509}
                              disabled={!x509IssuerPubHex}
                              className="w-full py-3 bg-[#141414] text-[#E4E3E0] font-serif italic flex justify-center disabled:opacity-30 hover:opacity-90 transition-opacity"
                            >
                              Verify Signature against Issuer Key
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </motion.div>
            ) : (
              <motion.div
                key="python"
                initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}
                className="space-y-6"
              >
                <div>
                  <h2 className="font-serif italic text-2xl">Python Reference</h2>
                  <p className="text-xs opacity-60">Equivalent implementation for backend integration.</p>
                </div>
                <div className="relative group">
                  <button
                    onClick={() => copyToClipboard(pythonCode)}
                    className="absolute right-4 top-4 p-2 bg-[#E4E3E0] border border-[#141414] opacity-0 group-hover:opacity-100 transition-opacity"
                  >
                    <Copy size={14} />
                  </button>
                  <pre className="p-6 bg-[#141414] text-[#E4E3E0] font-mono text-xs overflow-x-auto rounded-sm leading-relaxed">{pythonCode}</pre>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="p-4 border border-[#141414]/20 bg-[#141414]/5">
                    <h4 className="text-[10px] uppercase font-bold tracking-wider mb-2">Recommended Libraries</h4>
                    <ul className="text-xs space-y-2 opacity-70 list-disc pl-4">
                      <li><strong>liboqs-python</strong>: Official wrapper for liboqs.</li>
                      <li><strong>cryptography</strong>: Check latest versions for FIPS 204 support.</li>
                      <li><strong>pure-python-dilithium</strong>: For environments without C deps.</li>
                    </ul>
                  </div>
                  <div className="p-4 border border-[#141414]/20 bg-[#141414]/5">
                    <h4 className="text-[10px] uppercase font-bold tracking-wider mb-2">Security Warning</h4>
                    <p className="text-xs opacity-70 italic">
                      Always use side-channel resistant implementations for production private key handling.
                      Post-quantum algorithms are sensitive to timing attacks.
                    </p>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </main>

      {/* Footer */}
      <footer className="mt-20 border-t border-[#141414] p-8 bg-[#141414] text-[#E4E3E0]">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row justify-between items-center gap-6">
          <div className="flex items-center gap-3">
            <Shield size={20} />
            <span className="font-serif italic text-lg">ML-DSA Inspector</span>
          </div>
          <div className="flex gap-8 text-[10px] uppercase tracking-widest font-bold opacity-60">
            <a href="#" className="hover:opacity-100">FIPS 204 Standard</a>
            <a href="#" className="hover:opacity-100">NIST PQC</a>
            <a href="#" className="hover:opacity-100">Documentation</a>
            <a href="https://github.com/sahebbiswas/mldsa_playground" target="_blank" rel="noreferrer" className="hover:opacity-100 text-violet-300">GitHub (sahebbiswas/mldsa_playground)</a>
          </div>
          <p className="text-[10px] opacity-40 font-mono">&copy; 2026 SAHEB BISWAS. ALL RIGHTS RESERVED.</p>
        </div>
      </footer >
    </div >
  );
}
