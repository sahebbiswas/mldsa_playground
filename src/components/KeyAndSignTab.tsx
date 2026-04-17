import React, { useRef, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
    Layers, Key, RefreshCw, Upload, FileText, ChevronRight, Hash, Lock, CheckCircle2, ChevronDown
} from 'lucide-react';
import { cn } from '../lib/utils';
import {
    generateKeyPair, signMessage, analyzeSignature, hexToUint8Array, uint8ArrayToHex,
    type MLDSAVariant, type SignMode, type HashAlg, type SigningOptions
} from '../services/mldsa';
import { ModeBadge, HexPreview, ActionRow, TinyBtn, AdvancedOptions, downloadJSON, downloadBinary, readBinFile, type KeyBundle, type SignatureBundle } from './SharedUI';
import KeyAnalysisPanel from './KeyAnalysisPanel';
import type { SendToInspectorPayload } from './KatTab';
import type { PythonTabProps } from './PythonTab';

export interface KeyAndSignTabProps {
    variant: MLDSAVariant;
    onVariantChange: (v: MLDSAVariant) => void;
    onSendToInspector: (payload: SendToInspectorPayload) => void;
    state: Pick<PythonTabProps,
        'genKeys' | 'genMessage' | 'isGenMessageBinary' | 'genSignature' | 'signMode' | 'signContext' | 'signHashAlg' | 'signDeterministic'>;
    setState: React.Dispatch<React.SetStateAction<KeyAndSignTabProps['state']>>;
}

export default function KeyAndSignTab({
    variant,
    onVariantChange,
    onSendToInspector,
    state,
    setState
}: KeyAndSignTabProps) {
    const { genKeys, genMessage, isGenMessageBinary, genSignature, signMode, signContext, signHashAlg, signDeterministic } = state;

    const [showAdvancedSign, setShowAdvancedSign] = useState(false);
    const [importError, setImportError] = useState<string | null>(null);
    const [signRegenEnabled, setSignRegenEnabled] = useState(false);
    const [signRegenLimit, setSignRegenLimit] = useState<number>(100);
    const [isSigning, setIsSigning] = useState(false);
    const [signProgress, setSignProgress] = useState(0);
    const [signLastAttemptCount, setSignLastAttemptCount] = useState<number | null>(null);
    const [signRegenError, setSignRegenError] = useState<string | null>(null);

    const importInputRef = useRef<HTMLInputElement>(null);
    const importPubBinRef = useRef<HTMLInputElement>(null);
    const importPrivBinRef = useRef<HTMLInputElement>(null);
    const importSigBinRef = useRef<HTMLInputElement>(null);
    const importGenMessageBinRef = useRef<HTMLInputElement>(null);

    const isValidHex = (str: string) => {
        if (!str) return true;
        const stripped = str.replace(/\s/g, '');
        return stripped.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(stripped);
    };

    const handleGenerateKeys = () => { setState(p => ({ ...p, genKeys: generateKeyPair(variant), genSignature: '' })); };

    const handleSign = async () => {
        if (!genKeys) return;
        setIsSigning(true);
        setSignProgress(0);
        setSignLastAttemptCount(null);
        setSignRegenError(null);
        setState(p => ({ ...p, genSignature: '' }));

        try {
            const opts: SigningOptions = {
                mode: signMode,
                contextText: signContext,
                hashAlg: signHashAlg,
                deterministic: signDeterministic,
            };

            let msgInput: Uint8Array | string = genMessage;
            if (isGenMessageBinary) {
                const cleanHex = genMessage.replace(/\s/g, '');
                if (!/^[0-9a-fA-F]*$/.test(cleanHex)) {
                    setSignRegenError('Message hex contains invalid characters. Only 0-9, A-F are allowed.');
                    return;
                }
                if (cleanHex.length % 2 !== 0) {
                    setSignRegenError('Message hex must have an even number of characters.');
                    return;
                }
                msgInput = hexToUint8Array(cleanHex);
            }

            const limit = signDeterministic || !signRegenEnabled ? 1 : signRegenLimit;
            let successSig = '';
            let attempts = 0;

            for (let i = 1; i <= limit; i++) {
                attempts = i;
                const sig = signMessage(variant, genKeys.privateKey, msgInput, opts);

                if (limit === 1) {
                    successSig = sig;
                    break;
                }

                const analysis = analyzeSignature(variant, sig);
                if (analysis.zNormOk && analysis.hNormOk) {
                    successSig = sig;
                    break;
                }

                if (i % 10 === 0 || i === limit) {
                    setSignProgress(i);
                    await new Promise(r => setTimeout(r, 0));
                }
            }

            if (successSig) {
                setState(p => ({ ...p, genSignature: successSig }));
                if (limit > 1) setSignLastAttemptCount(attempts);
            } else {
                setSignRegenError(`Failed to generate a signature meeting the z/h bounds within ${limit} attempts. Try increasing the limit or generating a new key.`);
            }
        } finally {
            setIsSigning(false);
        }
    };

    const copyToClipboard = (text: string) => navigator.clipboard.writeText(text);

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
                const parsed = JSON.parse(evt.target?.result as string);
                if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
                    throw new Error('Invalid JSON format: expected an object');
                }
                if (typeof parsed.publicKey !== 'string' || typeof parsed.privateKey !== 'string') {
                    throw new Error('Missing or invalid key fields');
                }
                const allowedVariants: MLDSAVariant[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];
                if (parsed.variant && typeof parsed.variant === 'string' && allowedVariants.includes(parsed.variant as MLDSAVariant) && parsed.variant !== variant) {
                    onVariantChange(parsed.variant as MLDSAVariant);
                }
                setState(p => ({ ...p, genKeys: { publicKey: parsed.publicKey, privateKey: parsed.privateKey }, genSignature: '' }));
            } catch { setImportError('Invalid key bundle file.'); }
        };
        reader.readAsText(file);
        e.target.value = '';
    };

    const handleExportSignature = () => {
        if (!genSignature || !genKeys) return;
        downloadJSON(`mldsa-signature-${variant.toLowerCase()}.json`, {
            version: 1, variant, mode: signMode,
            hashAlg: signMode === 'hash-ml-dsa' ? signHashAlg : undefined,
            contextText: signContext, message: genMessage,
            signature: genSignature, publicKey: genKeys.publicKey,
        } as SignatureBundle);
    };

    const handleExportPublicKeyBin = () => genKeys && downloadBinary(`mldsa-pubkey-${variant.toLowerCase()}.bin`, hexToUint8Array(genKeys.publicKey));
    const handleExportPrivateKeyBin = () => genKeys && downloadBinary(`mldsa-privkey-${variant.toLowerCase()}.bin`, hexToUint8Array(genKeys.privateKey));
    const handleExportSignatureBin = () => genSignature && downloadBinary(`mldsa-sig-${variant.toLowerCase()}.bin`, hexToUint8Array(genSignature));

    const handleImportPublicKeyBin = async (e: React.ChangeEvent<HTMLInputElement>) => {
        setImportError(null);
        const file = e.target.files?.[0];
        if (!file) return;
        try {
            const bytes = await readBinFile(file);
            setState(p => ({ ...p, genKeys: p.genKeys ? { ...p.genKeys, publicKey: uint8ArrayToHex(bytes) } : { publicKey: uint8ArrayToHex(bytes), privateKey: '' }, genSignature: '' }));
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
            setState(p => ({ ...p, genKeys: p.genKeys ? { ...p.genKeys, privateKey: privHex } : { publicKey: '', privateKey: privHex }, genSignature: '' }));
        } catch { setImportError('Failed to read binary private key file.'); }
        e.target.value = '';
    };

    const handleImportSignatureBin = async (e: React.ChangeEvent<HTMLInputElement>) => {
        setImportError(null);
        const file = e.target.files?.[0];
        if (!file) return;
        try {
            const bytes = await readBinFile(file);
            setState(p => ({ ...p, genSignature: uint8ArrayToHex(bytes) }));
        } catch { setImportError('Failed to read binary signature file.'); }
        e.target.value = '';
    };

    const handleImportGenMessageBin = async (e: React.ChangeEvent<HTMLInputElement>) => {
        setImportError(null);
        const file = e.target.files?.[0];
        if (!file) return;
        try {
            const bytes = await readBinFile(file);
            setState(p => ({ ...p, genMessage: uint8ArrayToHex(bytes), isGenMessageBinary: true, genSignature: '' }));
        } catch { setImportError('Failed to read binary message file.'); }
        e.target.value = '';
    };

    const sendToInspector = () => {
        onSendToInspector({
            variant,
            publicKey: genKeys?.publicKey || '',
            signature: genSignature,
            message: genMessage,
            mode: signMode,
            contextRawHex: signContext ? uint8ArrayToHex(new TextEncoder().encode(signContext)) : '', 
            hashAlg: signHashAlg,
            showAdvanced: signMode === 'hash-ml-dsa' || !!signContext,
            primitiveVerify: false,
            externalMu: false
        });
    };

    return (
        <motion.div key="generate" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} className="space-y-6">
            {/* ─── Gen/Sign header + Variant selector ─── */}
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                <div>
                    <h2 className="font-serif italic text-2xl flex items-center gap-2">
                        <Key size={20} className="opacity-60" /> Keypair Gen & Sign
                    </h2>
                    <p className="text-xs opacity-60 mt-1 max-w-xl">
                        Generate NIST PQC cryptographic keypairs securely, and sign arbitrary data locally.
                        Uses standard WebCrypto randomness.
                    </p>
                </div>
                <div className="flex bg-[#141414]/5 p-1 rounded-sm border border-[#141414]/10 shrink-0 self-start">
                    {(['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as MLDSAVariant[]).map((v) => (
                        <button
                            key={v}
                            onClick={() => { onVariantChange(v); setState(p => ({ ...p, genKeys: null, genSignature: '' })); }}
                            className={cn(
                                'px-4 py-1.5 text-[11px] font-mono font-bold transition-all rounded-sm',
                                variant === v
                                    ? 'bg-white shadow-sm border border-[#141414]/10 text-[#141414]'
                                    : 'text-[#141414]/40 hover:text-[#141414]/80'
                            )}
                        >
                            {v.replace('ML-DSA-', '')}
                        </button>
                    ))}
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
                {/* Key Generation Module */}
                <div className="bg-[#141414]/3 border border-[#141414]/10 p-5 space-y-5 shadow-sm">
                    <div className="flex items-center justify-between border-b border-[#141414]/10 pb-3">
                        <h3 className="uppercase text-[10px] font-bold tracking-widest opacity-40 flex items-center gap-1.5 flex-1">
                            <Key size={12} /> Cryptographic Keys
                        </h3>
                        <div className="flex gap-2 relative group flex-1 justify-end">
                            <button onClick={handleGenerateKeys} className="px-3 py-1.5 text-[10px] font-mono border border-blue-400 bg-blue-50 text-blue-700 hover:bg-blue-100 transition-colors uppercase tracking-widest font-bold w-full md:w-auto">
                                {genKeys ? 'Rotate Keys' : 'Generate New Pair'}
                            </button>
                        </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-6 py-1">
                        <div className="flex gap-3">
                            <button onClick={() => importInputRef.current?.click()} className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] uppercase font-bold tracking-wider border border-[#141414]/20 hover:bg-[#141414] hover:text-[#E4E3E0] transition-colors">
                                <Upload size={12} /> Import full json
                            </button>
                            <input ref={importInputRef} type="file" accept=".json" className="hidden" onChange={handleImportKeys} />

                            <button disabled={!genKeys} onClick={handleExportKeys} className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] uppercase font-bold tracking-wider border border-[#141414]/20 hover:bg-[#141414] hover:text-[#E4E3E0] transition-colors disabled:opacity-30">
                                <FileText size={12} /> Export full json
                            </button>
                        </div>
                    </div>

                    <details className="text-[10px] font-mono opacity-60 border border-[#141414]/20 p-2">
                        <summary className="cursor-pointer hover:opacity-100 uppercase font-bold tracking-wider">Example JSON Format</summary>
                        {`{
  "version": 1,
  "variant": "ML-DSA-44",
  "publicKey": "001122...",
  "privateKey": "334455..."
}`}
                    </details>

                    {importError && (
                        <div className="p-3 border border-red-400 bg-red-50 text-red-700 font-mono text-[10px]">
                            {importError}
                        </div>
                    )}

                    {genKeys ? (
                        <div className="space-y-4">
                            <div className="space-y-2">
                                <div className="flex justify-between items-end">
                                    <span className="text-[9px] uppercase font-bold tracking-wider opacity-60 flex items-center gap-1">
                                        <CheckCircle2 size={10} className="text-green-600" /> Public Key
                                    </span>
                                    <ActionRow>
                                        <TinyBtn onClick={handleExportPublicKeyBin}>Export .bin</TinyBtn>
                                        <TinyBtn onClick={() => importPubBinRef.current?.click()}>Load .bin</TinyBtn>
                                        <TinyBtn onClick={() => copyToClipboard(genKeys.publicKey)}>Copy Hex</TinyBtn>
                                    </ActionRow>
                                    <input ref={importPubBinRef} type="file" accept=".bin,.pub" className="hidden" onChange={handleImportPublicKeyBin} />
                                </div>
                                <div className="p-3 bg-white border border-[#141414]/20 font-mono text-[10px] break-all leading-relaxed max-h-32 overflow-y-auto shadow-inner">
                                    {genKeys.publicKey}
                                </div>
                            </div>

                            <div className="space-y-2">
                                <div className="flex justify-between items-end">
                                    <span className="text-[9px] uppercase font-bold tracking-wider opacity-60 flex items-center gap-1">
                                        <CheckCircle2 size={10} className="text-green-600" /> Secret Key
                                    </span>
                                    <ActionRow>
                                        <TinyBtn onClick={handleExportPrivateKeyBin}>Export .bin</TinyBtn>
                                        <TinyBtn onClick={() => importPrivBinRef.current?.click()}>Load .bin</TinyBtn>
                                        <TinyBtn onClick={() => copyToClipboard(genKeys.privateKey)}>Copy Hex</TinyBtn>
                                    </ActionRow>
                                    <input ref={importPrivBinRef} type="file" accept=".bin,.key" className="hidden" onChange={handleImportPrivateKeyBin} />
                                </div>
                                <div className="relative group">
                                    <div className="p-3 bg-white border border-red-200 text-red-900 font-mono text-[10px] break-all leading-relaxed max-h-32 overflow-y-auto blur-sm group-hover:blur-0 transition-all duration-300">
                                        {genKeys.privateKey}
                                    </div>
                                    <div className="absolute inset-0 flex items-center justify-center pointer-events-none group-hover:opacity-0 transition-opacity">
                                        <span className="bg-red-50 border border-red-200 px-3 py-1 font-mono text-[9px] font-bold text-red-600 uppercase tracking-widest shadow-sm">
                                            Hidden / Hover to reveal
                                        </span>
                                    </div>
                                </div>
                            </div>

                            <KeyAnalysisPanel publicKeyHex={genKeys.publicKey} variant={variant} />
                        </div>
                    ) : (
                        <div className="text-center p-8 border border-dashed border-[#141414]/20 opacity-40 font-serif italic text-sm">
                            No keys loaded into workspace.
                        </div>
                    )}
                </div>

                {/* Message & Payload Module */}
                <div className="space-y-6">
                    <div className="bg-[#141414]/3 border border-[#141414]/10 p-5 space-y-5 shadow-sm">
                        <h3 className="uppercase text-[10px] font-bold tracking-widest opacity-40 border-b border-[#141414]/10 pb-2 flex items-center gap-1.5">
                            <FileText size={12} /> Message Payload
                        </h3>

                        <div className="space-y-2">
                            <div className="flex justify-between items-end">
                                <ActionRow>
                                    <span className="text-[9px] font-mono opacity-30 bg-[#141414]/5 px-1 py-0.5 border border-[#141414]/10">Parse input as:</span>
                                    <div className="flex border border-[#141414]/20 bg-[#141414]/5">
                                        <button
                                            onClick={() => { setState(p => ({ ...p, isGenMessageBinary: false, genSignature: '' })); }}
                                            className={cn('px-2 py-1 text-[9px] font-bold uppercase rounded-sm transition-colors', !isGenMessageBinary ? 'bg-[#141414] text-[#E4E3E0]' : 'text-[#141414]/60 hover:text-[#141414]')}
                                        >
                                            Text
                                        </button>
                                        <button
                                            title={!isValidHex(genMessage) ? "Message must be valid hex" : "Toggle hex payload format"}
                                            onClick={() => { setState(p => ({ ...p, isGenMessageBinary: true, genSignature: '' })); }}
                                            className={cn('px-2 py-1 text-[9px] font-bold uppercase rounded-sm transition-colors', isGenMessageBinary ? 'bg-violet-600 text-white' : 'text-[#141414]/60 hover:text-[#141414]', !isValidHex(genMessage) && !isGenMessageBinary ? 'opacity-30 cursor-not-allowed' : '')}
                                            disabled={!isValidHex(genMessage) && !isGenMessageBinary}
                                        >
                                            Hex
                                        </button>
                                    </div>
                                </ActionRow>

                                <ActionRow>
                                    <TinyBtn onClick={() => importGenMessageBinRef.current?.click()} title="Load from binary file">Load .bin</TinyBtn>
                                </ActionRow>
                                <input ref={importGenMessageBinRef} type="file" className="hidden" onChange={handleImportGenMessageBin} />
                            </div>

                            <textarea
                                value={genMessage}
                                onChange={(e) => {
                                    setState(p => ({ ...p, genMessage: e.target.value, genSignature: '' }));
                                }}
                                className="w-full h-32 p-3 font-mono text-[10px] bg-white border border-[#141414]/30 focus:outline-none focus:border-[#141414] resize-none leading-relaxed"
                                placeholder={isGenMessageBinary ? "Enter hexadecimal bounds (e.g. 0A1B2C...)" : "Enter plaintext message..."}
                            />
                        </div>

                        {/* Signature generation area */}
                        <div className="space-y-3 pt-4 border-t border-[#141414]/10">
                            <button
                                onClick={() => setShowAdvancedSign(!showAdvancedSign)}
                                className="flex items-center gap-1.5 text-[10px] uppercase font-bold tracking-wider opacity-40 hover:opacity-100 transition-opacity"
                            >
                                <ChevronDown size={12} className={cn('transition-transform', showAdvancedSign && 'rotate-180')} />
                                Sign Config: {signMode} {signMode === 'hash-ml-dsa' ? `(${signHashAlg})` : ''} {signContext ? '+ Context' : ''}
                            </button>

                            <AnimatePresence>
                                {showAdvancedSign && (
                                    <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                                        <AdvancedOptions
                                            mode={signMode}
                                            onModeChange={(m) => { setState(p => ({ ...p, signMode: m, genSignature: '' })); }}
                                            context={signContext}
                                            onContextChange={(c) => { setState(p => ({ ...p, signContext: c, genSignature: '' })); }}
                                            hashAlg={signHashAlg}
                                            onHashAlgChange={(h) => { setState(p => ({ ...p, signHashAlg: h, genSignature: '' })); }}
                                            deterministic={signDeterministic}
                                            onDeterministicChange={(v) => { setState(p => ({ ...p, signDeterministic: v, genSignature: '' })); }}
                                            regenLimit={signRegenLimit}
                                            onRegenLimitChange={(l) => { setSignRegenLimit(l); setState(p => ({ ...p, genSignature: '' })); }}
                                            regenEnabled={signRegenEnabled}
                                            onRegenEnabledChange={(v) => { setSignRegenEnabled(v); setState(p => ({ ...p, genSignature: '' })); }}
                                        />
                                    </motion.div>
                                )}
                            </AnimatePresence>

                            <button
                                title="Compute the lattice signature for this payload"
                                onClick={handleSign}
                                disabled={!genKeys || isSigning}
                                className="w-full py-3 border border-[#141414] bg-[#141414] text-[#E4E3E0] font-serif italic disabled:opacity-30 flex items-center justify-center gap-2 transition-opacity hover:opacity-90"
                            >
                                {isSigning ? <RefreshCw size={16} className="animate-spin" /> : <Layers size={16} />}
                                {isSigning ? `Generating Signature (Attempt ${signProgress}/${signDeterministic || !signRegenEnabled ? 1 : signRegenLimit})...` : signMode === 'hash-ml-dsa' ? `Sign with Hash ML-DSA (${signHashAlg})` : 'Sign Payload'}
                            </button>

                            {signLastAttemptCount !== null && !isSigning && !signRegenError && (
                                <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="flex justify-center mt-2">
                                    <span className="text-[10px] font-mono opacity-60 bg-[#141414]/5 px-2 py-1 rounded-sm">
                                        Valid strict-bounds signature generated in <strong className="text-violet-700">{signLastAttemptCount}</strong> attempts.
                                    </span>
                                </motion.div>
                            )}

                            {signRegenError && (
                                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex items-center gap-3 p-3 border border-red-400 bg-red-50 text-red-700 text-xs font-mono">
                                    {signRegenError}
                                </motion.div>
                            )}
                        </div>

                        {genSignature && (
                            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-2 !mt-6">
                                <div className="flex justify-between items-end border-b border-[#141414]/10 pb-2 mb-2">
                                    <h3 className="uppercase text-[10px] font-bold tracking-widest opacity-40 flex items-center gap-1.5 flex-1">
                                        <CheckCircle2 size={12} className="text-green-600" /> Signature Result
                                    </h3>
                                    <ActionRow>
                                        <TinyBtn onClick={sendToInspector} title="Copy config + signature over to Inspector tab" className="text-blue-600 font-bold border-r pr-3 mr-1">
                                            Send to Inspect Tab <ChevronRight size={10} />
                                        </TinyBtn>
                                        <TinyBtn onClick={handleExportSignature}>Export .json</TinyBtn>
                                        <TinyBtn onClick={handleExportSignatureBin}>Export .bin</TinyBtn>
                                        <TinyBtn onClick={() => copyToClipboard(genSignature)}>Copy Hex</TinyBtn>
                                    </ActionRow>
                                </div>

                                <div className="flex items-center gap-2 mb-1">
                                    <ModeBadge mode={signMode} />
                                    {signContext && <span className="inline-block px-1.5 py-0.5 text-[9px] font-mono bg-[#141414]/5 border border-[#141414]/10 text-[#141414]/50">ctx</span>}
                                    {signDeterministic && <span className="inline-block px-1.5 py-0.5 text-[9px] font-mono bg-blue-50 border border-blue-200 text-blue-700">deterministic</span>}
                                </div>

                                <div className="p-3 bg-green-50/30 border border-green-200 font-mono text-[10px] break-all max-h-48 overflow-y-auto leading-relaxed shadow-inner">
                                    {genSignature}
                                </div>
                            </motion.div>
                        )}
                    </div>
                </div>
            </div>
        </motion.div>
    );
}