import React, { useRef, useState, useMemo, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
    Shield, CheckCircle2, XCircle, Search, RefreshCw, ChevronDown, ChevronRight
} from 'lucide-react';
import { cn } from '../lib/utils';
import {
    inspectSignature, hexToUint8Array, uint8ArrayToHex,
    type MLDSAVariant, type SignMode, type HashAlg, type SigningOptions, type InspectionResult
} from '../services/mldsa';
import { ModeBadge, HexPreview, ActionRow, TinyBtn, AdvancedOptions, readBinFile } from './SharedUI';
import SignatureAnalysisPanel from './SignatureAnalysisPanel';
import type { SendToInspectorPayload } from './KatTab';
import type { PythonTabProps } from './PythonTab';

export interface InspectTabProps {
    variant: MLDSAVariant;
    initialPayload: SendToInspectorPayload | null;
    state: Pick<PythonTabProps,
        'publicKey' | 'signature' | 'message' | 'isMessageBinary' | 'inspectMode' | 'inspectContext' | 'inspectContextRawHex' | 'inspectHashAlg'> & {
            inspectPrimitive: boolean;
            inspectExternalMu: boolean;
        };
    setState: React.Dispatch<React.SetStateAction<InspectTabProps['state']>>;
}

export default function InspectTab({
    variant,
    initialPayload,
    state,
    setState
}: InspectTabProps) {
    const { publicKey, signature, message, isMessageBinary, inspectMode, inspectContext, inspectContextRawHex, inspectHashAlg, inspectPrimitive, inspectExternalMu } = state;
    const [result, setResult] = useState<InspectionResult | null>(null);
    const [isInspecting, setIsInspecting] = useState(false);
    const [showAdvancedVerify, setShowAdvancedVerify] = useState(false);
    const [inspectImportError, setInspectImportError] = useState<string | null>(null);

    // Sync state when 'initialPayload' changes (i.e. user clicked "Send to Inspector")
    useEffect(() => {
        if (initialPayload) {
            setState(prev => ({
                ...prev,
                publicKey: initialPayload.publicKey,
                signature: initialPayload.signature,
                message: initialPayload.message,
                isMessageBinary: initialPayload.message.length > 0 && /^[0-9A-Fa-f]+$/.test(initialPayload.message),
                inspectMode: initialPayload.mode,
                inspectContext: '',
                inspectContextRawHex: initialPayload.contextRawHex || undefined,
                inspectHashAlg: initialPayload.hashAlg || 'SHA-256',
                inspectPrimitive: !!initialPayload.primitiveVerify,
                inspectExternalMu: !!initialPayload.externalMu
            }));
            setShowAdvancedVerify(initialPayload.showAdvanced);
            setResult(null);
        }
    }, [initialPayload, setState]);

    const inspectMessageBytes = useMemo<Uint8Array>(() => {
        if (!message) return new Uint8Array();
        return isMessageBinary ? hexToUint8Array(message) : new TextEncoder().encode(message);
    }, [message, isMessageBinary]);

    const inspectOpts = useMemo<SigningOptions>(() => ({
        mode: inspectMode,
        contextText: inspectContext,
        contextRawHex: inspectContextRawHex,
        hashAlg: inspectHashAlg,
        deterministic: false,
        primitiveVerify: inspectPrimitive || undefined,
        externalMu: inspectExternalMu || undefined,
    }), [inspectMode, inspectContext, inspectContextRawHex, inspectHashAlg, inspectPrimitive, inspectExternalMu]);

    const inspectPubBinRef = useRef<HTMLInputElement>(null);
    const inspectSigBinRef = useRef<HTMLInputElement>(null);
    const inspectMessageBinRef = useRef<HTMLInputElement>(null);

    const handleInspect = async () => {
        if (!publicKey || !signature || (inspectExternalMu && !message)) return;
        setIsInspecting(true);
        const msgInput = (isMessageBinary || inspectExternalMu) ? hexToUint8Array(message) : message;
        const res = await inspectSignature(variant, publicKey, signature, msgInput, inspectOpts);
        setResult(res);
        setIsInspecting(false);
    };

    const handleImportPubKeyBin = async (e: React.ChangeEvent<HTMLInputElement>) => {
        setInspectImportError(null);
        const file = e.target.files?.[0];
        if (!file) return;
        try {
            const bytes = await readBinFile(file);
            setState(p => ({ ...p, publicKey: uint8ArrayToHex(bytes) }));
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
            setState(p => ({ ...p, signature: uint8ArrayToHex(bytes) }));
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
            setState(p => ({ ...p, message: uint8ArrayToHex(bytes), isMessageBinary: true }));
            setResult(null);
        } catch { setInspectImportError('Failed to read binary message file.'); }
        e.target.value = '';
    };

    const isValidHex = (str: string) => {
        if (!str) return true;
        const stripped = str.replace(/\s/g, '');
        return stripped.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(stripped);
    };

    return (
        <motion.div key="inspect" initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 1.02 }} transition={{ duration: 0.2 }} className="space-y-6">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                <div>
                    <h2 className="font-serif italic text-2xl flex items-center gap-2">
                        <Search size={20} className="opacity-60" /> Signature Inspector
                    </h2>
                    <p className="text-xs opacity-60 mt-1 max-w-xl">
                        Manually verify a cryptographic signature against a payload using ML-DSA.
                        All parsing and arithmetic executes locally via Noble.
                    </p>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
                <div className="space-y-6">
                    <div className="bg-[#141414]/3 border border-[#141414]/10 p-5 space-y-4 shadow-sm">
                        {inspectImportError && (
                            <div className="p-3 border border-red-400 bg-red-50 text-red-700 font-mono text-[10px] mb-4">
                                {inspectImportError}
                            </div>
                        )}
                        <div className="space-y-2 relative">
                            <div className="flex justify-between items-end">
                                <label className="text-[10px] uppercase font-bold tracking-wider opacity-40">Lattice Public Key</label>
                                <ActionRow>
                                    <TinyBtn onClick={() => inspectPubBinRef.current?.click()} title="Load from binary file">Load .bin</TinyBtn>
                                </ActionRow>
                                <input ref={inspectPubBinRef} type="file" accept=".bin,.pub" className="hidden" onChange={handleImportPubKeyBin} />
                            </div>
                            <textarea
                                value={publicKey}
                                onChange={(e) => { setState(p => ({ ...p, publicKey: e.target.value })); setResult(null); }}
                                className="w-full h-24 p-2 font-mono text-[10px] bg-white border border-[#141414]/30 focus:outline-none focus:border-[#141414] resize-none leading-relaxed transition-colors break-all"
                                placeholder="Paste hexadecimal public key..."
                            />
                        </div>

                        <div className="space-y-2">
                            <div className="flex justify-between items-end">
                                <label className="text-[10px] uppercase font-bold tracking-wider opacity-40">Signature Bytes</label>
                                <ActionRow>
                                    <TinyBtn onClick={() => inspectSigBinRef.current?.click()} title="Load from binary file">Load .bin</TinyBtn>
                                </ActionRow>
                                <input ref={inspectSigBinRef} type="file" accept=".bin,.sig" className="hidden" onChange={handleImportSigBin} />
                            </div>
                            <textarea
                                value={signature}
                                onChange={(e) => { setState(p => ({ ...p, signature: e.target.value })); setResult(null); }}
                                className="w-full h-32 p-2 font-mono text-[10px] bg-white border border-[#141414]/30 focus:outline-none focus:border-[#141414] resize-none leading-relaxed transition-colors break-all"
                                placeholder="Paste hexadecimal signature..."
                            />
                        </div>

                        <div className="space-y-2">
                            <div className="flex justify-between items-end">
                                <label className="text-[10px] uppercase font-bold tracking-wider opacity-40 flex items-center gap-1">
                                    Message Payload
                                    {inspectExternalMu && <span className="text-[9px] font-mono lowercase opacity-50 text-blue-700 bg-blue-50 border border-blue-200 px-1 ml-2">(expected 64-byte hex: μ)</span>}
                                    {inspectPrimitive && <span className="text-[9px] font-mono lowercase opacity-50 bg-[#141414]/10 border border-[#141414]/20 px-1 ml-2">(expected exact raw bytes: M')</span>}
                                </label>
                                <ActionRow>
                                    <span className="text-[9px] font-mono opacity-30 bg-[#141414]/5 px-1 py-0.5 border border-[#141414]/10">Parse input as:</span>
                                    <div className="flex border border-[#141414]/20 bg-[#141414]/5">
                                        <button
                                            onClick={() => { setState(p => ({ ...p, isMessageBinary: false })); setResult(null); }}
                                            className={cn('px-2 py-1 text-[9px] font-bold uppercase rounded-sm transition-colors', !isMessageBinary && !inspectExternalMu ? 'bg-[#141414] text-[#E4E3E0]' : 'text-[#141414]/60 hover:text-[#141414]')}
                                            disabled={inspectExternalMu}
                                        >
                                            Text
                                        </button>
                                        <button
                                            title={!isValidHex(message) ? "Message must be valid hex" : "Toggle hex payload format"}
                                            onClick={() => { setState(p => ({ ...p, isMessageBinary: true })); setResult(null); }}
                                            className={cn('px-2 py-1 text-[9px] font-bold uppercase rounded-sm transition-colors', isMessageBinary || inspectExternalMu ? 'bg-violet-600 text-white' : 'text-[#141414]/60 hover:text-[#141414]', !isValidHex(message) && !isMessageBinary ? 'opacity-30 cursor-not-allowed' : '')}
                                            disabled={inspectExternalMu || (!isValidHex(message) && !isMessageBinary)}
                                        >
                                            Hex
                                        </button>
                                    </div>
                                </ActionRow>

                                <ActionRow>
                                    <TinyBtn onClick={() => inspectMessageBinRef.current?.click()} title="Load from binary file">Load .bin</TinyBtn>
                                </ActionRow>
                                <input ref={inspectMessageBinRef} type="file" className="hidden" onChange={handleImportMessageBin} />
                            </div>

                            <textarea
                                value={message}
                                onChange={(e) => { setState(p => ({ ...p, message: e.target.value })); setResult(null); }}
                                className={cn('w-full p-2 font-mono text-[10px] bg-white border focus:outline-none resize-none leading-relaxed transition-colors',
                                    inspectExternalMu ? 'border-blue-300 focus:border-blue-600 bg-blue-50/20' : 'border-[#141414]/30 focus:border-[#141414]',
                                    inspectPrimitive ? 'bg-gray-50 border-gray-300' : ''
                                )}
                                style={{ height: inspectExternalMu ? '5rem' : '8rem' }}
                                placeholder={inspectExternalMu ? "Enter 64-byte external μ hex..." : isMessageBinary ? "Enter hexadecimal bounds (e.g. 0A1B2C...)" : "Enter plaintext message..."}
                            />
                        </div>

                        <div className="space-y-3 pt-4 border-t border-[#141414]/10">
                            <button
                                onClick={() => setShowAdvancedVerify(!showAdvancedVerify)}
                                className="flex items-center gap-1.5 text-[10px] uppercase font-bold tracking-wider opacity-40 hover:opacity-100 transition-opacity"
                            >
                                <ChevronDown size={12} className={cn('transition-transform', showAdvancedVerify && 'rotate-180')} />
                                Verify Config: {inspectMode} {inspectMode === 'hash-ml-dsa' ? `(${inspectHashAlg})` : ''} {inspectContext || inspectContextRawHex ? '+ Context' : ''} {inspectExternalMu ? '+ Ext-μ' : inspectPrimitive ? '+ Primitive-Only' : ''}
                            </button>

                            <AnimatePresence>
                                {showAdvancedVerify && (
                                    <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                                        <AdvancedOptions
                                            mode={inspectMode}
                                            onModeChange={(m) => { setState(p => ({ ...p, inspectMode: m })); setResult(null); }}
                                            context={inspectContext}
                                            onContextChange={(c) => { setState(p => ({ ...p, inspectContext: c, inspectContextRawHex: undefined })); setResult(null); }}
                                            hashAlg={inspectHashAlg}
                                            onHashAlgChange={(h) => { setState(p => ({ ...p, inspectHashAlg: h })); setResult(null); }}
                                            primitiveVerify={inspectPrimitive}
                                            onPrimitiveVerifyChange={(v) => { setState(p => ({ ...p, inspectPrimitive: v })); setResult(null); }}
                                            externalMu={inspectExternalMu}
                                            onExternalMuChange={(v) => {
                                                setState(p => ({ ...p, inspectExternalMu: v, isMessageBinary: v ? true : p.isMessageBinary }));
                                                setResult(null);
                                            }}
                                        />

                                        {inspectContextRawHex && (
                                            <div className="mt-2 p-2 border border-blue-200 bg-blue-50 text-[9px] font-mono text-blue-800 break-all relative">
                                                <span className="font-bold block mb-1">Raw Context Bytes Loaded from KAT:</span>
                                                {inspectContextRawHex}
                                                <button onClick={() => { setState(p => ({ ...p, inspectContextRawHex: undefined })); setResult(null); }} className="absolute top-2 right-2 opacity-50 hover:opacity-100">✕</button>
                                            </div>
                                        )}
                                    </motion.div>
                                )}
                            </AnimatePresence>

                            <button
                                title={inspectPrimitive ? 'Verify using MLDSA internal primitive (no domain separator)' : inspectExternalMu ? 'Verify using externally-supplied μ (externalMu mode)' : 'Run cryptographic ML-DSA algorithms to verify the signature'}
                                onClick={handleInspect}
                                disabled={isInspecting || !publicKey || !signature || (inspectExternalMu && !message)}
                                className="w-full py-4 bg-[#141414] text-[#E4E3E0] font-serif italic text-lg flex items-center justify-center gap-3 hover:opacity-90 disabled:opacity-30 transition-opacity"
                            >
                                {isInspecting ? <RefreshCw className="animate-spin" /> : <ChevronRight />}
                                {isInspecting ? 'Computing Verification...' : 'Inspect & Verify'}
                            </button>

                            <AnimatePresence>
                                {result && (
                                    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className={cn(
                                        "p-6 flex flex-col items-center justify-center gap-3 border transition-colors shadow-inner",
                                        result.valid ? "bg-green-50/50 border-green-400 text-green-900" : "bg-red-50/50 border-red-400 text-red-900"
                                    )}>
                                        {result.valid ? <CheckCircle2 size={32} className="text-green-600" /> : <XCircle size={32} className="text-red-600" />}
                                        <div className="text-center">
                                            <p className="font-serif italic text-xl">
                                                {result.valid ? "Signature is Cryptographically Valid" : "Signature Rejected"}
                                            </p>
                                            {!result.valid && (
                                                <p className="font-mono text-[10px] mt-2 opacity-80 break-all max-w-sm mx-auto">
                                                    {result.error}
                                                </p>
                                            )}
                                        </div>
                                    </motion.div>
                                )}
                            </AnimatePresence>
                        </div>
                    </div>
                </div>

                <div className="space-y-6">
                    <SignatureAnalysisPanel
                        publicKey={publicKey}
                        signatureHex={signature}
                        variant={variant}
                        opts={inspectOpts}
                        message={inspectMessageBytes}
                    />
                </div>
            </div>
        </motion.div>
    );
}
