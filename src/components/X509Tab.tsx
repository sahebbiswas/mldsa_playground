import React, { useRef, useState } from 'react';
import { motion } from 'motion/react';
import {
    Shield, CheckCircle2, XCircle, Info, RefreshCw, Upload,
    Fingerprint, Dna, FileJson, ArrowRight, FileCheck2, Calendar, Link, User, Lock
} from 'lucide-react';
import { cn } from '../lib/utils';
import { processCertificateBytes, verifyX509Signature, type X509ParseResult } from '../services/x509';
import { hexToUint8Array, uint8ArrayToHex } from '../services/mldsa';
import { readBinFile } from './SharedUI';

export default function X509Tab() {
    const [x509Result, setX509Result] = useState<X509ParseResult | null>(null);
    const [x509VerifyValid, setX509VerifyValid] = useState<boolean | null>(null);
    const [x509IssuerPubHex, setX509IssuerPubHex] = useState('');
    const x509UploadRef = useRef<HTMLInputElement>(null);
    const x509IssuerUploadRef = useRef<HTMLInputElement>(null);
    const [x509DragActive, setX509DragActive] = useState(false);

    const loadX509File = async (file: File) => {
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
            setX509VerifyValid(null);
        } catch (e) { }
        e.target.value = '';
    };

    return (
        <motion.div key="x509" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} className="space-y-6">
            <div>
                <h2 className="font-serif italic text-2xl flex items-center gap-2">
                    <Shield size={20} className="opacity-60" /> X.509 Certificate Decoder
                </h2>
                <p className="text-xs opacity-60 mt-1">
                    Inspect certificates encoded with ML-DSA (Dilithium) keys or signatures (e.g., OID <code>2.16.840.1.101.3.4.3.*</code>).
                    Supports PEM or raw DER files.
                </p>
            </div>

            <input ref={x509UploadRef} type="file" accept=".pem,.crt,.cer,.der" className="hidden" onChange={handleX509Upload} />
            <button
                onClick={() => x509UploadRef.current?.click()}
                onDrop={handleX509Drop} onDragOver={handleX509DragOver} onDragLeave={handleX509DragLeave}
                className={cn(
                    'w-full border-2 border-dashed p-10 flex flex-col items-center justify-center gap-3 transition-all',
                    x509DragActive ? 'border-violet-400 bg-violet-50' : 'border-[#141414]/20 hover:border-[#141414]/40 hover:bg-[#141414]/2',
                    x509Result ? 'p-6' : ''
                )}
            >
                <Upload size={x509Result ? 20 : 28} className={x509DragActive ? 'text-violet-500' : 'opacity-30'} />
                <p className="text-sm font-serif italic max-w-xs text-center leading-relaxed">
                    {x509DragActive ? <span className="text-violet-700">Drop certificate here</span> : <span className="opacity-60">Click or drag a <strong>.pem, .crt, .cer</strong>, or <strong>.der</strong> file to begin decoding.</span>}
                </p>
            </button>

            {x509Result && !x509Result.valid && (
                <div className="p-4 border border-red-400 bg-red-50 text-red-700 font-mono text-xs flex gap-3">
                    <XCircle size={16} className="shrink-0" />
                    <div className="space-y-1">
                        <p className="font-bold">Invalid or Unsupported Certificate</p>
                        <p className="opacity-80 break-all">{x509Result.error}</p>
                    </div>
                </div>
            )}

            {x509Result?.valid && x509Result.details && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    {/* Detailed Info Panel */}
                    <div className="space-y-6">
                        <div className="space-y-4">
                            <h3 className="uppercase text-[10px] font-bold tracking-widest opacity-40 border-b border-[#141414]/10 pb-2 flex items-center gap-1.5">
                                <Dna size={12} /> Certificate Identity
                            </h3>
                            <div className="space-y-3">
                                <div className="p-3 bg-white border border-[#141414]/10">
                                    <span className="block text-[9px] uppercase font-bold opacity-40 mb-1 flex items-center gap-1"><User size={10} /> Subject</span>
                                    <div className="text-[11px] font-mono leading-relaxed">
                                        {x509Result.details.subject.split(', ').map((item, i) => (
                                            <div key={i}>{item}</div>
                                        ))}
                                    </div>
                                </div>
                                <div className="p-3 bg-white border border-[#141414]/10">
                                    <span className="block text-[9px] uppercase font-bold opacity-40 mb-1 flex items-center gap-1"><Shield size={10} /> Issuer</span>
                                    <div className="text-[11px] font-mono leading-relaxed">
                                        {x509Result.details.issuer.split(', ').map((item, i) => (
                                            <div key={i}>{item}</div>
                                        ))}
                                    </div>
                                </div>
                                <div className="p-3 bg-white border border-[#141414]/10">
                                    <span className="block text-[9px] uppercase font-bold opacity-40 mb-1 flex items-center gap-1"><Calendar size={10} /> Validity</span>
                                    <div className="flex justify-between text-[11px] font-mono">
                                        <span className="opacity-60">Not Before</span>
                                        <span>{x509Result.details.notBefore.toISOString().split('T')[0]}</span>
                                    </div>
                                    <div className="flex justify-between text-[11px] font-mono mt-1">
                                        <span className="opacity-60">Not After</span>
                                        <span>{x509Result.details.notAfter.toISOString().split('T')[0]}</span>
                                    </div>
                                </div>
                                {x509Result.details.serialNumber && (
                                    <div className="flex justify-between items-center p-3 bg-white border border-[#141414]/10">
                                        <span className="text-[9px] uppercase font-bold opacity-40">Serial</span>
                                        <span className="text-[10px] font-mono break-all text-right max-w-[200px]">{x509Result.details.serialNumber}</span>
                                    </div>
                                )}
                            </div>
                        </div>

                        <div className="space-y-4">
                            <h3 className="uppercase text-[10px] font-bold tracking-widest opacity-40 border-b border-[#141414]/10 pb-2 flex items-center gap-1.5">
                                <Fingerprint size={12} /> ML-DSA Cryptography
                            </h3>

                            <div className="space-y-3">
                                <div className="p-4 border border-violet-200 bg-violet-50 text-violet-900 rounded-sm">
                                    <div className="flex items-center gap-2 mb-2">
                                        <Lock size={14} className="opacity-60" />
                                        <span className="text-[10px] uppercase font-bold tracking-widest">Public Key</span>
                                    </div>
                                    <p className="text-xl font-serif italic mb-2">
                                        {x509Result.details.publicKeyBytes ? "Public Key Extracted" : <span className="text-red-600/70">No Public Key</span>}
                                    </p>
                                    {x509Result.details.publicKeyBytes && (
                                        <p className="text-[10px] font-mono opacity-60">
                                            Length: {x509Result.details.publicKeyBytes.length} bytes
                                        </p>
                                    )}
                                </div>

                                <div className="p-4 border border-blue-200 bg-blue-50 text-blue-900 rounded-sm">
                                    <div className="flex items-center gap-2 mb-2">
                                        <FileCheck2 size={14} className="opacity-60" />
                                        <span className="text-[10px] uppercase font-bold tracking-widest">Signature Algorithm</span>
                                    </div>
                                    <p className="text-xl font-serif italic mb-2">
                                        {x509Result.details.signatureVariant || <span className="text-red-600/70">Unsupported OID</span>}
                                    </p>
                                    {x509Result.details.signatureVariant && (
                                        <p className="text-[10px] font-mono opacity-60">
                                            {x509Result.details.signatureValueBytes.length} bytes · Pre-hashed TBS: {x509Result.details.tbsBytes.length} bytes
                                        </p>
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="space-y-6">
                        <h3 className="uppercase text-[10px] font-bold tracking-widest opacity-40 flex items-center gap-1.5 pb-2 border-b border-[#141414]/10">
                            <CheckCircle2 size={12} /> Signature Verification
                        </h3>

                        {!x509Result.details.signatureVariant ? (
                            <div className="p-4 text-center border border-dashed border-[#141414]/20 text-xs font-mono opacity-50">
                                Cannot verify: Signature algorithm OID not recognized as a supported ML-DSA variant.
                            </div>
                        ) : x509Result.details.isSelfSigned ? (
                            <div className="space-y-4">
                                <div className="p-4 bg-[#141414]/5 border border-[#141414]/10 flex items-start gap-3">
                                    <Info className="shrink-0 opacity-40 mt-0.5" size={16} />
                                    <p className="text-[11px] font-mono leading-relaxed">
                                        This certificate appears to be <strong>self-signed</strong> (Subject == Issuer).
                                        The signature has been automatically verified against its own embedded ML-DSA public key.
                                    </p>
                                </div>

                                <div className={cn(
                                    "p-6 flex flex-col items-center justify-center gap-2 border transition-all",
                                    x509VerifyValid === true ? "bg-green-50 border-green-400 text-green-800" :
                                        x509VerifyValid === false ? "bg-red-50 border-red-400 text-red-800" :
                                            "bg-white"
                                )}>
                                    {x509VerifyValid === true ? <CheckCircle2 size={32} className="text-green-600" /> :
                                        x509VerifyValid === false ? <XCircle size={32} className="text-red-600" /> :
                                            <RefreshCw size={32} className="animate-spin opacity-20" />}

                                    <p className="font-serif italic text-lg">
                                        {x509VerifyValid === true ? "Self-Signature is Cryptographically Valid" :
                                            x509VerifyValid === false ? "Self-Signature is Invalid" : "Verifying..."}
                                    </p>
                                </div>
                            </div>
                        ) : (
                            <div className="space-y-4">
                                <div className="p-4 bg-orange-50 border border-orange-200 flex items-start gap-3 text-orange-900">
                                    <Link className="shrink-0 opacity-60 mt-0.5" size={16} />
                                    <div className="space-y-2">
                                        <p className="text-[11px] font-mono leading-relaxed font-bold">
                                            Issuer Public Key Required
                                        </p>
                                        <p className="text-[10px] font-mono leading-relaxed opacity-80">
                                            This is not a self-signed certificate. To verify the ML-DSA signature, you must provide the public key of the issuing CA.
                                        </p>
                                        <p className="text-[9px] font-mono bg-white/50 p-2 break-all opacity-80">
                                            <strong>Issuer:</strong> {x509Result.details.issuer}
                                        </p>
                                    </div>
                                </div>

                                <div className="space-y-3 p-5 bg-white border border-[#141414]/10">
                                    <p className="text-[10px] uppercase font-bold tracking-widest opacity-40">Load Issuer Key</p>

                                    <input ref={x509IssuerUploadRef} type="file" accept=".bin,.pub" className="hidden" onChange={handleImportX509IssuerBin} />
                                    <div className="flex gap-2">
                                        <button
                                            onClick={() => x509IssuerUploadRef.current?.click()}
                                            className="px-3 py-2 bg-[#141414]/5 hover:bg-[#141414]/10 transition-colors border border-[#141414]/10 text-[10px] uppercase font-bold tracking-wider shrink-0"
                                        >
                                            Import .bin
                                        </button>
                                        <input
                                            type="text"
                                            placeholder="...or paste pure hex bytes here"
                                            value={x509IssuerPubHex}
                                            onChange={e => {
                                                setX509IssuerPubHex(e.target.value);
                                                setX509VerifyValid(null);
                                            }}
                                            className="flex-1 bg-transparent border-b border-[#141414]/20 focus:border-[#141414] focus:outline-none text-[10px] font-mono p-2"
                                        />
                                    </div>

                                    <button
                                        onClick={handleVerifyX509}
                                        disabled={!x509IssuerPubHex || x509IssuerPubHex.length < 1000}
                                        className="w-full mt-4 py-3 bg-[#141414] text-[#E4E3E0] font-serif italic flex items-center justify-center gap-2 hover:opacity-90 disabled:opacity-30 transition-opacity"
                                    >
                                        <Shield size={16} /> Verify Signature
                                    </button>
                                </div>

                                {x509VerifyValid !== null && (
                                    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className={cn(
                                        "p-4 flex items-center justify-center gap-3 border font-serif italic",
                                        x509VerifyValid ? "bg-green-50 border-green-400 text-green-800" : "bg-red-50 border-red-400 text-red-800"
                                    )}>
                                        {x509VerifyValid ? <CheckCircle2 /> : <XCircle />}
                                        {x509VerifyValid ? "Signature mathematically verifies against the provided key." : "Signature rejected!"}
                                    </motion.div>
                                )}
                            </div>
                        )}

                        {/* ASN.1 visualization removed as it is not provided by the parser */}
                    </div>
                </div>
            )}
        </motion.div>
    );
}
