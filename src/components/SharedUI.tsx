import React from 'react';
import { Lock, Hash } from 'lucide-react';
import { cn } from '../lib/utils';
import type { SignMode, HashAlg, MLDSAVariant } from '../services/mldsa';

// ─── Download helpers ─────────────────────────────────────────────────────────

export interface KeyBundle { version: 1; variant: MLDSAVariant; publicKey: string; privateKey: string; }
export interface SignatureBundle { version: 1; variant: MLDSAVariant; mode: SignMode; hashAlg?: HashAlg; contextText: string; message: string; signature: string; publicKey: string; }

export function downloadJSON(filename: string, data: object) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: filename });
    a.click();
    URL.revokeObjectURL(url);
}

export function downloadBinary(filename: string, bytes: Uint8Array) {
    const plain = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
    const blob = new Blob([plain], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: filename });
    a.click();
    URL.revokeObjectURL(url);
}

export function readBinFile(file: File): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(new Uint8Array(e.target?.result as ArrayBuffer));
        reader.onerror = reject;
        reader.readAsArrayBuffer(file);
    });
}

// ─── Shared UI components ─────────────────────────────────────────────────────

export function ModeBadge({ mode }: { mode: SignMode }) {
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

export function HexPreview({ label, hex, bytes, className }: { label: string; hex: string; bytes?: number; className?: string }) {
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

export const ActionRow = ({ children }: { children: React.ReactNode }) => (
    <div className="flex gap-3 flex-wrap items-center">{children}</div>
);

export const TinyBtn = ({ onClick, disabled, className, children, title }: {
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

export const AdvancedOptions = ({
    mode, onModeChange, context, onContextChange, hashAlg, onHashAlgChange, label,
    primitiveVerify, onPrimitiveVerifyChange,
    externalMu, onExternalMuChange,
    deterministic, onDeterministicChange,
    regenLimit, onRegenLimitChange,
    regenEnabled, onRegenEnabledChange,
}: {
    mode: SignMode; onModeChange: (m: SignMode) => void;
    context: string; onContextChange: (c: string) => void;
    hashAlg: HashAlg; onHashAlgChange: (h: HashAlg) => void;
    label?: string;
    primitiveVerify?: boolean;
    onPrimitiveVerifyChange?: (v: boolean) => void;
    externalMu?: boolean;
    onExternalMuChange?: (v: boolean) => void;
    deterministic?: boolean;
    onDeterministicChange?: (v: boolean) => void;
    regenLimit?: number;
    onRegenLimitChange?: (l: number) => void;
    regenEnabled?: boolean;
    onRegenEnabledChange?: (v: boolean) => void;
}) => (
    <div className="space-y-4 p-4 border border-[#141414]/20 bg-[#141414]/3 rounded-sm">
        {label && <p className="text-[10px] uppercase font-bold opacity-40 tracking-wider">{label}</p>}

        <div className="flex gap-2">
            {(['pure', 'hash-ml-dsa'] as SignMode[]).map((m) => (
                <button
                    key={m}
                    title={m === 'pure' ? 'Pure ML-DSA (M\' construction)' : 'Hash ML-DSA (pre-hashed message)'}
                    onClick={() => onModeChange(m)}
                    className={cn(
                        'flex-1 py-1.5 text-[10px] font-mono border transition-colors flex items-center justify-center gap-1.5',
                        mode === m ? 'bg-[#141414] text-[#E4E3E0] border-[#141414]' : 'border-[#141414]/30 hover:border-[#141414]/60'
                    )}
                >
                    {m === 'pure' ? <Lock size={12} /> : <Hash size={12} />}
                    {m === 'pure' ? 'Pure ML-DSA' : 'Hash ML-DSA'}
                </button>
            ))}
        </div>

        {mode === 'hash-ml-dsa' && (
            <div className="space-y-1.5">
                <label className="text-[10px] uppercase font-bold opacity-40">Pre-hash Algorithm</label>
                <div className="flex gap-2">
                    {(['SHA-256', 'SHA-384', 'SHA-512'] as HashAlg[]).map((alg) => (
                        <button
                            key={alg}
                            onClick={() => onHashAlgChange(alg)}
                            className={cn(
                                'px-2 py-1 text-[10px] font-mono border transition-colors',
                                hashAlg === alg ? 'bg-[#141414] text-[#E4E3E0] border-[#141414]' : 'border-[#141414]/30 hover:border-[#141414]/60'
                            )}
                        >
                            {alg}
                        </button>
                    ))}
                </div>
            </div>
        )}

        <div className="space-y-1.5">
            <label className="text-[10px] uppercase font-bold opacity-40">Domain Separation Context</label>
            <input
                type="text"
                value={context}
                onChange={(e) => onContextChange(e.target.value)}
                placeholder="Optional context string (max 255 chars)"
                maxLength={255}
                title={context && context.length > 255 ? 'Context must be exactly 0 or up to 255 bytes.' : 'Cryptographically bound to the signature'}
                className="w-full p-2 bg-white border border-[#141414]/30 font-mono text-[10px] focus:outline-none focus:border-[#141414]"
            />
        </div>

        {onPrimitiveVerifyChange && onExternalMuChange && (
            <div className="space-y-1.5 pt-4 border-t border-[#141414]/10 mt-4">
                <label className="flex items-center gap-2 cursor-pointer mb-2">
                    <input
                        type="checkbox"
                        checked={!!primitiveVerify}
                        onChange={(e) => {
                            onPrimitiveVerifyChange(e.target.checked);
                            if (e.target.checked && externalMu) onExternalMuChange(false);
                        }}
                        className="w-3 h-3 accent-[#141414]"
                    />
                    <span className="text-[10px] uppercase font-bold opacity-60">
                        Internal Interface <code>verify(pk, M', sig)</code>
                    </span>
                </label>
                {primitiveVerify && (
                    <p className="text-[9px] opacity-40 leading-relaxed font-mono pl-5">
                        Check this to bypass M' construction and domain separation. The supplied message will be treated directly as M'. Notice FIPS 204 § 5.4.
                    </p>
                )}

                <label className="flex items-center gap-2 cursor-pointer mt-2">
                    <input
                        type="checkbox"
                        checked={!!externalMu}
                        onChange={(e) => {
                            onExternalMuChange(e.target.checked);
                            if (e.target.checked && primitiveVerify) onPrimitiveVerifyChange(false);
                        }}
                        className="w-3 h-3 accent-[#141414]"
                    />
                    <span className="text-[10px] uppercase font-bold opacity-60">
                        External μ <code>verify(pk, μ, sig)</code>
                    </span>
                </label>
                {externalMu && (
                    <p className="text-[9px] opacity-40 leading-relaxed font-mono pl-5">
                        Treats the message field as a pre-computed 64-byte message representative μ.
                    </p>
                )}
            </div>
        )}

        {onDeterministicChange && (
            <div className="space-y-1.5 pt-4 border-t border-[#141414]/10 mt-4">
                <label className="flex items-center gap-2 cursor-pointer">
                    <input
                        type="checkbox"
                        checked={!!deterministic}
                        onChange={(e) => onDeterministicChange(e.target.checked)}
                        className="w-3 h-3 accent-[#141414]"
                    />
                    <span className="text-[10px] uppercase font-bold opacity-60">
                        Deterministic Signing
                    </span>
                </label>
                <p className="text-[9px] opacity-40 pl-5 font-mono">
                    Uses a fixed zero rnd string as per FIPS 204.
                </p>
            </div>
        )}

        {onRegenLimitChange && onRegenEnabledChange && !deterministic && (
            <div className="space-y-1.5 pt-4 border-t border-[#141414]/10 mt-4">
                <label className="flex items-center gap-2 cursor-pointer mb-2">
                    <input
                        type="checkbox"
                        checked={!!regenEnabled}
                        onChange={(e) => onRegenEnabledChange(e.target.checked)}
                        className="w-3 h-3 accent-[#141414]"
                    />
                    <span className="text-[10px] uppercase font-bold opacity-60">
                        Enable Auto-Regeneration for Strict Bounds
                    </span>
                </label>
                {regenEnabled && (
                    <div className="flex items-center gap-2 pl-5">
                        <select
                            value={regenLimit}
                            onChange={(e) => onRegenLimitChange(Number(e.target.value))}
                            className="p-1.5 bg-white border border-[#141414]/30 font-mono text-[10px] focus:outline-none focus:border-[#141414]"
                        >
                            <option value={100}>100 attempts</option>
                            <option value={200}>200 attempts</option>
                            <option value={500}>500 attempts</option>
                        </select>
                        <span className="text-[9px] opacity-40 leading-relaxed font-mono">
                            Automatically retry generation if the library produces a signature exceeding z or h bounds.
                        </span>
                    </div>
                )}
            </div>
        )}
    </div>
);
