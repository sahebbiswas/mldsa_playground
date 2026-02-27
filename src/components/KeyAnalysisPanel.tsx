/**
 * KeyAnalysisPanel
 *
 * Three sections rendered inline in the Inspector tab whenever a public key is present:
 *   1. Public key decoder — ρ (seed) + t₁ polynomial vector
 *   2. Key fingerprints   — SHAKE256 and SSH-style SHA-256
 *   3. Variant comparison — side-by-side key/sig sizes and security levels
 */

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  ChevronDown,
  Key,
  Fingerprint,
  Layers,
  Copy,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { cn } from '../lib/utils';
import {
  MLDSAVariant,
  analyzePublicKey,
  PublicKeyAnalysis,
  VARIANT_PARAMS,
} from '../services/mldsa';

// ─── Shared ───────────────────────────────────────────────────────────────────

function useCopy() {
  const [copied, setCopied] = useState<string | null>(null);
  const copy = (text: string, id: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(id);
      setTimeout(() => setCopied(null), 1500);
    });
  };
  return { copied, copy };
}

function CopyBtn({ text, id, copied, onCopy }: { text: string; id: string; copied: string | null; onCopy: (t: string, id: string) => void }) {
  const done = copied === id;
  return (
    <button
      type="button"
      onClick={() => onCopy(text, id)}
      className="opacity-50 hover:opacity-100 transition-opacity"
      title="Copy to clipboard"
    >
      {done ? <CheckCircle2 size={10} className="text-green-600" /> : <Copy size={10} />}
    </button>
  );
}

function SectionHeader({ open, onToggle, icon, title }: {
  open: boolean; onToggle: () => void; icon: React.ReactNode; title: string;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className="w-full flex items-center gap-3 p-4 text-left hover:bg-[#141414]/5 transition-colors"
    >
      <ChevronDown size={12} className={cn('opacity-40 shrink-0 transition-transform', open && 'rotate-180')} />
      <span className="opacity-60 shrink-0">{icon}</span>
      <span className="text-[11px] uppercase font-bold tracking-wider opacity-70">{title}</span>
    </button>
  );
}

// ─── 1. Public Key Decoder ────────────────────────────────────────────────────

function KeyDecoder({ analysis }: { analysis: PublicKeyAnalysis }) {
  const { copy, copied } = useCopy();
  const [showAllPolys, setShowAllPolys] = useState(false);
  const polysToShow = showAllPolys ? analysis.t1Polynomials : analysis.t1Polynomials.slice(0, 2);
  const { k } = VARIANT_PARAMS[analysis.variant];

  return (
    <div className="p-4 space-y-4">
      {/* Length check */}
      <div className={cn(
        'flex items-center gap-2 text-[10px] font-mono px-3 py-2 border',
        analysis.lengthOk ? 'border-green-300 bg-green-50 text-green-800' : 'border-red-300 bg-red-50 text-red-800',
      )}>
        {analysis.lengthOk
          ? <><CheckCircle2 size={12} /> Key length {analysis.totalBytes}B — matches {analysis.variant} ({analysis.expectedBytes}B)</>
          : <><AlertTriangle size={12} /> Length mismatch: got {analysis.totalBytes}B, expected {analysis.expectedBytes}B</>
        }
      </div>

      {/* Byte layout bar */}
      <div>
        <div className="text-[9px] uppercase font-bold opacity-40 tracking-wider mb-2">Byte Layout</div>
        <div className="flex h-6 w-full border border-[#141414]/20 overflow-hidden font-mono text-[9px]">
          <div
            style={{ width: `${(32 / analysis.totalBytes) * 100}%` }}
            className="bg-emerald-200 border-r border-emerald-400 flex items-center justify-center"
            title="ρ: 32 bytes"
          >
            <span className="text-emerald-800 font-bold">ρ</span>
          </div>
          <div
            style={{ width: `${(analysis.t1Bytes / analysis.totalBytes) * 100}%` }}
            className="bg-sky-100 flex items-center justify-center"
            title={`t₁: ${analysis.t1Bytes} bytes`}
          >
            <span className="text-sky-800 font-bold">t₁ ({k} polynomials)</span>
          </div>
        </div>
      </div>

      {/* ρ */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <span className="text-[9px] uppercase font-bold opacity-40 tracking-wider">ρ — matrix seed (32 bytes)</span>
          <CopyBtn text={analysis.rhoHex} id="rho" copied={copied} onCopy={copy} />
        </div>
        <div className="p-2 bg-emerald-50 border border-emerald-200 font-mono text-[10px] break-all leading-relaxed text-emerald-900">
          {analysis.rhoHex}
        </div>
        <p className="text-[9px] font-mono opacity-40">
          Used to deterministically expand the matrix A = ExpandA(ρ) via SHAKE128. Public, not secret.
        </p>
      </div>

      {/* t₁ polynomials */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-[9px] uppercase font-bold opacity-40 tracking-wider">
            t₁ — compressed polynomial vector ({k} polys × 256 coeffs × 10 bits = {analysis.t1Bytes}B)
          </span>
        </div>
        <div className="space-y-2">
          {polysToShow.map(poly => (
            <div key={poly.index} className="border border-[#141414]/10 bg-sky-50/50">
              <div className="flex items-center gap-3 px-3 py-1.5 border-b border-[#141414]/10">
                <span className="text-[9px] font-mono font-bold text-sky-700">t₁[{poly.index}]</span>
                <span className="text-[9px] font-mono opacity-40">
                  min={poly.minCoeff} max={poly.maxCoeff} range=[0, 2¹⁰−1=1023]
                </span>
              </div>
              {/* Mini sparkline — 64-sample bar chart */}
              <div className="flex items-end h-8 px-2 py-1 gap-px">
                {poly.coefficients.filter((_, i) => i % 4 === 0).map((c, i) => (
                  <div
                    key={i}
                    className="flex-1 bg-sky-400/60 min-h-px"
                    style={{ height: `${(c / 1023) * 100}%` }}
                    title={`coeff[${i * 4}]=${c}`}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
        {analysis.t1Polynomials.length > 2 && (
          <button
            type="button"
            onClick={() => setShowAllPolys(x => !x)}
            className="text-[10px] font-mono opacity-50 hover:opacity-100 underline"
          >
            {showAllPolys ? 'Show fewer' : `Show all ${analysis.t1Polynomials.length} polynomials`}
          </button>
        )}
      </div>
    </div>
  );
}

// ─── 2. Key Fingerprints ──────────────────────────────────────────────────────

function KeyFingerprints({ analysis }: { analysis: PublicKeyAnalysis }) {
  const { copy, copied } = useCopy();

  const rows = [
    {
      id: 'ssh',
      label: 'SSH-style (SHA-256)',
      sublabel: 'SHA256(pk) encoded as base64 — same format as ssh-keygen -l',
      value: analysis.ssh_style,
      color: 'bg-indigo-50 border-indigo-200 text-indigo-900',
    },
    {
      id: 'sha256',
      label: 'SHA-256 (hex)',
      sublabel: '32-byte SHA-256 digest of the raw public key bytes',
      value: analysis.sha256Fingerprint,
      color: 'bg-neutral-50 border-[#141414]/15 text-[#141414]',
    },
    {
      id: 'shake256',
      label: 'SHAKE256 (hex, 32B)',
      sublabel: '32-byte SHAKE256 digest — same hash used internally by ML-DSA (tr = SHAKE256(pk, 64B))',
      value: analysis.shake256Fingerprint,
      color: 'bg-violet-50 border-violet-200 text-violet-900',
    },
  ];

  return (
    <div className="p-4 space-y-3">
      <p className="text-[10px] font-mono opacity-50 leading-relaxed">
        Short digests of the public key for identity verification. Share these instead of the full {analysis.totalBytes}B key for quick confirmation.
      </p>
      {rows.map(row => (
        <div key={row.id} className="space-y-1.5">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-[9px] uppercase font-bold opacity-40 tracking-wider">{row.label}</span>
              <p className="text-[9px] font-mono opacity-40">{row.sublabel}</p>
            </div>
            <CopyBtn text={row.value} id={row.id} copied={copied} onCopy={copy} />
          </div>
          <div className={cn('p-2 border font-mono text-[10px] break-all leading-relaxed', row.color)}>
            {row.value}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── 3. Variant Comparison ────────────────────────────────────────────────────

const SECURITY_NOTES: Record<MLDSAVariant, { nist: string; classical: string; quantum: string; use: string }> = {
  'ML-DSA-44': { nist: 'Level 2', classical: '≥ 112-bit', quantum: '≥ 96-bit', use: 'General purpose, smallest keys' },
  'ML-DSA-65': { nist: 'Level 3', classical: '≥ 128-bit', quantum: '≥ 112-bit', use: 'Recommended for most applications' },
  'ML-DSA-87': { nist: 'Level 5', classical: '≥ 192-bit', quantum: '≥ 128-bit', use: 'Highest security, long-lived keys' },
};

function VariantComparison({ activeVariant }: { activeVariant: MLDSAVariant }) {
  const variants: MLDSAVariant[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];
  const maxSig = Math.max(...variants.map(v => VARIANT_PARAMS[v].sigBytes));
  const maxPk  = Math.max(...variants.map(v => VARIANT_PARAMS[v].pkBytes));
  const maxSk  = Math.max(...variants.map(v => VARIANT_PARAMS[v].skBytes));

  return (
    <div className="p-4 space-y-4">
      <div className="overflow-x-auto">
        <table className="w-full text-[10px] font-mono border-collapse">
          <thead>
            <tr className="border-b border-[#141414]/20">
              <th className="text-left py-2 pr-4 text-[9px] uppercase tracking-wider opacity-40 font-bold">Variant</th>
              <th className="text-right py-2 px-2 text-[9px] uppercase tracking-wider opacity-40 font-bold">Public Key</th>
              <th className="text-right py-2 px-2 text-[9px] uppercase tracking-wider opacity-40 font-bold">Private Key</th>
              <th className="text-right py-2 px-2 text-[9px] uppercase tracking-wider opacity-40 font-bold">Signature</th>
              <th className="text-left py-2 pl-4 text-[9px] uppercase tracking-wider opacity-40 font-bold">NIST Level</th>
              <th className="text-left py-2 pl-2 text-[9px] uppercase tracking-wider opacity-40 font-bold">Classical</th>
              <th className="text-left py-2 pl-2 text-[9px] uppercase tracking-wider opacity-40 font-bold">Quantum</th>
            </tr>
          </thead>
          <tbody>
            {variants.map(v => {
              const p = VARIANT_PARAMS[v];
              const s = SECURITY_NOTES[v];
              const isActive = v === activeVariant;
              return (
                <tr key={v} className={cn('border-b border-[#141414]/10', isActive && 'bg-[#141414]/5')}>
                  <td className="py-2 pr-4">
                    <span className={cn('font-bold', isActive ? 'text-[#141414]' : 'opacity-60')}>{v}</span>
                    {isActive && <span className="ml-2 text-[8px] border border-[#141414] px-1 py-0.5">current</span>}
                  </td>
                  <td className="py-2 px-2 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <div className="h-1.5 bg-emerald-300" style={{ width: `${(p.pkBytes / maxPk) * 48}px` }} />
                      <span>{p.pkBytes}B</span>
                    </div>
                  </td>
                  <td className="py-2 px-2 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <div className="h-1.5 bg-rose-300" style={{ width: `${(p.skBytes / maxSk) * 48}px` }} />
                      <span>{p.skBytes}B</span>
                    </div>
                  </td>
                  <td className="py-2 px-2 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <div className="h-1.5 bg-sky-300" style={{ width: `${(p.sigBytes / maxSig) * 48}px` }} />
                      <span>{p.sigBytes}B</span>
                    </div>
                  </td>
                  <td className="py-2 pl-4 opacity-70">{s.nist}</td>
                  <td className="py-2 pl-2 opacity-70">{s.classical}</td>
                  <td className="py-2 pl-2 opacity-70">{s.quantum}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Bar chart of key sizes */}
      <div className="space-y-3">
        <div className="text-[9px] uppercase font-bold opacity-40 tracking-wider">Size comparison</div>
        {(['pkBytes', 'skBytes', 'sigBytes'] as const).map(field => {
          const labels: Record<string, string> = { pkBytes: 'Public Key', skBytes: 'Private Key', sigBytes: 'Signature' };
          const colors: Record<string, string> = { pkBytes: 'bg-emerald-400', skBytes: 'bg-rose-400', sigBytes: 'bg-sky-400' };
          const maxVal = Math.max(...variants.map(v => VARIANT_PARAMS[v][field]));
          return (
            <div key={field} className="space-y-1">
              <div className="text-[9px] font-mono opacity-50">{labels[field]}</div>
              <div className="space-y-1">
                {variants.map(v => (
                  <div key={v} className="flex items-center gap-3">
                    <span className={cn('text-[9px] font-mono w-20 shrink-0', v === activeVariant ? 'font-bold' : 'opacity-50')}>{v}</span>
                    <div className="flex-1 h-3 bg-[#141414]/5 border border-[#141414]/10">
                      <div
                        className={cn('h-full', colors[field], v === activeVariant ? 'opacity-100' : 'opacity-40')}
                        style={{ width: `${(VARIANT_PARAMS[v][field] / maxVal) * 100}%` }}
                      />
                    </div>
                    <span className="text-[9px] font-mono opacity-60 w-14 text-right shrink-0">{VARIANT_PARAMS[v][field].toLocaleString()}B</span>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      {/* Use-case notes */}
      <div className="grid grid-cols-3 gap-2">
        {variants.map(v => (
          <div key={v} className={cn('border p-2 space-y-1', v === activeVariant ? 'border-[#141414]' : 'border-[#141414]/20')}>
            <div className="text-[9px] font-bold font-mono">{v}</div>
            <div className="text-[9px] font-mono opacity-60 leading-snug">{SECURITY_NOTES[v].use}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Top-level panel ──────────────────────────────────────────────────────────

interface Props {
  variant: MLDSAVariant;
  publicKeyHex: string;
}

type Section = 'decoder' | 'fingerprint' | 'comparison';

export default function KeyAnalysisPanel({ variant, publicKeyHex }: Props) {
  const [open, setOpen] = useState<Section | null>(null);
  const toggle = (s: Section) => setOpen(x => x === s ? null : s);

  const analysis = React.useMemo<PublicKeyAnalysis | null>(() => {
    try { return analyzePublicKey(variant, publicKeyHex); } catch { return null; }
  }, [variant, publicKeyHex]);

  if (!analysis) return null;

  return (
    <div className="border border-[#141414]/15 bg-white">
      <div className="px-4 pt-4 pb-2 flex items-center gap-2 border-b border-[#141414]/10">
        <Key size={14} className="opacity-60" />
        <span className="text-[10px] uppercase font-bold tracking-wider opacity-60">Key Analysis</span>
      </div>

      <div className="divide-y divide-[#141414]/10">
        {/* 1 — Decoder */}
        <div>
          <SectionHeader open={open === 'decoder'} onToggle={() => toggle('decoder')} icon={<Key size={13} />} title="Public Key Structure (ρ + t₁)" />
          <AnimatePresence>
            {open === 'decoder' && (
              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                <KeyDecoder analysis={analysis} />
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* 2 — Fingerprints */}
        <div>
          <SectionHeader open={open === 'fingerprint'} onToggle={() => toggle('fingerprint')} icon={<Fingerprint size={13} />} title="Key Fingerprints" />
          <AnimatePresence>
            {open === 'fingerprint' && (
              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                <KeyFingerprints analysis={analysis} />
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* 3 — Comparison */}
        <div>
          <SectionHeader open={open === 'comparison'} onToggle={() => toggle('comparison')} icon={<Layers size={13} />} title="Variant Size & Security Comparison" />
          <AnimatePresence>
            {open === 'comparison' && (
              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                <VariantComparison activeVariant={variant} />
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
