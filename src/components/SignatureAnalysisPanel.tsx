/**
 * SignatureAnalysisPanel
 *
 * Three collapsible sub-panels rendered inside the Inspector result area:
 *   1. Structural decoder  — c̃ / z / h regions with sizes and byte offsets
 *   2. Norm / bound checker — per-polynomial ∞-norm against FIPS 204 §3.3 bounds
 *   3. Malleability tester  — sample-bit-flip re-verification with heatmap
 */

import React, { useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  ChevronDown,
  ShieldCheck,
  ShieldAlert,
  Cpu,
  FlaskConical,
  Activity,
  AlertTriangle,
} from 'lucide-react';
import { cn } from '../lib/utils';
import {
  MLDSAVariant,
  SigningOptions,
  analyzeSignature,
  testMalleability,
  SignatureAnalysis,
  MalleabilityResult,
  hexToUint8Array,
} from '../services/mldsa';

// ─── Shared helpers ───────────────────────────────────────────────────────────

function SectionHeader({
  open, onToggle, icon, title, badge, badgeOk,
}: {
  open: boolean; onToggle: () => void;
  icon: React.ReactNode; title: string;
  badge?: string; badgeOk?: boolean;
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
      {badge !== undefined && (
        <span className={cn(
          'ml-auto text-[10px] font-mono font-bold px-2 py-0.5 border',
          badgeOk
            ? 'border-green-400 text-green-700 bg-green-50'
            : 'border-red-400 text-red-700 bg-red-50',
        )}>
          {badge}
        </span>
      )}
    </button>
  );
}

function ByteRegion({ label, offset, size, color }: { label: string; offset: number; size: number; color: string }) {
  return (
    <div className="flex items-center gap-3 text-[10px] font-mono">
      <div className={cn('w-3 h-3 shrink-0 border', color)} />
      <span className="opacity-50 w-20 shrink-0">+{offset}B</span>
      <span className="font-bold">{label}</span>
      <span className="ml-auto opacity-40">{size} bytes</span>
    </div>
  );
}

// ─── 1. Structural Decoder ────────────────────────────────────────────────────

function StructuralDecoder({ analysis }: { analysis: SignatureAnalysis }) {
  const { cTildeBytes, cTildeHex, zOffsetBytes, zSizeBytes, hOffsetBytes, hSizeBytes, totalBytes, expectedBytes, lengthOk } = analysis;

  // Build a proportional bar
  const cPct = (cTildeBytes / totalBytes) * 100;
  const zPct = (zSizeBytes / totalBytes) * 100;
  const hPct = (hSizeBytes / totalBytes) * 100;

  return (
    <div className="p-4 space-y-4">
      {/* Length check */}
      <div className={cn(
        'flex items-center gap-2 text-[10px] font-mono px-3 py-2 border',
        lengthOk ? 'border-green-300 bg-green-50 text-green-800' : 'border-red-300 bg-red-50 text-red-800',
      )}>
        {lengthOk
          ? <><ShieldCheck size={12} /> Signature length {totalBytes}B matches expected {expectedBytes}B</>
          : <><AlertTriangle size={12} /> Length mismatch: got {totalBytes}B, expected {expectedBytes}B</>
        }
      </div>

      {/* Proportional bar */}
      <div>
        <div className="text-[9px] uppercase font-bold opacity-40 tracking-wider mb-2">Byte Layout</div>
        <div className="flex h-7 w-full border border-[#141414]/20 overflow-hidden font-mono text-[9px]">
          <div
            style={{ width: `${cPct}%` }}
            className="bg-violet-200 border-r border-violet-400 flex items-center justify-center overflow-hidden whitespace-nowrap"
            title={`c̃: ${cTildeBytes}B`}
          >
            <span className="text-violet-800 font-bold">c̃</span>
          </div>
          <div
            style={{ width: `${zPct}%` }}
            className="bg-blue-100 border-r border-blue-300 flex items-center justify-center overflow-hidden whitespace-nowrap"
            title={`z: ${zSizeBytes}B`}
          >
            <span className="text-blue-800 font-bold">z ({analysis.zPolynomials.length} polys)</span>
          </div>
          <div
            style={{ width: `${hPct}%` }}
            className="bg-amber-100 flex items-center justify-center overflow-hidden whitespace-nowrap"
            title={`h: ${hSizeBytes}B`}
          >
            <span className="text-amber-800 font-bold">h</span>
          </div>
        </div>
      </div>

      {/* Region legend */}
      <div className="space-y-1.5">
        <ByteRegion label={`c̃  — commitment hash (λ/8)`} offset={0} size={cTildeBytes} color="bg-violet-200 border-violet-400" />
        <ByteRegion label={`z  — response vector (ℓ=${analysis.zPolynomials.length} polynomials)`} offset={zOffsetBytes} size={zSizeBytes} color="bg-blue-100 border-blue-300" />
        <ByteRegion label={`h  — hint vector (ω=${analysis.hOmega} max ones)`} offset={hOffsetBytes} size={hSizeBytes} color="bg-amber-100 border-amber-300" />
      </div>

      {/* c̃ hex */}
      <div className="space-y-1">
        <div className="text-[9px] uppercase font-bold opacity-40 tracking-wider">Commitment Hash c̃ ({cTildeBytes} bytes)</div>
        <div className="p-2 bg-violet-50 border border-violet-200 font-mono text-[10px] break-all leading-relaxed text-violet-900">
          {cTildeHex}
        </div>
      </div>

      {/* Hint summary */}
      <div className="space-y-2">
        <div className="text-[9px] uppercase font-bold opacity-40 tracking-wider">Hint Vector h — ones per polynomial</div>
        <div className="flex flex-wrap gap-2">
          {analysis.hHints.map(h => (
            <div key={h.polyIndex} className="flex flex-col items-center border border-[#141414]/20 px-2 py-1 bg-amber-50 min-w-[36px]">
              <span className="text-[9px] opacity-50 font-mono">h[{h.polyIndex}]</span>
              <span className="text-[13px] font-bold font-mono text-amber-800">{h.oneCount}</span>
            </div>
          ))}
          <div className="flex flex-col items-center border border-amber-400 px-2 py-1 bg-amber-100 min-w-[36px]">
            <span className="text-[9px] opacity-50 font-mono">total</span>
            <span className="text-[13px] font-bold font-mono text-amber-900">{analysis.hTotalOnes}</span>
          </div>
          <div className="flex flex-col items-center border border-[#141414]/20 px-2 py-1 min-w-[36px]">
            <span className="text-[9px] opacity-50 font-mono">ω max</span>
            <span className="text-[13px] font-bold font-mono opacity-50">{analysis.hOmega}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── 2. Norm / Bound Checker ──────────────────────────────────────────────────

function NormChecker({ analysis }: { analysis: SignatureAnalysis }) {
  const { zPolynomials, zBound, zNormOk, hNormOk, hTotalOnes, hOmega } = analysis;

  return (
    <div className="p-4 space-y-4">
      {/* Summary row */}
      <div className="grid grid-cols-2 gap-3">
        <div className={cn(
          'flex items-center gap-2 p-3 border text-[10px] font-mono',
          zNormOk ? 'border-green-300 bg-green-50 text-green-800' : 'border-red-300 bg-red-50 text-red-800',
        )}>
          {zNormOk ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
          <div>
            <div className="font-bold">z ∞-norm</div>
            <div className="opacity-70">bound: γ₁={analysis.zPolynomials[0]?.normBound + 1}, β={analysis.zBound}</div>
          </div>
        </div>
        <div className={cn(
          'flex items-center gap-2 p-3 border text-[10px] font-mono',
          hNormOk ? 'border-green-300 bg-green-50 text-green-800' : 'border-red-300 bg-red-50 text-red-800',
        )}>
          {hNormOk ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
          <div>
            <div className="font-bold">h weight</div>
            <div className="opacity-70">{hTotalOnes} ones ≤ ω={hOmega}</div>
          </div>
        </div>
      </div>

      {/* Per-polynomial norm bars */}
      <div className="space-y-2">
        <div className="text-[9px] uppercase font-bold opacity-40 tracking-wider">
          z polynomial ∞-norms — bound ‖z‖∞ &lt; γ₁−β = {zBound.toLocaleString()}
        </div>
        <div className="space-y-1.5">
          {zPolynomials.map(poly => {
            const pct = Math.min(100, (poly.maxAbsCoeff / (poly.normBound + 1)) * 100);
            const ok = poly.maxAbsCoeff <= zBound;
            return (
              <div key={poly.index} className="flex items-center gap-3">
                <span className="text-[9px] font-mono opacity-50 w-10 shrink-0">z[{poly.index}]</span>
                <div className="flex-1 h-4 bg-[#141414]/5 border border-[#141414]/10 relative overflow-hidden">
                  <div
                    className={cn('h-full transition-all', ok ? 'bg-blue-300' : 'bg-red-400')}
                    style={{ width: `${pct}%` }}
                  />
                  {/* γ₁−β marker */}
                  <div
                    className="absolute top-0 bottom-0 w-px bg-[#141414]/40"
                    style={{ left: `${(zBound / (poly.normBound + 1)) * 100}%` }}
                  />
                </div>
                <span className={cn('text-[9px] font-mono w-24 text-right shrink-0', ok ? 'text-green-700' : 'text-red-700')}>
                  {poly.maxAbsCoeff.toLocaleString()} {ok ? '✓' : '✗'}
                </span>
              </div>
            );
          })}
        </div>
        <p className="text-[9px] font-mono opacity-40">
          Bar shows max |coeff| relative to γ₁. Vertical line marks the γ₁−β acceptability bound. Red bar = exceeds bound.
        </p>
      </div>
    </div>
  );
}

// ─── 3. Malleability Tester ───────────────────────────────────────────────────

function MalleabilityTester({
  variant, publicKey, signatureHex, message, opts,
}: {
  variant: MLDSAVariant;
  publicKey: string;
  signatureHex: string;
  message: Uint8Array;
  opts: SigningOptions;
}) {
  const [results, setResults] = useState<MalleabilityResult[] | null>(null);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [stride, setStride] = useState(64);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async () => {
    setRunning(true);
    setProgress(0);
    setError(null);
    setResults(null);
    try {
      const r = await testMalleability(variant, publicKey, signatureHex, message, opts, stride, setProgress);
      setResults(r);
    } catch (e: any) {
      setError(e.message || 'Test failed');
    }
    setRunning(false);
  }, [variant, publicKey, signatureHex, message, opts, stride]);

  const survivedCount = results?.filter(r => r.stillValid).length ?? 0;
  const totalTested = results?.length ?? 0;
  const regionCounts = results ? {
    'c̃': results.filter(r => r.region === 'c̃'),
    'z':  results.filter(r => r.region === 'z'),
    'h':  results.filter(r => r.region === 'h'),
  } : null;

  return (
    <div className="p-4 space-y-4">
      <p className="text-[10px] font-mono opacity-60 leading-relaxed">
        Flips individual bits in the signature one at a time, re-verifying after each flip.
        Shows which regions tolerate bit-flips and which cause immediate rejection.
        Sampling every {stride}th byte keeps runtime practical.
      </p>

      {/* Controls */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-2">
          <label className="text-[9px] uppercase font-bold opacity-50 tracking-wider">Stride (bytes)</label>
          {[16, 32, 64, 128].map(s => (
            <button
              key={s}
              type="button"
              onClick={() => setStride(s)}
              className={cn(
                'text-[10px] font-mono px-2 py-0.5 border transition-colors',
                stride === s ? 'bg-[#141414] text-[#E4E3E0] border-[#141414]' : 'border-[#141414]/30 hover:border-[#141414]/60',
              )}
            >
              {s}
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={run}
          disabled={running}
          className="flex items-center gap-2 px-4 py-1.5 bg-[#141414] text-[#E4E3E0] text-[10px] font-mono hover:opacity-80 disabled:opacity-40 transition-opacity"
        >
          {running ? <><Activity size={10} className="animate-pulse" /> Running…</> : <><FlaskConical size={10} /> Run Malleability Test</>}
        </button>
      </div>

      {/* Progress bar — only shown while running */}
      {running && (
        <div className="space-y-1">
          <div className="flex justify-between text-[9px] font-mono opacity-50">
            <span>Testing bit-flips…</span>
            <span>{progress}%</span>
          </div>
          <div className="h-1.5 w-full bg-[#141414]/10 border border-[#141414]/15 overflow-hidden">
            <div
              className="h-full bg-[#141414] transition-all duration-150 ease-linear"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {error && (
        <div className="flex items-center gap-2 p-2 border border-red-300 bg-red-50 text-red-700 text-[10px] font-mono">
          <AlertTriangle size={10} /> {error}
        </div>
      )}

      {results && (
        <div className="space-y-4">
          {/* Summary */}
          <div className="grid grid-cols-3 gap-3">
            {(Object.entries(regionCounts!) as [string, MalleabilityResult[]][]).map(([region, bits]) => {
              const survived = bits.filter(b => b.stillValid).length;
              return (
                <div key={region} className="border border-[#141414]/20 p-3 space-y-1">
                  <div className="text-[9px] uppercase font-bold opacity-40 tracking-wider">{region} region</div>
                  <div className="text-[10px] font-mono">{bits.length} bits tested</div>
                  <div className={cn('text-[11px] font-bold font-mono', survived === 0 ? 'text-green-700' : 'text-red-700')}>
                    {survived} survived
                  </div>
                  {survived > 0 && (
                    <div className="text-[9px] font-mono text-red-600 opacity-70">
                      ⚠ Signature survived {survived} flip{survived !== 1 ? 's' : ''}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Heatmap — one cell per tested bit */}
          <div className="space-y-2">
            <div className="text-[9px] uppercase font-bold opacity-40 tracking-wider">
              Bit-flip Heatmap — {totalTested} bits tested ({stride}B stride)
            </div>
            <div className="flex flex-wrap gap-0.5">
              {results.map((r, i) => (
                <div
                  key={i}
                  title={`byte +${r.byteIndex} bit ${r.bitIndex} (${r.region}): ${r.stillValid ? 'SURVIVED' : 'rejected'}`}
                  className={cn(
                    'w-2.5 h-2.5 border border-transparent transition-all',
                    r.stillValid
                      ? 'bg-red-500 border-red-700'
                      : r.region === 'c̃' ? 'bg-violet-300'
                      : r.region === 'z' ? 'bg-blue-200'
                      : 'bg-amber-200',
                  )}
                />
              ))}
            </div>
            <div className="flex flex-wrap gap-3 text-[9px] font-mono opacity-60">
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 bg-violet-300 inline-block" /> c̃ (rejected)</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 bg-blue-200 inline-block" /> z (rejected)</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 bg-amber-200 inline-block" /> h (rejected)</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 bg-red-500 inline-block" /> any region (SURVIVED)</span>
            </div>
          </div>

          {survivedCount === 0 && (
            <div className="flex items-center gap-2 p-3 border border-green-300 bg-green-50 text-green-800 text-[10px] font-mono">
              <ShieldCheck size={12} />
              All {totalTested} tested bit-flips caused verification failure — no malleability detected at this sampling density.
            </div>
          )}
          {survivedCount > 0 && (
            <div className="flex items-center gap-2 p-3 border border-red-300 bg-red-50 text-red-800 text-[10px] font-mono">
              <ShieldAlert size={12} />
              {survivedCount} bit-flip{survivedCount > 1 ? 's' : ''} survived verification. This may indicate padding, non-canonical encoding, or a structural anomaly.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Top-level panel ──────────────────────────────────────────────────────────

interface Props {
  variant: MLDSAVariant;
  publicKey: string;
  signatureHex: string;
  message: Uint8Array;
  opts: SigningOptions;
}

type Section = 'structure' | 'norms' | 'malleability';

export default function SignatureAnalysisPanel({ variant, publicKey, signatureHex, message, opts }: Props) {
  const [open, setOpen] = useState<Section | null>(null);
  const toggle = (s: Section) => setOpen(x => x === s ? null : s);

  // Analyse once, share between sub-panels
  const analysis = React.useMemo<SignatureAnalysis | null>(() => {
    try { return analyzeSignature(variant, signatureHex); } catch { return null; }
  }, [variant, signatureHex]);

  if (!analysis) return null;

  const allNormsOk = analysis.zNormOk && analysis.hNormOk;

  return (
    <div className="w-full border-t border-[#141414]/10 bg-[#141414]/2">
      <div className="px-6 pt-5 pb-2 flex items-center gap-2">
        <FlaskConical size={14} className="opacity-60" />
        <span className="text-[10px] uppercase font-bold tracking-wider opacity-60">Deeper Signature Analysis</span>
      </div>

      <div className="divide-y divide-[#141414]/10">
        {/* 1 — Structure */}
        <div>
          <SectionHeader
            open={open === 'structure'} onToggle={() => toggle('structure')}
            icon={<Cpu size={13} />}
            title="Signature Component Decoder"
            badge={analysis.lengthOk ? 'OK' : 'LENGTH ERROR'}
            badgeOk={analysis.lengthOk}
          />
          <AnimatePresence>
            {open === 'structure' && (
              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                <StructuralDecoder analysis={analysis} />
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* 2 — Norms */}
        <div>
          <SectionHeader
            open={open === 'norms'} onToggle={() => toggle('norms')}
            icon={<Activity size={13} />}
            title="Norm & Bound Checker (FIPS 204 §3.3)"
            badge={allNormsOk ? 'All bounds satisfied' : 'Bound violation'}
            badgeOk={allNormsOk}
          />
          <AnimatePresence>
            {open === 'norms' && (
              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                <NormChecker analysis={analysis} />
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* 3 — Malleability */}
        <div>
          <SectionHeader
            open={open === 'malleability'} onToggle={() => toggle('malleability')}
            icon={<ShieldAlert size={13} />}
            title="Signature Malleability Tester"
          />
          <AnimatePresence>
            {open === 'malleability' && (
              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                <MalleabilityTester
                  variant={variant} publicKey={publicKey}
                  signatureHex={signatureHex} message={message} opts={opts}
                />
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
