/**
 * KatTab — NIST FIPS 204 Known Answer Test runner UI
 *
 * Accepts:
 *  - NIST ACVP prompt JSON     (primary: testGroups with pk/message/signature per test)
 *  - NIST ACVP expectedResults.json  (companion: merges tcId→testPassed for diff analysis)
 *  - Legacy Dilithium .rsp     (pre-FIPS 204, SM = sig||msg)
 *  - Simple JSON array         (custom vectors)
 */

import React, { useRef, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  FlaskConical,
  Upload,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ChevronDown,
  ExternalLink,
  Info,
  FileText,
  Download,
  FileCheck2,
  HelpCircle,
  Search,
} from 'lucide-react';
import { cn } from '../lib/utils';
import type { MLDSAVariant, SignMode, HashAlg } from '../services/mldsa';
import {
  parseKatFile,
  parseExpectedResults,
  runKatVectors,
  inferVariantFromVectors,
  SIG_BYTES,
  type KatRunResult,
  type KatVectorResult,
  type ExpectedResultsMap,
} from '../services/kat';

// ─── Props ────────────────────────────────────────────────────────────────────

/** Everything the Inspector tab needs to pre-populate from a KAT vector. */
export interface SendToInspectorPayload {
  variant: MLDSAVariant;
  publicKey: string;
  signature: string;
  message: string;
  mode: SignMode;
  /** Only defined for SHA-2 HashML-DSA vectors the inspector can re-verify. */
  hashAlg?: HashAlg;
  /** Raw hex-encoded context bytes from the ACVP vector (may contain non-UTF8 bytes). */
  contextRawHex: string;
  showAdvanced: boolean;
}

interface KatTabProps {
  variant: MLDSAVariant;
  onVariantChange: (v: MLDSAVariant) => void;
  onSendToInspector: (payload: SendToInspectorPayload) => void;
}

const VARIANTS: MLDSAVariant[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

const KAT_SOURCES = [
  { label: 'FIPS 204 Standard', url: 'https://doi.org/10.6028/NIST.FIPS.204' },
  { label: 'ACVP-Server (KAT files)', url: 'https://github.com/usnistgov/ACVP-Server' },
  { label: 'ACVP ML-DSA Spec', url: 'https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html' },
  { label: 'dilithium-py KATs', url: 'https://github.com/GiacomoPope/dilithium-py' },
];

// ─── Tooltip helper ───────────────────────────────────────────────────────────

function Tip({ text }: { text: string }) {
  return (
    <span className="group relative inline-flex items-center">
      <HelpCircle size={11} className="opacity-30 group-hover:opacity-70 transition-opacity cursor-help" />
      <span className="pointer-events-none absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-56 px-3 py-2
        bg-[#141414] text-[#E4E3E0] text-[10px] font-mono leading-relaxed rounded-sm shadow-lg
        opacity-0 group-hover:opacity-100 transition-opacity z-50 whitespace-normal">
        {text}
      </span>
    </span>
  );
}

// ─── Status pills ─────────────────────────────────────────────────────────────

function VerifyPill({ ok, skipped, correctRejection }: { ok: boolean; skipped?: boolean; correctRejection?: boolean }) {
  if (skipped) return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono font-bold rounded-sm border border-[#141414]/20 text-[#141414]/40 bg-[#141414]/5">
      SKIP
    </span>
  );
  if (correctRejection) return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono font-bold rounded-sm border border-green-400 text-green-700 bg-green-50">
      <CheckCircle2 size={9} /> REJECT✓
    </span>
  );
  return (
    <span className={cn(
      'inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono font-bold rounded-sm border',
      ok ? 'border-green-400 text-green-700 bg-green-50' : 'border-red-400 text-red-700 bg-red-50',
    )}>
      {ok ? <CheckCircle2 size={9} /> : <XCircle size={9} />}
      {ok ? 'PASS' : 'FAIL'}
    </span>
  );
}

function ExpectedPill({ expected, matches }: { expected: boolean; matches: boolean }) {
  return (
    <span className={cn(
      'inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono font-bold rounded-sm border',
      matches
        ? 'border-blue-300 text-blue-700 bg-blue-50'
        : 'border-orange-400 text-orange-700 bg-orange-50',
    )}>
      {matches ? <CheckCircle2 size={9} /> : <AlertTriangle size={9} />}
      exp:{expected ? 'P' : 'F'} {matches ? '✓' : '≠'}
    </span>
  );
}

const ModePill: React.FC<{ mode: string }> = ({ mode }) => {
  const isLegacy = mode.includes('Legacy');
  const isPreHash = mode.includes('HashML-DSA');
  const isPreHashUnknown = mode.includes('PreHash');
  const isExtMu = mode.includes('External');
  const isCtx = mode.includes('Context');
  return (
    <span className={cn(
      'inline-flex items-center px-2 py-0.5 text-[9px] font-mono border whitespace-nowrap',
      isLegacy ? 'border-orange-300 text-orange-700 bg-orange-50' :
        isPreHash ? 'border-violet-400 text-violet-700 bg-violet-50' :
          isPreHashUnknown ? 'border-red-300 text-red-600 bg-red-50' :
            isExtMu ? 'border-blue-300 text-blue-700 bg-blue-50' :
              isCtx ? 'border-[#141414]/30 text-[#141414]/70' :
                'border-[#141414]/20 text-[#141414]/50',
    )}>
      {mode}
    </span>
  );
}

// ─── Constants ────────────────────────────────────────────────────────────────

/** Bytes of SM hex to preview in legacy .rsp mode (rest truncated). */
const SIG_PREVIEW_LEN = 64;

// ─── TinyBtn — matches App.tsx ActionRow style ────────────────────────────────

function TinyBtn({ onClick, children, className, title }: {
  onClick: () => void; children: React.ReactNode; className?: string; title?: string;
}) {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      className={cn('text-[10px] flex items-center gap-1 hover:underline', className)}
    >
      {children}
    </button>
  );
}

// ─── Build inspector payload from a KAT vector ────────────────────────────────

function buildInspectorPayload(v: KatVectorResult, variant: MLDSAVariant): SendToInspectorPayload {
  // For legacy .rsp: the stored signature is the raw SM (sig ‖ msg). Extract sig.
  let sigHex = v.signature;
  if (v._format === '__legacy_sm__') {
    const sigLen = SIG_BYTES[variant];
    sigHex = v.signature.slice(0, sigLen * 2); // hex chars = bytes * 2
  }

  // Map ACVP preHash+hashAlg → Inspector SignMode + HashAlg
  const isHashMode = v.preHash && !['pure', 'none', ''].includes(v.preHash.toLowerCase()) && !v.isExternalMu;
  const mode: SignMode = isHashMode ? 'hash-ml-dsa' : 'pure';

  // Map ACVP hashAlg → Inspector HashAlg. Only SHA-2 variants are supported by
  // the inspector's mldsa.ts HASH_FNS. SHA3/SHAKE vectors can't be re-verified
  // in the inspector so hashAlg is left undefined for them.
  let hashAlg: HashAlg | undefined;
  if (v.hashAlg) {
    const n = v.hashAlg.toUpperCase().replace(/[-_/\s]/g, '');
    if (n === 'SHA2256' || n === 'SHA256') hashAlg = 'SHA-256';
    else if (n === 'SHA2384' || n === 'SHA384') hashAlg = 'SHA-384';
    else if (n === 'SHA2512' || n === 'SHA512') hashAlg = 'SHA-512';
    // SHA3/SHAKE/SHA2-224/512-t: not supported by inspector — left undefined
  }

  // Pass context as raw hex — App.tsx will route it through contextRawHex in
  // SigningOptions so mldsa.ts decodes it as bytes, not as UTF-8 text.
  return {
    variant,
    publicKey: v.pk,
    signature: sigHex,
    message: v.message,
    mode,
    hashAlg,
    contextRawHex: v.context ?? '',
    showAdvanced: mode === 'hash-ml-dsa' || !!v.context,
  };
}

// ─── Vector row ───────────────────────────────────────────────────────────────

const MODE_TOOLTIPS: Record<string, string> = {
  'Pure': 'Standard ML-DSA.Verify(): signature and message are separate fields. No pre-hashing.',
  'Pure + Context': 'Pure ML-DSA with a context string cryptographically bound to the signature.',
  'External μ': 'The message representative μ is provided pre-computed. Noble verifies via internal.verify() with externalMu:true, bypassing M\' construction.',
  'Legacy .rsp': 'Pre-FIPS 204 Dilithium format. SM field = signature ‖ message concatenated. These vectors may not match the final FIPS 204 spec.',
  'Error': 'An exception was thrown during verification.',
};

function getModeTooltip(mode: string) {
  if (mode in MODE_TOOLTIPS) return MODE_TOOLTIPS[mode];
  if (mode.startsWith('HashML-DSA')) {
    const alg = mode.replace('HashML-DSA (', '').replace(')', '');
    return `HashML-DSA (Hash-then-sign): message is pre-hashed with ${alg} before verification. Uses noble's prehash() interface per FIPS 204 §5.4. Supported: SHA2-256/384/512, SHA3-224/256/384/512, SHAKE-128 (32B output), SHAKE-256 (64B output).`;
  }
  if (mode.startsWith('PreHash (')) {
    const alg = mode.replace('PreHash (', '').replace(')', '');
    return `"${alg}" is not recognised. Check the ACVP hashAlg field in your vector file.`;
  }
  return mode;
}

function HexField({ label, hex, tooltip }: { label: string; hex: string; tooltip?: string }) {
  const bytes = Math.floor(hex.length / 2);
  return (
    <div className="space-y-0.5">
      <div className="flex justify-between items-center">
        <span className="flex items-center gap-1 text-[9px] uppercase font-bold opacity-40 tracking-wider">
          {label}
          {tooltip && <Tip text={tooltip} />}
        </span>
        <span className="text-[9px] font-mono opacity-30">{bytes}B</span>
      </div>
      <div className="p-2 bg-[#141414]/5 font-mono text-[10px] break-all border border-[#141414]/10 leading-relaxed max-h-14 overflow-y-auto">
        {hex || <span className="opacity-30 italic">—</span>}
      </div>
    </div>
  );
}

const VectorRow: React.FC<{ v: KatVectorResult; variant: MLDSAVariant; onSendToInspector: (p: SendToInspectorPayload) => void }> = ({ v, variant, onSendToInspector }) => {
  const [open, setOpen] = useState(false);
  const isSkipped = v.modeLabel.startsWith('PreHash (') || v.modeLabel === 'Error';
  const hasExpected = v.expectedPassed !== undefined;
  const isCorrectRejection = !v.verifyOk && v.expectedPassed === false && v.matchesExpected === true;

  return (
    <div className={cn(
      'border-b border-[#141414]/10 last:border-0',
      !v.effectivePass && !isSkipped && 'bg-red-50/60',
      hasExpected && v.matchesExpected === false && 'border-l-2 border-l-orange-400',
    )}>
      <button
        type="button"
        onClick={() => setOpen(x => !x)}
        className="w-full flex items-center gap-2 px-4 py-2.5 text-left hover:bg-[#141414]/5 transition-colors"
      >
        <ChevronDown size={12} className={cn('shrink-0 opacity-40 transition-transform', open && 'rotate-180')} />
        <span className="font-mono text-[10px] opacity-40 w-16 shrink-0">tc#{v.tcId}</span>

        <VerifyPill ok={v.effectivePass} skipped={isSkipped} correctRejection={isCorrectRejection} />

        <span className="flex items-center gap-1">
          <ModePill mode={v.modeLabel} />
          <Tip text={getModeTooltip(v.modeLabel)} />
        </span>

        <span className="font-mono text-[9px] border border-[#141414]/20 px-1.5 py-0.5 text-[#141414]/50 shrink-0">
          {variant}
        </span>

        {hasExpected && (
          <span className="flex items-center gap-1">
            <ExpectedPill expected={v.expectedPassed!} matches={v.matchesExpected!} />
            <Tip text={
              v.matchesExpected
                ? `Result matches expectedResults.json (expected: ${v.expectedPassed ? 'pass' : 'fail'})`
                : `MISMATCH: we got ${v.verifyOk ? 'pass' : 'fail'} but expected ${v.expectedPassed ? 'pass' : 'fail'}`
            } />
          </span>
        )}

        <span className="ml-auto text-[10px] font-mono opacity-40 truncate max-w-[200px]">{v.note}</span>
        {v.error && <span className="text-[10px] text-red-600 font-mono shrink-0">{v.error}</span>}
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 pt-2 space-y-3 bg-white border-t border-[#141414]/10">
              {v.tgId !== undefined && (
                <p className="text-[9px] font-mono opacity-40">
                  Test Group: tgId={v.tgId} · tcId={v.tcId}
                  {v.hashAlg && ` · hashAlg=${v.hashAlg}`}
                  {v.signatureInterface && ` · interface=${v.signatureInterface}`}
                  {v.preHash && ` · preHash=${v.preHash}`}
                </p>
              )}
              <HexField label="Public Key" hex={v.pk}
                tooltip="The ML-DSA public key used to verify the signature. Size: 1312B (44), 1952B (65), or 2592B (87)." />
              <HexField
                label={v.isExternalMu ? 'μ (pre-computed message representative)' : 'Message'}
                hex={v.message}
                tooltip={v.isExternalMu
                  ? 'Pre-computed μ = SHAKE256(tr ‖ M′, 64). Passed directly to the internal verifier, skipping M′ construction.'
                  : v.preHash && v.preHash !== 'pure'
                    ? `Raw message before pre-hashing. The verifier will compute ${v.hashAlg ?? 'hash'}(message) internally before verifying.`
                    : 'The exact byte sequence that was signed. For pure ML-DSA this is passed directly into M′ construction.'}
              />
              <HexField label="Signature" hex={v._format === '__legacy_sm__' ? v.signature.slice(0, SIG_PREVIEW_LEN) + '…' : v.signature}
                tooltip={v._format === '__legacy_sm__'
                  ? 'Raw SM field from .rsp file. Contains signature ‖ message concatenated. The first N bytes are extracted as the signature.'
                  : `Detached ML-DSA signature. Size: 2420B (44), 3309B (65), or 4627B (87).`}
              />
              {v.context && (
                <HexField label="Context" hex={v.context}
                  tooltip="Optional context string (hex). Cryptographically bound to the signature via M′ construction: M′ = [0x00, ctx_len, ctx, msg]." />
              )}
              {hasExpected && (
                <div className={cn(
                  'p-3 border text-xs font-mono',
                  v.matchesExpected ? 'border-blue-200 bg-blue-50 text-blue-800' : 'border-orange-300 bg-orange-50 text-orange-800',
                )}>
                  <span className="font-bold">Expected (NIST): </span>
                  {v.expectedPassed ? 'testPassed = true' : 'testPassed = false'}
                  {' → '}
                  <span className={v.matchesExpected ? 'text-blue-700' : 'text-orange-700 font-bold'}>
                    {v.matchesExpected ? 'matches our result ✓' : `MISMATCH — we returned ${v.verifyOk ? 'pass' : 'fail'}`}
                  </span>
                </div>
              )}

              {/* Send to Inspector */}
              {(() => {
                const payload = buildInspectorPayload(v, variant);
                const unsupportedHash = payload.mode === 'hash-ml-dsa' && !payload.hashAlg;
                return (
                  <div className="flex items-center gap-3 pt-1 border-t border-[#141414]/10">
                    <TinyBtn
                      onClick={() => !unsupportedHash && onSendToInspector(payload)}
                      className={unsupportedHash ? 'opacity-30 cursor-not-allowed text-blue-600' : 'text-blue-600'}
                      title={unsupportedHash
                        ? `Inspector only supports SHA2-256/384/512 for HashML-DSA. This vector uses ${v.hashAlg ?? 'an unsupported hash'} which cannot be re-verified there.`
                        : undefined}
                    >
                      <Search size={10} /> Send to Inspector
                    </TinyBtn>
                    <span className="text-[9px] font-mono opacity-30">
                      {unsupportedHash
                        ? `${v.hashAlg ?? 'Hash algorithm'} not supported by Inspector`
                        : 'Loads this vector\'s pk, signature, and message into the Inspector tab'}
                    </span>
                  </div>
                );
              })()}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─── Summary bar ─────────────────────────────────────────────────────────────

function SummaryBar({ result }: { result: KatRunResult }) {
  const runnable = result.total - result.skipped;
  const pct = runnable > 0 ? Math.round((result.passed / runnable) * 100) : 0;
  const allPass = runnable > 0 && result.failed === 0;
  const hasMismatches = result.expectedMismatches > 0;

  return (
    <div className={cn(
      'p-5 border-2 space-y-3',
      hasMismatches ? 'border-orange-500 bg-orange-50' :
        allPass ? 'border-[#141414] bg-white' : 'border-red-500 bg-red-50',
    )}>
      <div className="flex items-center gap-3 flex-wrap">
        {hasMismatches
          ? <AlertTriangle className="w-8 h-8 text-orange-600 shrink-0" />
          : allPass
            ? <CheckCircle2 className="w-8 h-8 text-green-600 shrink-0" />
            : <XCircle className="w-8 h-8 text-red-600 shrink-0" />}
        <div className="space-y-1">
          <p className={cn('font-bold text-lg font-serif italic',
            hasMismatches ? 'text-orange-700' : allPass ? 'text-green-700' : 'text-red-700')}>
            {hasMismatches
              ? `${result.expectedMismatches} expected-result mismatch${result.expectedMismatches !== 1 ? 'es' : ''}`
              : allPass ? 'All vectors passed' : `${result.failed} vector${result.failed !== 1 ? 's' : ''} failed`}
          </p>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-mono opacity-60">
            <span className="flex items-center gap-1">
              {result.passed}/{runnable} passed
              <Tip text="Vectors where ML-DSA.Verify() returned true, out of the runnable (non-skipped) total." />
            </span>
            {result.skipped > 0 && (
              <span className="flex items-center gap-1">
                {result.skipped} skipped
                <Tip text="Vectors skipped because their hash algorithm is unrecognised (not a FIPS 204 hash), or an exception was thrown." />
              </span>
            )}
            {result.expectedMismatches > 0 && (
              <span className="flex items-center gap-1 text-orange-700">
                {result.expectedMismatches} expected mismatch{result.expectedMismatches !== 1 ? 'es' : ''}
                <Tip text="Vectors where our result disagrees with the NIST expectedResults.json file. These indicate a potential implementation issue." />
              </span>
            )}
            <span>{result.variant}</span>
            <span>{result.durationMs}ms</span>
          </div>
          {result.modesPresent.length > 0 && (
            <div className="flex gap-1.5 flex-wrap pt-1">
              {result.modesPresent.map(m => <ModePill key={m} mode={m} />)}
            </div>
          )}
        </div>
        <span className={cn('ml-auto text-3xl font-mono font-bold',
          hasMismatches ? 'text-orange-600' : allPass ? 'text-green-700' : 'text-red-600')}>
          {pct}%
        </span>
      </div>
      <div className="h-1.5 w-full bg-[#141414]/10 rounded-full overflow-hidden">
        <div
          className={cn('h-full transition-all duration-500',
            hasMismatches ? 'bg-orange-500' : allPass ? 'bg-green-500' : 'bg-red-500')}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function KatTab({ variant, onVariantChange, onSendToInspector }: KatTabProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const expectedInputRef = useRef<HTMLInputElement>(null);
  const [dragActive, setDragActive] = useState(false);
  const [running, setRunning] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);
  const [expectedError, setExpectedError] = useState<string | null>(null);
  const [result, setResult] = useState<KatRunResult | null>(null);
  const [activeVariant, setActiveVariant] = useState<MLDSAVariant>(variant);
  const [vectorLimit, setVectorLimit] = useState<number>(25);
  const [fileName, setFileName] = useState<string | null>(null);
  const [expectedFileName, setExpectedFileName] = useState<string | null>(null);
  const [expectedResults, setExpectedResults] = useState<ExpectedResultsMap | null>(null);
  const [filterMode, setFilterMode] = useState<'all' | 'failed' | 'mismatch'>('all');
  const [advancedOpen, setAdvancedOpen] = useState(false);
  // Keep last parsed vectors so we can re-run when expectedResults are loaded
  const [lastVectors, setLastVectors] = useState<ReturnType<typeof parseKatFile> | null>(null);
  const [lastRunVariant, setLastRunVariant] = useState<MLDSAVariant | null>(null);

  const runVectors = async (
    parsed: ReturnType<typeof parseKatFile>,
    chosenVariant: MLDSAVariant,
    expected: ExpectedResultsMap | null,
  ) => {
    setRunning(true);
    try {
      const runResult = await runKatVectors(chosenVariant, parsed.vectors, vectorLimit, expected ?? undefined);
      setResult(runResult);
    } catch (err: any) {
      setParseError(err?.message ?? 'Failed to run vectors.');
    } finally {
      setRunning(false);
    }
  };

  const handleFile = async (file: File) => {
    setParseError(null);
    setResult(null);
    setFileName(file.name);
    let text: string;
    try { text = await file.text(); }
    catch { setParseError('Failed to read file.'); return; }
    try {
      const parsed = parseKatFile(text, file.name);
      const detected = parsed.inferredVariant ?? inferVariantFromVectors(parsed.vectors);
      const chosen = detected ?? activeVariant;
      setActiveVariant(chosen);
      onVariantChange(chosen);
      setLastVectors(parsed);
      setLastRunVariant(chosen);
      await runVectors(parsed, chosen, expectedResults);
    } catch (err: any) {
      setParseError(err?.message ?? 'Failed to parse file.');
    }
  };

  const handleExpectedFile = async (file: File) => {
    setExpectedError(null);
    setExpectedFileName(file.name);
    let text: string;
    try { text = await file.text(); }
    catch { setExpectedError('Failed to read expectedResults file.'); return; }
    try {
      const map = parseExpectedResults(text);
      if (map.size === 0) throw new Error('No test results found. Check the file format.');
      setExpectedResults(map);
      // Re-run existing vectors with the new expected results
      if (lastVectors) await runVectors(lastVectors, lastRunVariant ?? activeVariant, map);
    } catch (err: any) {
      setExpectedError(err?.message ?? 'Failed to parse expectedResults file.');
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
    e.target.value = '';
  };

  const handleExpectedInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleExpectedFile(file);
    e.target.value = '';
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file);
  };

  const exportResults = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), {
      href: url,
      download: `kat-results-${result.variant.toLowerCase()}.json`,
    });
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const displayVectors = result ? result.vectors.filter(v => {
    if (filterMode === 'failed') return !v.effectivePass && !v.modeLabel.startsWith('PreHash (') && v.modeLabel !== 'Error';
    if (filterMode === 'mismatch') return v.matchesExpected === false;
    return true;
  }) : [];

  const hasExpected = expectedResults !== null;
  const hasMismatches = (result?.expectedMismatches ?? 0) > 0;

  return (
    <motion.div
      key="kat"
      initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}
      className="space-y-6"
    >
      {/* Header */}
      <div>
        <h2 className="font-serif italic text-2xl flex items-center gap-2">
          <FlaskConical size={20} className="opacity-60" /> KAT Validator
        </h2>
        <p className="text-xs opacity-60 mt-1">
          Run NIST FIPS 204 Known Answer Test vectors against the ML-DSA implementation.
          Optionally load an <code className="bg-[#141414]/10 px-1">expectedResults.json</code> file to compare against NIST's expected outcomes.
        </p>
      </div>

      {/* Source links */}
      <div className="p-4 border border-[#141414]/20 bg-[#141414]/5 space-y-2">
        <div className="flex items-center gap-2 opacity-60 mb-2">
          <Info size={13} />
          <span className="text-[10px] uppercase font-bold tracking-wider">Official KAT Sources</span>
        </div>
        <div className="flex flex-wrap gap-4">
          {KAT_SOURCES.map(s => (
            <a key={s.url} href={s.url} target="_blank" rel="noreferrer"
              className="flex items-center gap-1.5 text-xs font-mono hover:underline opacity-70 hover:opacity-100 transition-opacity">
              <ExternalLink size={11} />{s.label}
            </a>
          ))}
        </div>
        <p className="text-[10px] opacity-50 leading-relaxed pt-1">
          From <code className="bg-[#141414]/10 px-1">usnistgov/ACVP-Server</code>, navigate to
          <code className="bg-[#141414]/10 px-1 mx-1">vectors/ML-DSA/</code> and download the
          <code className="bg-[#141414]/10 px-1 mx-1">internalProjection.json</code> (prompt) and
          <code className="bg-[#141414]/10 px-1 mx-1">expectedResults.json</code> (companion) files.
        </p>
      </div>

      {/* Max Vectors (always visible) + Advanced toggle */}
      <div className="flex flex-wrap items-end gap-4">
        <div className="space-y-1">
          <label className="text-[10px] uppercase font-bold opacity-40 tracking-wider flex items-center gap-1">
            Max Vectors
            <Tip text="Caps the number of vectors run per file. ACVP files can contain hundreds; start small to check format compatibility." />
          </label>
          <select value={vectorLimit} onChange={e => setVectorLimit(Number(e.target.value))}
            className="px-3 py-1.5 border border-[#141414]/30 bg-transparent font-mono text-xs focus:outline-none focus:border-[#141414]">
            {[10, 25, 50, 100, 250, 500].map(n => <option key={n} value={n}>{n} vectors</option>)}
          </select>
        </div>
        <button
          type="button"
          onClick={() => setAdvancedOpen(o => !o)}
          className="flex items-center gap-1.5 px-3 py-1.5 border border-[#141414]/20 text-[10px] font-mono uppercase tracking-widest opacity-50 hover:opacity-100 hover:border-[#141414]/50 transition-all"
        >
          <ChevronDown size={11} className={cn('transition-transform', advancedOpen && 'rotate-180')} />
          Advanced
          {hasExpected && <span className="w-1.5 h-1.5 rounded-full bg-blue-500 ml-1" />}
        </button>
      </div>

      {/* Advanced panel */}
      <AnimatePresence>
        {advancedOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="border border-[#141414]/20 p-5 space-y-5 bg-[#141414]/3">
              <p className="text-[9px] uppercase font-bold opacity-30 tracking-widest">Advanced Options</p>

              {/* Fallback variant */}
              <div className="space-y-1">
                <label className="text-[10px] uppercase font-bold opacity-40 tracking-wider flex items-center gap-1">
                  Fallback Variant
                  <Tip text="Auto-detected from public key length (1312B→44, 1952B→65, 2592B→87). This selector is only used if detection fails." />
                </label>
                <div className="flex gap-2">
                  {VARIANTS.map(v => (
                    <button key={v} type="button" onClick={() => setActiveVariant(v)}
                      className={cn('px-3 py-1 text-[10px] font-mono border transition-colors',
                        activeVariant === v ? 'bg-[#141414] text-[#E4E3E0] border-[#141414]' : 'border-[#141414]/30 hover:border-[#141414]/60')}>
                      {v}
                    </button>
                  ))}
                </div>
              </div>

              {/* Expected results loader */}
              <div className="space-y-2">
                <div className="flex items-center gap-1.5 text-[10px] uppercase font-bold opacity-50 tracking-wider">
                  <FileCheck2 size={12} />
                  Expected Results
                  <span className="text-[9px] font-mono normal-case opacity-60">(optional)</span>
                  <Tip text="Load the companion expectedResults.json file from NIST ACVP-Server. Each test case has a testPassed field that will be compared against our result." />
                </div>
                <input ref={expectedInputRef} type="file" accept=".json" className="hidden" onChange={handleExpectedInputChange} />
                <button
                  type="button"
                  onClick={() => expectedInputRef.current?.click()}
                  className={cn(
                    'w-full border-2 border-dashed p-5 flex flex-col items-center gap-2 transition-colors cursor-pointer',
                    hasExpected
                      ? 'border-blue-400 bg-blue-50'
                      : 'border-[#141414]/20 hover:border-[#141414]/40',
                  )}
                >
                  <FileCheck2 className={cn('w-5 h-5', hasExpected ? 'text-blue-500' : 'opacity-20')} />
                  <p className="text-xs font-serif italic opacity-60 text-center">
                    {expectedFileName
                      ? <span className="text-blue-700 opacity-100">{expectedFileName}</span>
                      : 'expectedResults.json'}
                  </p>
                  {hasExpected && (
                    <span className="text-[9px] font-mono text-blue-600">
                      {[...expectedResults!.values()].reduce((s, m) => s + m.size, 0)} expected results loaded · click to replace
                    </span>
                  )}
                </button>
                {expectedError && (
                  <div className="flex items-center gap-2 p-2 border border-red-400 bg-red-50 text-red-700 text-[10px] font-mono">
                    <AlertTriangle size={12} className="shrink-0" />
                    {expectedError}
                    <button type="button" onClick={() => setExpectedError(null)} className="ml-auto opacity-60 hover:opacity-100">✕</button>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* KAT Prompt drop zone */}
      <div className="space-y-2">
        <div className="flex items-center gap-1.5 text-[10px] uppercase font-bold opacity-50 tracking-wider">
          <FileText size={12} /> KAT Prompt File
          <Tip text="The internalProjection.json (or .rsp) file containing test vectors with pk/message/signature fields." />
        </div>
        <input ref={fileInputRef} type="file" accept=".rsp,.txt,.json" className="hidden" onChange={handleInputChange} />
        <button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          onDrop={handleDrop}
          onDragOver={e => { e.preventDefault(); setDragActive(true); }}
          onDragLeave={() => setDragActive(false)}
          className={cn(
            'w-full border-2 border-dashed p-8 flex flex-col items-center gap-2 transition-colors cursor-pointer',
            dragActive ? 'border-[#141414] bg-[#141414]/5' : 'border-[#141414]/30 hover:border-[#141414]/60',
          )}
        >
          {running ? <RefreshCw className="w-6 h-6 animate-spin opacity-40" /> : <Upload className="w-6 h-6 opacity-30" />}
          <p className="text-xs font-serif italic opacity-60 text-center">
            {running ? 'Running…' : fileName ? fileName : 'internalProjection.json or .rsp'}
          </p>
          {fileName && !running && (
            <span className="text-[9px] font-mono opacity-40">Click to reload</span>
          )}
        </button>
        {parseError && (
          <div className="flex items-center gap-2 p-2 border border-red-400 bg-red-50 text-red-700 text-[10px] font-mono">
            <AlertTriangle size={12} className="shrink-0" />
            {parseError}
            <button type="button" onClick={() => setParseError(null)} className="ml-auto opacity-60 hover:opacity-100">✕</button>
          </div>
        )}
      </div>

      {/* Results */}
      <AnimatePresence>
        {result && (
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
            <SummaryBar result={result} />

            {/* Toolbar */}
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[10px] uppercase font-bold tracking-wider opacity-40 flex items-center gap-1">
                  {displayVectors.length} shown
                  <Tip text="Number of vectors currently displayed, based on the active filter." />
                </span>
                {result.failed > 0 && (
                  <button type="button"
                    onClick={() => setFilterMode(f => f === 'failed' ? 'all' : 'failed')}
                    className={cn('flex items-center gap-1.5 px-2 py-1 text-[10px] font-mono border transition-colors',
                      filterMode === 'failed' ? 'bg-red-600 text-white border-red-600' : 'border-red-400 text-red-700 hover:bg-red-50')}>
                    <XCircle size={9} />
                    {filterMode === 'failed' ? 'Clear filter' : `${result.failed} failed`}
                  </button>
                )}
                {hasMismatches && (
                  <button type="button"
                    onClick={() => setFilterMode(f => f === 'mismatch' ? 'all' : 'mismatch')}
                    className={cn('flex items-center gap-1.5 px-2 py-1 text-[10px] font-mono border transition-colors',
                      filterMode === 'mismatch' ? 'bg-orange-600 text-white border-orange-600' : 'border-orange-400 text-orange-700 hover:bg-orange-50')}>
                    <AlertTriangle size={9} />
                    {filterMode === 'mismatch' ? 'Clear filter' : `${result.expectedMismatches} mismatch${result.expectedMismatches !== 1 ? 'es' : ''}`}
                  </button>
                )}
              </div>
              <button type="button" onClick={exportResults}
                className="flex items-center gap-1.5 px-3 py-1.5 border border-[#141414]/30 text-[10px] font-mono uppercase tracking-widest hover:border-[#141414] transition-colors">
                <Download size={10} /> Export Results JSON
              </button>
            </div>

            {/* Column header */}
            <div className="border border-[#141414]/20 overflow-hidden">
              <div className="flex items-center gap-2 px-4 py-2 border-b border-[#141414]/10 bg-[#141414]/5">
                <span className="w-4 shrink-0" />
                <span className="flex items-center gap-1 text-[9px] uppercase font-bold opacity-40 w-16 shrink-0">
                  Test ID <Tip text="tcId from the ACVP test case. Matches the ID in expectedResults.json." />
                </span>
                <span className="flex items-center gap-1 text-[9px] uppercase font-bold opacity-40">
                  Verify <Tip text="ML-DSA.Verify() result for this vector. PASS = cryptographically valid, FAIL = invalid, SKIP = not run." />
                </span>
                <span className="flex items-center gap-1 text-[9px] uppercase font-bold opacity-40">
                  Mode <Tip text="Signing interface used: Pure (no prehash), HashML-DSA (SHA2 prehash), External μ (pre-computed), or Legacy .rsp." />
                </span>
                {hasExpected && (
                  <span className="flex items-center gap-1 text-[9px] uppercase font-bold opacity-40">
                    Expected <Tip text="Comparison with NIST expectedResults.json. ✓ = matches, ≠ = mismatch (possible implementation issue)." />
                  </span>
                )}
                <span className="text-[9px] uppercase font-bold opacity-40 ml-auto">Note</span>
              </div>

              {displayVectors.length === 0
                ? <div className="p-6 text-center text-xs opacity-40 font-mono">
                    {filterMode !== 'all' ? 'No vectors match this filter.' : 'No vectors to display.'}
                  </div>
                : displayVectors.map(v => <VectorRow key={`${v.tgId ?? 0}-${v.tcId}`} v={v} variant={result.variant} onSendToInspector={onSendToInspector} />)
              }
            </div>

            {/* Legend */}
            <div className="p-4 border border-[#141414]/10 bg-[#141414]/3 space-y-2">
              <p className="text-[9px] uppercase font-bold opacity-40 tracking-wider">Legend</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-1.5 text-[10px] font-mono opacity-60 leading-relaxed">
                <span><strong>Pure</strong> — ML-DSA.Verify() with no pre-hashing</span>
                <span><strong>Pure + Context</strong> — Pure with context string bound to M′</span>
                <span><strong>HashML-DSA</strong> — Message pre-hashed with SHA2-256/384/512, SHA3-224/256/384/512, or SHAKE-128/256; uses noble's prehash() interface</span>
                <span><strong>External μ</strong> — μ provided; uses internal.verify(externalMu:true)</span>
                <span><strong>Legacy .rsp</strong> — Pre-FIPS 204; SM = sig ‖ msg concatenated</span>
                <span><strong>SKIP</strong> — Completely unrecognised hash algorithm or exception</span>
                {hasExpected && <span className="text-orange-700"><strong>≠</strong> — Mismatch with NIST expectedResults.json</span>}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Format reference (shown when no results yet) */}
      {!result && !running && (
        <div className="border border-[#141414]/10 p-5 space-y-4">
          <div className="flex items-center gap-2 opacity-50">
            <FileText size={13} />
            <span className="text-[10px] uppercase font-bold tracking-wider">Accepted Formats</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <p className="text-[10px] font-mono font-bold opacity-60">NIST ACVP JSON (primary)</p>
              <p className="text-[10px] opacity-40 leading-relaxed">
                From <code>usnistgov/ACVP-Server</code>. Supports sigVer vectors
                with internal/external interface, externalMu, preHash (SHA2-256/384/512), and context.
              </p>
              <pre className="text-[10px] font-mono opacity-50 leading-relaxed bg-[#141414]/5 p-3 overflow-x-auto">{`[
  { "acvVersion": "1.0" },
  {
    "testGroups": [{
      "tgId": 1,
      "parameterSet": "ML-DSA-44",
      "signatureInterface": "internal",
      "externalMu": false,
      "preHash": "pure",
      "tests": [{
        "tcId": 1,
        "pk": "3FE652...",
        "message": "4F0D7...",
        "signature": "C29A1..."
      }]
    }]
  }
]`}</pre>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-mono font-bold opacity-60">expectedResults.json (companion)</p>
              <p className="text-[10px] opacity-40 leading-relaxed">
                Loaded separately. Maps each tcId to <code>testPassed</code>. Enables
                comparison between our verify result and NIST's expected outcome.
              </p>
              <pre className="text-[10px] font-mono opacity-50 leading-relaxed bg-[#141414]/5 p-3 overflow-x-auto">{`[
  { "acvVersion": "1.0" },
  {
    "testGroups": [{
      "tgId": 1,
      "tests": [
        { "tcId": 1, "testPassed": true },
        { "tcId": 2, "testPassed": false }
      ]
    }]
  }
]`}</pre>
            </div>
          </div>
        </div>
      )}
    </motion.div>
  );
}
