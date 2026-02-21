/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
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
  Cpu
} from 'lucide-react';
import { 
  inspectSignature, 
  generateKeyPair, 
  signMessage, 
  MLDSAVariant,
  InspectionResult
} from './services/mldsa';
import { cn } from './lib/utils';

const VARIANTS: MLDSAVariant[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

export default function App() {
  const [variant, setVariant] = useState<MLDSAVariant>('ML-DSA-65');
  const [publicKey, setPublicKey] = useState('');
  const [signature, setSignature] = useState('');
  const [message, setMessage] = useState('');
  const [result, setResult] = useState<InspectionResult | null>(null);
  const [isInspecting, setIsInspecting] = useState(false);
  const [activeTab, setActiveTab] = useState<'inspect' | 'generate' | 'python'>('inspect');

  // For generation tab
  const [genKeys, setGenKeys] = useState<{ publicKey: string; privateKey: string } | null>(null);
  const [genMessage, setGenMessage] = useState('Hello, ML-DSA!');
  const [genSignature, setGenSignature] = useState('');

  const handleInspect = async () => {
    if (!publicKey || !signature || !message) return;
    setIsInspecting(true);
    const res = await inspectSignature(variant, publicKey, signature, message);
    setResult(res);
    setIsInspecting(false);
  };

  const handleGenerateKeys = () => {
    const keys = generateKeyPair(variant);
    setGenKeys(keys);
    setGenSignature('');
  };

  const handleSign = () => {
    if (!genKeys) return;
    const sig = signMessage(variant, genKeys.privateKey, genMessage);
    setGenSignature(sig);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

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

  return (
    <div className="min-h-screen bg-[#E4E3E0] text-[#141414] font-sans selection:bg-[#141414] selection:text-[#E4E3E0]">
      {/* Header */}
      <header className="border-b border-[#141414] p-6 flex justify-between items-center">
        <div className="flex items-center gap-3">
          <div className="bg-[#141414] p-2 rounded-sm">
            <Shield className="text-[#E4E3E0] w-6 h-6" />
          </div>
          <div>
            <h1 className="font-serif italic text-2xl leading-none">ML-DSA Inspector</h1>
            <p className="text-[10px] uppercase tracking-widest opacity-50 mt-1 font-mono">FIPS 204 Post-Quantum Utility</p>
          </div>
        </div>
        <div className="flex gap-4">
          {VARIANTS.map((v) => (
            <button
              key={v}
              onClick={() => setVariant(v)}
              className={cn(
                "px-3 py-1 text-[11px] font-mono border border-[#141414] transition-colors",
                variant === v ? "bg-[#141414] text-[#E4E3E0]" : "hover:bg-[#141414]/5"
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
          <button
            onClick={() => setActiveTab('inspect')}
            className={cn(
              "w-full flex items-center gap-3 p-4 border border-[#141414] text-left transition-all",
              activeTab === 'inspect' ? "bg-[#141414] text-[#E4E3E0]" : "hover:bg-[#141414]/5"
            )}
          >
            <Search size={18} />
            <span className="font-serif italic">Inspect Signature</span>
          </button>
          <button
            onClick={() => setActiveTab('generate')}
            className={cn(
              "w-full flex items-center gap-3 p-4 border border-[#141414] text-left transition-all",
              activeTab === 'generate' ? "bg-[#141414] text-[#E4E3E0]" : "hover:bg-[#141414]/5"
            )}
          >
            <Key size={18} />
            <span className="font-serif italic">Key & Sign Tools</span>
          </button>
          <button
            onClick={() => setActiveTab('python')}
            className={cn(
              "w-full flex items-center gap-3 p-4 border border-[#141414] text-left transition-all",
              activeTab === 'python' ? "bg-[#141414] text-[#E4E3E0]" : "hover:bg-[#141414]/5"
            )}
          >
            <Terminal size={18} />
            <span className="font-serif italic">Python Reference</span>
          </button>

          <div className="mt-8 p-4 border border-[#141414]/20 bg-[#141414]/5 rounded-sm">
            <div className="flex items-center gap-2 mb-2 opacity-60">
              <Info size={14} />
              <span className="text-[10px] uppercase font-bold tracking-wider">Technical Note</span>
            </div>
            <p className="text-xs leading-relaxed opacity-70">
              ML-DSA is a module-lattice-based digital signature algorithm. 
              It is part of the NIST post-quantum cryptography standards (FIPS 204).
            </p>
          </div>
        </div>

        {/* Main Content Area */}
        <div className="lg:col-span-9">
          <AnimatePresence mode="wait">
            {activeTab === 'inspect' ? (
              <motion.div
                key="inspect"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-6"
              >
                <div className="grid grid-cols-1 gap-6">
                  {/* Public Key Input */}
                  <div className="space-y-2">
                    <label className="flex items-center gap-2 text-[11px] uppercase font-bold tracking-wider opacity-60">
                      <Key size={14} /> Public Key (Hex)
                    </label>
                    <textarea
                      value={publicKey}
                      onChange={(e) => setPublicKey(e.target.value)}
                      placeholder="Enter hex-encoded public key..."
                      className="w-full h-24 p-4 bg-transparent border border-[#141414] font-mono text-xs focus:outline-none focus:ring-1 focus:ring-[#141414] resize-none"
                    />
                  </div>

                  {/* Signature Input */}
                  <div className="space-y-2">
                    <label className="flex items-center gap-2 text-[11px] uppercase font-bold tracking-wider opacity-60">
                      <Terminal size={14} /> Signature (Hex)
                    </label>
                    <textarea
                      value={signature}
                      onChange={(e) => setSignature(e.target.value)}
                      placeholder="Enter hex-encoded signature..."
                      className="w-full h-32 p-4 bg-transparent border border-[#141414] font-mono text-xs focus:outline-none focus:ring-1 focus:ring-[#141414] resize-none"
                    />
                  </div>

                  {/* Message Input */}
                  <div className="space-y-2">
                    <label className="flex items-center gap-2 text-[11px] uppercase font-bold tracking-wider opacity-60">
                      <FileText size={14} /> Payload / Message
                    </label>
                    <input
                      type="text"
                      value={message}
                      onChange={(e) => setMessage(e.target.value)}
                      placeholder="Enter the message that was signed..."
                      className="w-full p-4 bg-transparent border border-[#141414] font-mono text-xs focus:outline-none focus:ring-1 focus:ring-[#141414]"
                    />
                  </div>

                  <button
                    onClick={handleInspect}
                    disabled={isInspecting || !publicKey || !signature || !message}
                    className="w-full py-4 bg-[#141414] text-[#E4E3E0] font-serif italic text-lg flex items-center justify-center gap-3 hover:opacity-90 disabled:opacity-30 transition-opacity"
                  >
                    {isInspecting ? <RefreshCw className="animate-spin" /> : <ChevronRight />}
                    {isInspecting ? 'Analyzing...' : 'Inspect & Verify'}
                  </button>
                </div>

                {/* Results Section */}
                {result && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.98 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className={cn(
                      "p-6 border-2 flex flex-col gap-6 items-start",
                      result.valid ? "border-[#141414] bg-white" : "border-red-500 bg-red-50"
                    )}
                  >
                    <div className="flex gap-6 items-start w-full">
                      <div className="shrink-0">
                        {result.valid ? (
                          <CheckCircle2 className="w-12 h-12 text-green-600" />
                        ) : (
                          <XCircle className="w-12 h-12 text-red-600" />
                        )}
                      </div>
                      <div className="flex-1 space-y-4">
                        <div>
                          <h3 className="font-serif italic text-xl">
                            {result.valid ? 'Verification Successful' : 'Verification Failed'}
                          </h3>
                          <p className="text-xs opacity-60 font-mono mt-1">
                            {result.valid 
                              ? `The signature is cryptographically valid for the provided ${variant} public key.` 
                              : result.error || 'The signature does not match the public key and message.'}
                          </p>
                        </div>

                        {result.details && (
                          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 border-t border-[#141414]/10 pt-4">
                            <div className="space-y-1">
                              <span className="text-[9px] uppercase font-bold opacity-40">Variant</span>
                              <p className="text-xs font-mono">{result.details.variant}</p>
                            </div>
                            <div className="space-y-1">
                              <span className="text-[9px] uppercase font-bold opacity-40">Sig Size</span>
                              <p className="text-xs font-mono">{result.details.signatureSize} bytes</p>
                            </div>
                            <div className="space-y-1">
                              <span className="text-[9px] uppercase font-bold opacity-40">PK Size</span>
                              <p className="text-xs font-mono">{result.details.publicKeySize} bytes</p>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>

                    {result.components && (
                      <div className="w-full space-y-4 border-t border-[#141414]/10 pt-6">
                        <div className="flex items-center gap-2">
                          <Cpu size={14} className="opacity-60" />
                          <span className="text-[10px] uppercase font-bold tracking-wider opacity-60">Signature Breakdown (Internal)</span>
                        </div>
                        
                        <div className="grid grid-cols-1 gap-4">
                          <div className="space-y-1">
                            <span className="text-[9px] uppercase font-bold opacity-40">Commitment Hash (c̃)</span>
                            <div className="p-2 bg-[#141414]/5 font-mono text-[10px] break-all border border-[#141414]/10">
                              {result.components.challenge}
                            </div>
                          </div>
                          <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-1">
                              <span className="text-[9px] uppercase font-bold opacity-40">Response Vector (z) [Start]</span>
                              <div className="p-2 bg-[#141414]/5 font-mono text-[10px] break-all border border-[#141414]/10">
                                {result.components.response}
                              </div>
                            </div>
                            <div className="space-y-1">
                              <span className="text-[9px] uppercase font-bold opacity-40">Hint Vector (h) [End]</span>
                              <div className="p-2 bg-[#141414]/5 font-mono text-[10px] break-all border border-[#141414]/10">
                                {result.components.hint}
                              </div>
                            </div>
                          </div>
                        </div>

                        <div className="bg-[#141414]/5 p-4 rounded-sm border border-[#141414]/10">
                          <p className="text-xs leading-relaxed opacity-70 italic">
                            The commitment (w1) was successfully reconstructed from the signature response (z) and public key. 
                            The hash of the reconstructed commitment matches the challenge (c̃) extracted from the signature.
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
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-8"
              >
                {/* Key Generation */}
                <section className="space-y-4">
                  <div className="flex justify-between items-end">
                    <div>
                      <h2 className="font-serif italic text-2xl">Key Generation</h2>
                      <p className="text-xs opacity-60">Generate a new {variant} key pair.</p>
                    </div>
                    <button
                      onClick={handleGenerateKeys}
                      className="px-6 py-2 border border-[#141414] hover:bg-[#141414] hover:text-[#E4E3E0] transition-colors font-mono text-xs uppercase tracking-widest"
                    >
                      Generate New Pair
                    </button>
                  </div>

                  {genKeys && (
                    <div className="grid grid-cols-1 gap-4">
                      <div className="space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="text-[10px] uppercase font-bold opacity-40">Public Key</span>
                          <button onClick={() => copyToClipboard(genKeys.publicKey)} className="text-[10px] flex items-center gap-1 hover:underline"><Copy size={10}/> Copy</button>
                        </div>
                        <div className="p-3 bg-white border border-[#141414] font-mono text-[10px] break-all max-h-24 overflow-y-auto">
                          {genKeys.publicKey}
                        </div>
                      </div>
                      <div className="space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="text-[10px] uppercase font-bold opacity-40">Private Key (Secret)</span>
                          <button onClick={() => copyToClipboard(genKeys.privateKey)} className="text-[10px] flex items-center gap-1 hover:underline"><Copy size={10}/> Copy</button>
                        </div>
                        <div className="p-3 bg-white border border-[#141414] font-mono text-[10px] break-all max-h-24 overflow-y-auto">
                          {genKeys.privateKey}
                        </div>
                      </div>
                    </div>
                  )}
                </section>

                {/* Signing Tool */}
                <section className="space-y-4 border-t border-[#141414]/10 pt-8">
                  <div>
                    <h2 className="font-serif italic text-2xl">Sign Message</h2>
                    <p className="text-xs opacity-60">Create a signature using the generated private key.</p>
                  </div>

                  <div className="space-y-4">
                    <div className="space-y-2">
                      <label className="text-[10px] uppercase font-bold opacity-40">Message to Sign</label>
                      <input
                        type="text"
                        value={genMessage}
                        onChange={(e) => setGenMessage(e.target.value)}
                        className="w-full p-3 bg-transparent border border-[#141414] font-mono text-xs focus:outline-none"
                      />
                    </div>
                    <button
                      onClick={handleSign}
                      disabled={!genKeys}
                      className="w-full py-3 border border-[#141414] bg-[#141414] text-[#E4E3E0] font-serif italic disabled:opacity-30"
                    >
                      Sign Payload
                    </button>

                    {genSignature && (
                      <div className="space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="text-[10px] uppercase font-bold opacity-40">Generated Signature</span>
                          <div className="flex gap-3">
                            <button 
                              onClick={() => {
                                setPublicKey(genKeys?.publicKey || '');
                                setSignature(genSignature);
                                setMessage(genMessage);
                                setActiveTab('inspect');
                              }} 
                              className="text-[10px] flex items-center gap-1 hover:underline text-blue-600"
                            >
                              <Search size={10}/> Send to Inspector
                            </button>
                            <button onClick={() => copyToClipboard(genSignature)} className="text-[10px] flex items-center gap-1 hover:underline"><Copy size={10}/> Copy</button>
                          </div>
                        </div>
                        <div className="p-3 bg-white border border-[#141414] font-mono text-[10px] break-all max-h-32 overflow-y-auto">
                          {genSignature}
                        </div>
                      </div>
                    )}
                  </div>
                </section>
              </motion.div>
            ) : (
              <motion.div
                key="python"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-6"
              >
                <div>
                  <h2 className="font-serif italic text-2xl">Python Reference</h2>
                  <p className="text-xs opacity-60">Equivalent implementation using Python for backend integration.</p>
                </div>

                <div className="relative group">
                  <button 
                    onClick={() => copyToClipboard(pythonCode)}
                    className="absolute right-4 top-4 p-2 bg-[#E4E3E0] border border-[#141414] opacity-0 group-hover:opacity-100 transition-opacity"
                  >
                    <Copy size={14} />
                  </button>
                  <pre className="p-6 bg-[#141414] text-[#E4E3E0] font-mono text-xs overflow-x-auto rounded-sm leading-relaxed">
                    {pythonCode}
                  </pre>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="p-4 border border-[#141414]/20 bg-[#141414]/5">
                    <h4 className="text-[10px] uppercase font-bold tracking-wider mb-2">Recommended Libraries</h4>
                    <ul className="text-xs space-y-2 opacity-70 list-disc pl-4">
                      <li><strong>liboqs-python</strong>: Official wrapper for liboqs.</li>
                      <li><strong>cryptography</strong>: Check latest versions for FIPS 204 support.</li>
                      <li><strong>pure-python-dilithium</strong>: For environments without C dependencies.</li>
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
          </div>
          <p className="text-[10px] opacity-40 font-mono">
            &copy; 2026 CRYPTO-LABS. ALL RIGHTS RESERVED.
          </p>
        </div>
      </footer>
    </div>
  );
}
