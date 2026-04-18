import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import SignatureAnalysisPanel from '../SignatureAnalysisPanel';
import * as mldsaService from '../../services/mldsa';
import React from 'react';

// Mock Framer Motion
vi.mock('motion/react', () => {
    const React = require('react');
    const Component = React.forwardRef(({ children, initial, animate, exit, transition, ...props }: any, ref: any) => {
        return React.createElement('div', { ...props, ref }, children);
    });
    return {
        motion: new Proxy({}, { get: () => Component }),
        AnimatePresence: ({ children }: any) => children,
    };
});

vi.mock('../../services/mldsa', async (importOriginal) => {
    const original = await importOriginal<typeof import('../../services/mldsa')>();
    return {
        ...original,
        analyzeSignature: vi.fn(),
        testMalleability: vi.fn(),
    };
});

describe('SignatureAnalysisPanel', () => {
    const mockAnalysis = {
        totalBytes: 2420,
        expectedBytes: 2420,
        lengthOk: true,
        cTildeBytes: 32,
        cTildeHex: 'cTilde',
        zOffsetBytes: 32,
        zSizeBytes: 2000,
        zPolynomials: [{ index: 0, maxAbsCoeff: 100, normBound: 100000 }],
        zBound: 100000,
        zNormOk: true,
        hOffsetBytes: 2032,
        hSizeBytes: 388,
        hHints: [{ polyIndex: 0, oneCount: 10 }],
        hTotalOnes: 10,
        hOmega: 80,
        hNormOk: true,
    };

    const mockProps = {
        variant: 'ML-DSA-44' as const,
        publicKey: 'pub',
        signatureHex: 'sig',
        message: new Uint8Array([1, 2, 3]),
        opts: { mode: 'pure' as const, contextText: '', hashAlg: undefined },
    };

    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        cleanup();
    });

    it('renders null if analysis fails', () => {
        (mldsaService.analyzeSignature as any).mockReturnValue(null);
        const { container } = render(<SignatureAnalysisPanel {...mockProps} />);
        expect(container.firstChild).toBeNull();
    });

    it('renders correctly and toggles sections', async () => {
        (mldsaService.analyzeSignature as any).mockReturnValue(mockAnalysis);
        render(<SignatureAnalysisPanel {...mockProps} />);

        expect(screen.getByText(/Deeper Signature Analysis/i)).toBeDefined();

        // 1. Structure
        fireEvent.click(screen.getByText(/Signature Component Decoder/i));
        expect(screen.getByText(/Signature length 2420B matches expected 2420B/i)).toBeDefined();
        expect(screen.getByText('c̃')).toBeDefined();

        // 2. Norms
        fireEvent.click(screen.getByText(/Norm & Bound Checker/i));
        expect(screen.getByText(/z ∞-norm/i)).toBeDefined();

        // 3. Malleability
        fireEvent.click(screen.getByText(/Signature Malleability Tester/i));
        expect(screen.getByText(/Run Malleability Test/i)).toBeDefined();
    });

    it('runs malleability test and displays results', async () => {
        (mldsaService.analyzeSignature as any).mockReturnValue(mockAnalysis);
        (mldsaService.testMalleability as any).mockResolvedValue([
            { byteIndex: 0, bitIndex: 0, region: 'c̃', stillValid: false },
        ]);

        render(<SignatureAnalysisPanel {...mockProps} />);

        fireEvent.click(screen.getByText(/Signature Malleability Tester/i));
        const runBtn = screen.getByText(/Run Malleability Test/i);
        fireEvent.click(runBtn);

        await waitFor(() => {
            expect(mldsaService.testMalleability).toHaveBeenCalled();
            expect(screen.getByText(/c̃ region/i)).toBeDefined();
            expect(screen.getByText(/All 1 tested bit-flips caused verification failure/i)).toBeDefined();
        });
    });
});
