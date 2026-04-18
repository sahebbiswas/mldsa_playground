import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup, act } from '@testing-library/react';
import KeyAnalysisPanel from '../KeyAnalysisPanel';
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

vi.mock('../../services/mldsa', () => {
    const original = vi.importActual('../../services/mldsa');
    return {
        ...original,
        analyzePublicKey: vi.fn(),
        VARIANT_PARAMS: {
            'ML-DSA-44': { pkBytes: 1312, skBytes: 2560, sigBytes: 2420, k: 4 },
            'ML-DSA-65': { pkBytes: 1952, skBytes: 4000, sigBytes: 3309, k: 6 },
            'ML-DSA-87': { pkBytes: 2592, skBytes: 4864, sigBytes: 4627, k: 8 },
        }
    };
});

describe('KeyAnalysisPanel', () => {
    const mockAnalysis = {
        variant: 'ML-DSA-44',
        totalBytes: 1312,
        expectedBytes: 1312,
        lengthOk: true,
        rhoHex: '00'.repeat(32),
        t1Bytes: 1280,
        t1Polynomials: [
            { index: 0, coefficients: new Array(256).fill(512), minCoeff: 512, maxCoeff: 512 },
            { index: 1, coefficients: new Array(256).fill(512), minCoeff: 512, maxCoeff: 512 },
        ],
        ssh_style: 'SHA256:abc',
        sha256Fingerprint: 'sha256',
        shake256Fingerprint: 'shake256',
    };

    beforeEach(() => {
        vi.clearAllMocks();
        // Mock clipboard
        Object.assign(navigator, {
            clipboard: {
                writeText: vi.fn().mockImplementation(() => Promise.resolve()),
            },
        });
    });

    afterEach(() => {
        cleanup();
    });

    it('renders null if analysis fails', () => {
        (mldsaService.analyzePublicKey as any).mockReturnValue(null);
        const { container } = render(<KeyAnalysisPanel variant="ML-DSA-44" publicKeyHex="invalid" />);
        expect(container.firstChild).toBeNull();
    });

    it('renders correctly and toggles sections', async () => {
        (mldsaService.analyzePublicKey as any).mockReturnValue(mockAnalysis);
        render(<KeyAnalysisPanel variant="ML-DSA-44" publicKeyHex="00" />);

        expect(screen.getByText(/Key Analysis/i)).toBeDefined();

        // 1. Decoder
        fireEvent.click(screen.getByText(/Public Key Structure/i));
        expect(await screen.findByText(/Key length 1312B — matches ML-DSA-44/i)).toBeDefined();
        expect(screen.getByText('ρ — matrix seed (32 bytes)')).toBeDefined();

        // 2. Fingerprints
        fireEvent.click(screen.getByText(/Key Fingerprints/i));
        expect(screen.getByText('SHA256:abc')).toBeDefined();

        // 3. Comparison
        fireEvent.click(screen.getByText(/Variant Size & Security Comparison/i));
        const comparisonEls = screen.getAllByText('ML-DSA-87');
        expect(comparisonEls.length).toBeGreaterThan(0);
    });

    it('handles clipboard copy', async () => {
        (mldsaService.analyzePublicKey as any).mockReturnValue(mockAnalysis);
        (navigator.clipboard.writeText as any).mockResolvedValueOnce(undefined);

        render(<KeyAnalysisPanel variant="ML-DSA-44" publicKeyHex="00" />);
        fireEvent.click(screen.getByText(/Key Fingerprints/i));

        const copyBtns = screen.getAllByTitle('Copy to clipboard');
        await act(async () => {
            fireEvent.click(copyBtns[0]);
        });

        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('SHA256:abc');
    });
});
