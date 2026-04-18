import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import InspectTab from '../InspectTab';
import * as mldsaService from '../../services/mldsa';
import * as sharedUI from '../SharedUI';
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

// Mock components
vi.mock('../SignatureAnalysisPanel', () => ({
    default: () => <div>SignatureAnalysisPanel</div>
}));

// Mock services
vi.mock('../../services/mldsa');
vi.mock('../SharedUI', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../SharedUI')>();
    return {
        ...actual,
        readBinFile: vi.fn(),
    };
});

describe('InspectTab', () => {
    const mockState = {
        publicKey: '',
        signature: '',
        message: '',
        isMessageBinary: false,
        inspectMode: 'pure' as const,
        inspectContext: '',
        inspectContextRawHex: undefined as string | undefined,
        inspectHashAlg: 'SHA-256' as const,
        inspectPrimitive: false,
        inspectExternalMu: false,
    };
    const mockSetState = vi.fn();

    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        cleanup();
    });

    it('renders correctly in initial state', () => {
        render(
            <InspectTab
                variant="ML-DSA-44"
                initialPayload={null}
                state={mockState}
                setState={mockSetState}
            />
        );
        expect(screen.getByText(/Signature Inspector/i)).toBeDefined();
        expect(screen.getByText(/Inspect & Verify/i)).toBeDefined();
    });

    it('updates state when initialPayload is provided', () => {
        const payload = {
            variant: 'ML-DSA-44' as const,
            publicKey: 'pub',
            signature: 'sig',
            message: 'msg',
            mode: 'pure' as const,
            contextRawHex: 'ctx',
            showAdvanced: true
        };

        render(
            <InspectTab
                variant="ML-DSA-44"
                initialPayload={payload}
                state={mockState}
                setState={mockSetState}
            />
        );

        expect(mockSetState).toHaveBeenCalled();
    });

    it('handles signature verification', async () => {
        const stateWithData = { ...mockState, publicKey: 'pub', signature: 'sig', message: 'msg' };
        (mldsaService.inspectSignature as any).mockResolvedValue({ valid: true });

        render(
            <InspectTab
                variant="ML-DSA-44"
                initialPayload={null}
                state={stateWithData}
                setState={mockSetState}
            />
        );

        fireEvent.click(screen.getByText(/Inspect & Verify/i));

        await waitFor(() => {
            expect(mldsaService.inspectSignature).toHaveBeenCalled();
            expect(screen.getByText(/Signature is Cryptographically Valid/i)).toBeDefined();
        });
    });

    it('handles verification failure', async () => {
        const stateWithData = { ...mockState, publicKey: 'pub', signature: 'sig', message: 'msg' };
        (mldsaService.inspectSignature as any).mockResolvedValue({ valid: false, error: 'Wrong sig' });

        render(
            <InspectTab
                variant="ML-DSA-44"
                initialPayload={null}
                state={stateWithData}
                setState={mockSetState}
            />
        );

        fireEvent.click(screen.getByText(/Inspect & Verify/i));

        await waitFor(() => {
            expect(screen.getByText(/Signature Rejected/i)).toBeDefined();
            expect(screen.getByText(/Wrong sig/i)).toBeDefined();
        });
    });

    it('handles binary imports', async () => {
        (sharedUI.readBinFile as any).mockResolvedValue(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
        (mldsaService.uint8ArrayToHex as any).mockReturnValue('deadbeef');

        const { container } = render(
            <InspectTab
                variant="ML-DSA-44"
                initialPayload={null}
                state={mockState}
                setState={mockSetState}
            />
        );

        const loadPubBtns = screen.getAllByTitle(/Load from binary file/i);
        const loadPubBtn = loadPubBtns[0];
        const inputs = container.querySelectorAll('input[type="file"]');

        fireEvent.change(inputs[0], { target: { files: [new File([''], 'pub.bin')] } });

        await waitFor(() => {
            expect(mockSetState).toHaveBeenCalled();
        });
    });
});
