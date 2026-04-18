import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup, act } from '@testing-library/react';
import KeyAndSignTab from '../KeyAndSignTab';
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

// Mock services
vi.mock('../../services/mldsa');
vi.mock('../SharedUI', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../SharedUI')>();
    return {
        ...actual,
        downloadJSON: vi.fn(),
        downloadBinary: vi.fn(),
        readBinFile: vi.fn().mockImplementation(() => Promise.resolve(new Uint8Array([0]))),
    };
});

describe('KeyAndSignTab', () => {
    const mockState = {
        genKeys: null,
        genMessage: 'hello',
        isGenMessageBinary: false,
        genSignature: '',
        signMode: 'pure' as const,
        signContext: '',
        signHashAlg: 'SHA-256' as const,
        signDeterministic: false,
    };
    const mockSetState = vi.fn((updater) => {
        if (typeof updater === 'function') {
            updater(mockState);
        }
    });
    const mockOnVariantChange = vi.fn();
    const mockOnSendToInspector = vi.fn();

    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        cleanup();
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
    });

    it('renders initial state with variant selector', () => {
        render(
            <KeyAndSignTab 
                variant="ML-DSA-44" 
                onVariantChange={mockOnVariantChange} 
                onSendToInspector={mockOnSendToInspector}
                state={mockState}
                setState={mockSetState}
            />
        );
        expect(screen.getByText(/Keypair Gen & Sign/i)).toBeDefined();
        expect(screen.getByText('Generate New Pair')).toBeDefined();
    });

    it('handles key generation', async () => {
        (mldsaService.generateKeyPair as any).mockReturnValue({ publicKey: 'pub', privateKey: 'priv' });

        render(
            <KeyAndSignTab 
                variant="ML-DSA-44" 
                onVariantChange={mockOnVariantChange} 
                onSendToInspector={mockOnSendToInspector}
                state={mockState}
                setState={mockSetState}
            />
        );

        const genBtn = screen.getByRole('button', { name: /Generate New Pair/i });
        fireEvent.click(genBtn);
        
        expect(mldsaService.generateKeyPair).toHaveBeenCalled();
        expect(mockSetState).toHaveBeenCalled();
    });

    it('handles signing a message', async () => {
        const stateWithKeys = { ...mockState, genKeys: { publicKey: 'pub', privateKey: 'priv' } };
        (mldsaService.signMessage as any).mockReturnValue('sig');

        render(
            <KeyAndSignTab 
                variant="ML-DSA-44" 
                onVariantChange={mockOnVariantChange} 
                onSendToInspector={mockOnSendToInspector}
                state={stateWithKeys}
                setState={mockSetState}
            />
        );

        const signBtn = screen.getByRole('button', { name: /Sign Payload/i });
        fireEvent.click(signBtn);
        
        expect(mldsaService.signMessage).toHaveBeenCalled();
        expect(mockSetState).toHaveBeenCalled();
    });

    it('handles binary message input validation', async () => {
        const stateWithKeys = { ...mockState, genKeys: { publicKey: 'pub', privateKey: 'priv' }, isGenMessageBinary: true, genMessage: 'invalid' };
        
        render(
            <KeyAndSignTab 
                variant="ML-DSA-44" 
                onVariantChange={mockOnVariantChange} 
                onSendToInspector={mockOnSendToInspector}
                state={stateWithKeys}
                setState={mockSetState}
            />
        );

        fireEvent.click(screen.getByRole('button', { name: /Sign Payload/i }));
        
        expect(screen.getByText(/Message hex contains invalid characters/i)).toBeDefined();
    });

    it('exports keys to JSON', () => {
        const stateWithKeys = { ...mockState, genKeys: { publicKey: 'pub', privateKey: 'priv' } };
        render(
            <KeyAndSignTab 
                variant="ML-DSA-44" 
                onVariantChange={mockOnVariantChange} 
                onSendToInspector={mockOnSendToInspector}
                state={stateWithKeys}
                setState={mockSetState}
            />
        );

        fireEvent.click(screen.getByRole('button', { name: /Export full json/i }));
        expect(sharedUI.downloadJSON).toHaveBeenCalled();
    });

    it('imports keys from JSON', async () => {
        // Mock FileReader
        const mockReader = {
            readAsText: vi.fn(function(this: any) {
                const result = JSON.stringify({ publicKey: 'p', privateKey: 's', variant: 'ML-DSA-44' });
                if (this.onload) this.onload({ target: { result } });
            }),
            onload: null as any
        };
        vi.stubGlobal('FileReader', function() { return mockReader; });

        const { container } = render(
            <KeyAndSignTab 
                variant="ML-DSA-44" 
                onVariantChange={mockOnVariantChange} 
                onSendToInspector={mockOnSendToInspector}
                state={mockState}
                setState={mockSetState}
            />
        );

        const input = container.querySelector('input[accept=".json"]')!;
        const mockFile = new File(['{}'], 'keys.json', { type: 'application/json' });
        
        fireEvent.change(input, { target: { files: [mockFile] } });

        await waitFor(() => {
            expect(mockSetState).toHaveBeenCalled();
        }, { timeout: 5000 });
    });
    
    it('shows error on invalid JSON import (array)', async () => {
        const mockReader = {
            readAsText: vi.fn(function(this: any) {
                if (this.onload) this.onload({ target: { result: JSON.stringify([{ a: 1 }]) } });
            }),
            onload: null as any
        };
        vi.stubGlobal('FileReader', function() { return mockReader; });

        const { container } = render(
            <KeyAndSignTab variant="ML-DSA-44" onVariantChange={mockOnVariantChange} onSendToInspector={mockOnSendToInspector} state={mockState} setState={mockSetState} />
        );
        const input = container.querySelector('input[accept=".json"]')!;
        fireEvent.change(input, { target: { files: [new File(['[]'], 'test.json')] } });

        await waitFor(() => {
            expect(screen.getByText(/Invalid JSON format: expected an object/i)).toBeDefined();
            expect(mockSetState).not.toHaveBeenCalled();
        });
    });

    it('shows error on JSON import missing keys', async () => {
        const mockReader = {
            readAsText: vi.fn(function(this: any) {
                if (this.onload) this.onload({ target: { result: JSON.stringify({ variant: 'ML-DSA-44' }) } });
            }),
            onload: null as any
        };
        vi.stubGlobal('FileReader', function() { return mockReader; });

        const { container } = render(
            <KeyAndSignTab variant="ML-DSA-44" onVariantChange={mockOnVariantChange} onSendToInspector={mockOnSendToInspector} state={mockState} setState={mockSetState} />
        );
        const input = container.querySelector('input[accept=".json"]')!;
        fireEvent.change(input, { target: { files: [new File(['{}'], 'test.json')] } });

        await waitFor(() => {
            expect(screen.getByText(/Missing or invalid key fields/i)).toBeDefined();
        });
    });

    it('shows error on JSON import with non-string keys', async () => {
        const mockReader = {
            readAsText: vi.fn(function(this: any) {
                if (this.onload) this.onload({ target: { result: JSON.stringify({ publicKey: 123, privateKey: 's' }) } });
            }),
            onload: null as any
        };
        vi.stubGlobal('FileReader', function() { return mockReader; });

        const { container } = render(
            <KeyAndSignTab variant="ML-DSA-44" onVariantChange={mockOnVariantChange} onSendToInspector={mockOnSendToInspector} state={mockState} setState={mockSetState} />
        );
        const input = container.querySelector('input[accept=".json"]')!;
        fireEvent.change(input, { target: { files: [new File(['{}'], 'test.json')] } });

        await waitFor(() => {
            expect(screen.getByText(/Missing or invalid key fields/i)).toBeDefined();
        });
    });
});
