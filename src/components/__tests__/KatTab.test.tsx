import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import KatTab from '../KatTab';
import * as katService from '../../services/kat';
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
vi.mock('../../services/kat');

describe('KatTab', () => {
    const mockOnVariantChange = vi.fn();
    const mockOnSendToInspector = vi.fn();

    beforeEach(() => {
        vi.clearAllMocks();
        // Shim File.prototype.text if missing (jsdom < 20)
        if (!File.prototype.text) {
            File.prototype.text = function() {
                return Promise.resolve('{"testGroups": []}');
            };
        }
        // Mock URL and document for export testing
        global.URL.createObjectURL = vi.fn(() => 'blob:url');
        global.URL.revokeObjectURL = vi.fn();
    });

    afterEach(() => {
        cleanup();
    });

    it('renders correctly in initial state', () => {
        render(
            <KatTab
                variant="ML-DSA-44"
                onVariantChange={mockOnVariantChange}
                onSendToInspector={mockOnSendToInspector}
            />
        );
        expect(screen.getByText(/KAT Validator/i)).toBeDefined();
        expect(screen.getByText(/MAX VECTORS:/i)).toBeDefined();
    });

    it('handles vector file upload and run', async () => {
        const mockFile = new File(['{"testGroups": []}'], 'prompt.json');
        (katService.parseKatFile as any).mockReturnValue({
            vectors: [{ tcId: 1, pk: '00', message: '11', signature: '22' }],
            inferredVariant: 'ML-DSA-44'
        });
        (katService.runKatVectors as any).mockResolvedValue({
            variant: 'ML-DSA-44',
            total: 1,
            passed: 1,
            failed: 0,
            skipped: 0,
            durationMs: 10,
            vectors: [{
                tcId: 1,
                pk: '00',
                message: '11',
                signature: '22',
                verifyOk: true,
                effectivePass: true,
                modeLabel: 'Pure',
                matchesExpected: true
            }]
        });

        const { container } = render(
            <KatTab
                variant="ML-DSA-44"
                onVariantChange={mockOnVariantChange}
                onSendToInspector={mockOnSendToInspector}
            />
        );

        const inputs = container.querySelectorAll('input[type="file"]');
        const promptInput = inputs[inputs.length - 1];
        // Actually wait, let's use the text or something more reliable.

        fireEvent.change(promptInput, { target: { files: [mockFile] } });

        await waitFor(() => {
            expect(screen.getByText(/100%/)).toBeDefined();
            expect(screen.getByText(/tc#1/i)).toBeDefined();
        });

        expect(katService.runKatVectors).toHaveBeenCalled();
    });

    it('handles expectedResults.json upload and comparison', async () => {
        // First load a vector file
        const mockPromptFile = new File(['{}'], 'prompt.json');
        (katService.parseKatFile as any).mockReturnValue({
            vectors: [{ tcId: 1, pk: '00', message: '11', signature: '22' }],
            inferredVariant: 'ML-DSA-44'
        });
        (katService.runKatVectors as any).mockResolvedValue({
            variant: 'ML-DSA-44',
            total: 1,
            passed: 1,
            failed: 0,
            skipped: 0,
            durationMs: 10,
            vectors: [{
                tcId: 1,
                pk: '00',
                message: '11',
                signature: '22',
                verifyOk: true,
                effectivePass: true,
                modeLabel: 'Pure',
                matchesExpected: true
            }]
        });

        const { container } = render(
            <KatTab
                variant="ML-DSA-44"
                onVariantChange={mockOnVariantChange}
                onSendToInspector={mockOnSendToInspector}
            />
        );

        // Open advanced to see expected results input
        fireEvent.click(screen.getByText(/Show Advanced/i));

        const inputs = container.querySelectorAll('input[type="file"]');
        const expectedInput = inputs[0];
        const promptInput = inputs[1];

        fireEvent.change(promptInput, { target: { files: [mockPromptFile] } });

        await waitFor(() => expect(screen.getByText(/tc#1/i)).toBeDefined());

        // Now load expected results
        const mockExpectedFile = new File(['{"results": []}'], 'expected.json');
        (katService.parseExpectedResults as any).mockReturnValue(new Map([[1, { testPassed: true }]]));

        fireEvent.change(expectedInput, { target: { files: [mockExpectedFile] } });

        await waitFor(() => {
            expect(katService.runKatVectors).toHaveBeenCalledTimes(2); // Initial + Re-run after expected loaded
        });
    });

    it('filters results correctly', async () => {
        (katService.runKatVectors as any).mockResolvedValue({
            variant: 'ML-DSA-44',
            total: 2,
            passed: 1,
            failed: 1,
            skipped: 0,
            durationMs: 10,
            vectors: [
                { tcId: 1, verifyOk: true, effectivePass: true, modeLabel: 'Pure' },
                { tcId: 2, verifyOk: false, effectivePass: false, modeLabel: 'Pure' },
            ]
        });

        const { container } = render(
            <KatTab
                variant="ML-DSA-44"
                onVariantChange={mockOnVariantChange}
                onSendToInspector={mockOnSendToInspector}
            />
        );

        // Mock a file load to trigger result display
        const promptInput = container.querySelectorAll('input[type="file"]')[0];
        (katService.parseKatFile as any).mockReturnValue({ vectors: [], inferredVariant: 'ML-DSA-44' });
        fireEvent.change(promptInput, { target: { files: [new File([''], 'p.json')] } });

        await waitFor(() => expect(screen.getByText(/1 failed/i)).toBeDefined());

        expect(screen.getByText(/tc#1/i)).toBeDefined();
        expect(screen.getByText(/tc#2/i)).toBeDefined();

        // Filter for failed
        fireEvent.click(screen.getByText(/1 failed/i));

        expect(screen.queryByText(/tc#1/i)).toBeNull();
        expect(screen.getByText(/tc#2/i)).toBeDefined();
    });

    it('exports results to JSON', async () => {
        (katService.runKatVectors as any).mockResolvedValue({
            variant: 'ML-DSA-44',
            vectors: []
        });

        const { container } = render(
            <KatTab
                variant="ML-DSA-44"
                onVariantChange={mockOnVariantChange}
                onSendToInspector={mockOnSendToInspector}
            />
        );

        const promptInput = container.querySelectorAll('input[type="file"]')[0];
        (katService.parseKatFile as any).mockReturnValue({ vectors: [], inferredVariant: 'ML-DSA-44' });
        fireEvent.change(promptInput, { target: { files: [new File([''], 'p.json')] } });

        await waitFor(() => expect(screen.getByText(/Export Results JSON/i)).toBeDefined());

        fireEvent.click(screen.getByText(/Export Results JSON/i));

        expect(global.URL.createObjectURL).toHaveBeenCalled();
    });
});
