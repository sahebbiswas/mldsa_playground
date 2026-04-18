import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import X509Tab from '../X509Tab';
import * as x509Service from '../../services/x509';
import * as mldsaService from '../../services/mldsa';
import * as sharedUI from '../SharedUI';
import React from 'react';

// Mock Framer Motion
vi.mock('motion/react', async () => {
    const React = (await import('react')).default;
    const Component = React.forwardRef(({ children, initial, animate, exit, transition, ...props }: any, ref: any) => {
        return React.createElement('div', { ...props, ref }, children);
    });
    return {
        motion: new Proxy({}, { get: () => Component }),
        AnimatePresence: ({ children }: any) => children,
    };
});

// Mock services
vi.mock('../../services/x509');
vi.mock('../../services/mldsa');
vi.mock('../SharedUI', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../SharedUI')>();
    return {
        ...actual,
        readBinFile: vi.fn().mockImplementation(() => Promise.resolve(new Uint8Array([0]))),
    };
});

describe('X509Tab', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        cleanup();
    });

    it('renders correctly in initial state', () => {
        render(<X509Tab />);
        expect(screen.getByText(/X.509 Certificate Decoder/i)).toBeDefined();
        expect(screen.getByText(/Click or drag/i)).toBeDefined();
    });

    it('handles file upload and error parsing', async () => {
        const mockFile = new File(['garbage'], 'test.der', { type: 'application/x-x509-ca-cert' });
        (sharedUI.readBinFile as any).mockResolvedValue(new Uint8Array([1, 2, 3]));
        (x509Service.processCertificateBytes as any).mockReturnValue({
            valid: false,
            error: 'Invalid format'
        });

        const { container } = render(<X509Tab />);
        const input = container.querySelector('input[type="file"]')!;

        // Simulating file upload
        fireEvent.change(input, { target: { files: [mockFile] } });

        await waitFor(() => {
            expect(screen.getByText(/Invalid or Unsupported Certificate/i)).toBeDefined();
            expect(screen.getByText(/Invalid format/i)).toBeDefined();
        });
    });

    it('handles successful self-signed certificate parsing and auto-verification', async () => {
        const mockFile = new File(['cert'], 'test.crt');
        const mockDetails = {
            subject: 'CN=Test Subject',
            issuer: 'CN=Test Subject', // Self-signed
            notBefore: new Date('2024-01-01T00:00:00Z'),
            notAfter: new Date('2025-01-01T00:00:00Z'),
            serialNumber: '01:02:03',
            signatureAlgorithmObj: '2.16.840.1.101.3.4.3.17',
            signatureVariant: 'ML-DSA-44',
            isSelfSigned: true,
            publicKeyBytes: new Uint8Array([0xaa]),
            signatureValueBytes: new Uint8Array([0xbb]),
            tbsBytes: new Uint8Array([0xcc]),
        };

        (sharedUI.readBinFile as any).mockResolvedValue(new Uint8Array([0]));
        (x509Service.processCertificateBytes as any).mockReturnValue({
            valid: true,
            details: mockDetails
        });
        (x509Service.verifyX509Signature as any).mockReturnValue(true);

        const { container } = render(<X509Tab />);
        const input = container.querySelector('input[type="file"]')!;
        fireEvent.change(input, { target: { files: [mockFile] } });

        // Wait for parsed results to appear (Subject + Issuer)
        const subjectEls = await screen.findAllByText(/Test Subject/i, {}, { timeout: 3000 });
        expect(subjectEls.length).toBeGreaterThanOrEqual(1);

        // Wait for auto-verification result
        const validEl = await screen.findByText(/is Cryptographically Valid/i, {}, { timeout: 3000 });
        expect(validEl).toBeDefined();

        expect(x509Service.verifyX509Signature).toHaveBeenCalled();
    });

    it('requires issuer key for non-self-signed certificates', async () => {
        const mockFile = new File(['cert'], 'test.crt');
        const mockDetails = {
            subject: 'CN=Client',
            issuer: 'CN=Root CA', // NOT self-signed
            notBefore: new Date('2024-01-01T00:00:00Z'),
            notAfter: new Date('2025-01-01T00:00:00Z'),
            serialNumber: '01:02:03',
            signatureAlgorithmObj: '2.16.840.1.101.3.4.3.17',
            signatureVariant: 'ML-DSA-44',
            isSelfSigned: false,
            publicKeyBytes: new Uint8Array([0xaa]),
            signatureValueBytes: new Uint8Array([0xbb]),
            tbsBytes: new Uint8Array([0xcc]),
        };

        (sharedUI.readBinFile as any).mockResolvedValue(new Uint8Array([0]));
        (x509Service.processCertificateBytes as any).mockReturnValue({
            valid: true,
            details: mockDetails
        });

        const { container } = render(<X509Tab />);
        const input = container.querySelector('input[type="file"]')!;
        fireEvent.change(input, { target: { files: [mockFile] } });

        await waitFor(() => {
            expect(screen.getByText(/Issuer Public Key Required/i)).toBeDefined();
        });

        // Try to verify with manual hex key
        const hexInput = screen.getByPlaceholderText(/paste pure hex bytes here/i);
        fireEvent.change(hexInput, { target: { value: '00'.repeat(1312) } }); // Long enough to enable button

        const verifyBtn = screen.getByText(/Verify Signature/i);
        (x509Service.verifyX509Signature as any).mockReturnValue(true);
        (mldsaService.hexToUint8Array as any).mockReturnValue(new Uint8Array(1312));

        fireEvent.click(verifyBtn);

        await waitFor(() => {
            expect(screen.getByText(/Signature mathematically verifies/i)).toBeDefined();
        });
    });

    it('handles drag and drop', async () => {
        (sharedUI.readBinFile as any).mockResolvedValue(new Uint8Array([0]));
        (x509Service.processCertificateBytes as any).mockReturnValue({ valid: false, error: 'Drop error' });

        render(<X509Tab />);
        const dropZone = screen.getByText(/Click or drag/i).closest('button')!;

        fireEvent.dragOver(dropZone);
        expect(screen.getByText(/Drop certificate here/i)).toBeDefined();

        fireEvent.dragLeave(dropZone);
        expect(screen.getByText(/Click or drag/i)).toBeDefined();

        // Simulate drop
        const file = new File([''], 'test.pem');
        fireEvent.drop(dropZone, {
            dataTransfer: {
                files: [file]
            }
        });

        await waitFor(() => {
            expect(screen.getByText(/Drop error/i)).toBeDefined();
        });
    });
});
