import { describe, it, expect, vi } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';
import { ModeBadge, HexPreview, TinyBtn, ActionRow, AdvancedOptions } from '../SharedUI';

describe('SharedUI Components', () => {

    describe('ModeBadge', () => {
        it('renders pure mode correctly', () => {
            render(<ModeBadge mode="pure" />);
            expect(screen.getByText('Pure ML-DSA')).toBeDefined();
            cleanup();
        });

        it('renders hash mode correctly', () => {
            render(<ModeBadge mode="hash-ml-dsa" />);
            expect(screen.getByText('Hash ML-DSA')).toBeDefined();
            cleanup();
        });
    });

    describe('HexPreview', () => {
        it('renders the label and hex text', () => {
            render(<HexPreview label="Public Key" hex="0A1B2C" />);
            expect(screen.getByText('Public Key')).toBeDefined();
            expect(screen.getByText('0A1B2C')).toBeDefined();
            cleanup();
        });

        it('renders the byte count if provided', () => {
            render(<HexPreview label="Signature" hex="001122" bytes={3} />);
            expect(screen.getByText('3 bytes')).toBeDefined();
            cleanup();
        });
    });

    describe('TinyBtn', () => {
        it('renders and responds to clicks', () => {
            const onClick = vi.fn();
            render(<TinyBtn onClick={onClick}>Click Me</TinyBtn>);
            const btn = screen.getByText('Click Me');
            btn.click();
            expect(onClick).toHaveBeenCalled();
            cleanup();
        });

        it('is disabled when the prop is set', () => {
            render(<TinyBtn onClick={() => {}} disabled>Disabled</TinyBtn>);
            const btn = screen.getByRole('button');
            expect(btn.hasAttribute('disabled')).toBe(true);
            cleanup();
        });
    });

    describe('AdvancedOptions', () => {
        const defaultProps = {
            mode: 'pure' as const,
            onModeChange: vi.fn(),
            context: '',
            onContextChange: vi.fn(),
            hashAlg: 'SHA-256' as const,
            onHashAlgChange: vi.fn(),
        };

        it('renders the label and mode buttons', () => {
            render(<AdvancedOptions {...defaultProps} label="Config" />);
            expect(screen.getByText('Config')).toBeDefined();
            expect(screen.getByText('Pure ML-DSA')).toBeDefined();
            cleanup();
        });

        it('switches mode when clicked', () => {
            render(<AdvancedOptions {...defaultProps} />);
            const hashBtn = screen.getByText('Hash ML-DSA');
            hashBtn.click();
            expect(defaultProps.onModeChange).toHaveBeenCalledWith('hash-ml-dsa');
            cleanup();
        });

        it('shows hash algorithms when in hash mode', () => {
            render(<AdvancedOptions {...defaultProps} mode="hash-ml-dsa" />);
            expect(screen.getByText('SHA-512')).toBeDefined();
            cleanup();
        });

        it('updates context when input changes', () => {
            render(<AdvancedOptions {...defaultProps} />);
            const input = screen.getByPlaceholderText(/context string/i);
            const { fireEvent } = require('@testing-library/react');
            fireEvent.change(input, { target: { value: 'new-ctx' } });
            expect(defaultProps.onContextChange).toHaveBeenCalledWith('new-ctx');
            cleanup();
        });
    });
});
