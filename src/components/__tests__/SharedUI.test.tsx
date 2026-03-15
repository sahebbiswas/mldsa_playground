import { describe, it, expect } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';
import { ModeBadge, HexPreview } from '../SharedUI';

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
});
