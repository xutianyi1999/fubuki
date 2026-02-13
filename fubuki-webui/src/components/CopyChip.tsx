import { useState, useCallback } from 'react';

interface CopyChipProps {
  label: string;
  copyText: string;
  title?: string;
  className?: string;
  /** Status color class, e.g. text-emerald-400 / text-amber-400 / text-red-400 */
  qualityClass?: string;
}

export function CopyChip({ label, copyText, title, className = '', qualityClass = '' }: CopyChipProps) {
  const [copied, setCopied] = useState(false);

  const handleClick = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(copyText);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // ignore
    }
  }, [copyText]);

  return (
    <button
      type="button"
      onClick={handleClick}
      title={title ?? 'Click to copy'}
      className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-xs font-medium bg-cyan-500/15 border border-cyan-500/25 hover:bg-cyan-500/25 cursor-pointer transition-colors ${qualityClass || 'text-cyan-400'} ${className}`}
    >
      {copied ? (
        <>
          <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          Copied
        </>
      ) : (
        label
      )}
    </button>
  );
}
