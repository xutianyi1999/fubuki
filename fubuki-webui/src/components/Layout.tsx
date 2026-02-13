import { Link } from 'react-router-dom';

interface LayoutProps {
  children: React.ReactNode;
}

export function Layout({ children }: LayoutProps) {
  return (
    <>
      <header className="border-b border-[var(--border)] bg-[var(--surface)]/80 backdrop-blur-sm sticky top-0 z-20">
        <div className="w-full mx-auto px-6 h-14 flex items-center gap-4">
          <Link
            to="/"
            className="font-semibold text-lg text-[var(--accent)] hover:text-[var(--accent)] hover:no-underline"
          >
            Fubuki
          </Link>
          <span className="text-[var(--text-muted)] text-sm">Web UI</span>
        </div>
      </header>
      <main className="flex-1 w-full px-6 py-6">
        {children}
      </main>
    </>
  );
}
