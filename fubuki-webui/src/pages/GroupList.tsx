import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { fetchInfo, fetchServerType } from '@/api/client';
import type { GroupListItem } from '@/types';
import { groupDisplayName } from '@/types';
import type { ServerType } from '@/api/client';

export function GroupList() {
  const [serverType, setServerType] = useState<ServerType | null>(null);
  const [groups, setGroups] = useState<GroupListItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([fetchServerType(), fetchInfo<GroupListItem[]>()])
      .then(([type, list]) => {
        if (!cancelled) {
          setServerType(type);
          setGroups(Array.isArray(list) ? list : []);
        }
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => { cancelled = true; };
  }, []);

  if (error) {
    return (
      <div className="animate-fade-in rounded-xl bg-red-500/10 border border-red-500/20 px-5 py-4">
        <p className="text-red-300 font-medium">Failed to load</p>
        <p className="text-red-400/90 text-sm mt-1">{error}</p>
        <p className="text-[var(--text-muted)] text-sm mt-2">Ensure Fubuki is running and the API address is correct (default port 3031).</p>
      </div>
    );
  }

  if (serverType == null || groups == null) {
    return (
      <div className="flex flex-col items-center justify-center py-24 gap-3">
        <div className="w-8 h-8 rounded-full border-2 border-cyan-500/50 border-t-cyan-400 animate-spin" />
        <p className="text-[var(--text-muted)] text-sm">Loading…</p>
      </div>
    );
  }

  return (
    <div className="animate-fade-in">
      <div className="mb-6">
        <h1 className="text-xl font-semibold text-[var(--text)]">
          Fubuki {serverType === 'node' ? 'Node' : 'Server'}
        </h1>
        <p className="text-[var(--text-muted)] text-sm mt-1">
          Select a group to view nodes and connection status
        </p>
      </div>

      <ul className="space-y-3">
        {groups.map((group) => {
          const name = groupDisplayName(group);
          const subtitle =
            'server_addr' in group
              ? group.server_addr
              : 'listen_addr' in group
                ? group.listen_addr
                : '';
          const nodeCount = group.node_map ? Object.keys(group.node_map).length : 0;
          return (
            <li key={name}>
              <Link
                to={`/group/${encodeURIComponent(name)}`}
                className="flex items-center gap-4 rounded-xl bg-[var(--surface)] border border-[var(--border)] p-4 hover:bg-[var(--surface-hover)] hover:border-cyan-500/30 transition-all no-underline text-[var(--text)]"
              >
                <span className="flex-shrink-0 w-11 h-11 rounded-xl bg-cyan-500/15 flex items-center justify-center text-cyan-400">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                </span>
                <div className="min-w-0 flex-1">
                  <div className="font-medium truncate">{name}</div>
                  {subtitle && (
                    <div className="text-sm text-[var(--text-muted)] font-mono truncate mt-0.5">
                      {subtitle}
                    </div>
                  )}
                </div>
                <span className="flex-shrink-0 text-xs text-[var(--text-muted)] bg-[var(--surface-hover)] px-2.5 py-1 rounded-md">
                  {nodeCount} node{nodeCount !== 1 ? 's' : ''}
                </span>
                <span className="text-[var(--text-muted)] opacity-60">→</span>
              </Link>
            </li>
          );
        })}
      </ul>

      {groups.length === 0 && (
        <div className="rounded-xl border border-[var(--border)] border-dashed bg-[var(--surface)]/50 py-16 text-center">
          <p className="text-[var(--text-muted)]">No groups yet</p>
          <p className="text-sm text-[var(--text-muted)]/80 mt-1">Groups will appear here after you start and configure Fubuki</p>
        </div>
      )}
    </div>
  );
}
