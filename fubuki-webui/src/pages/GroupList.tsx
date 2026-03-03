import { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { fetchInfo, fetchServerType } from '@/api/client';
import type { GroupListItem } from '@/types';
import { groupDisplayName, isNodeListItem, isServerListItem } from '@/types';
import type { ServerType } from '@/api/client';
import { toLatency, toLossRate, hasHeartbeatData, latencyQualityClass, lossQualityClass, EMPTY } from '@/utils/format';

export function GroupList() {
  const [serverType, setServerType] = useState<ServerType | null>(null);
  const [groups, setGroups] = useState<GroupListItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setError(null);
    setLoading(true);
    Promise.all([fetchServerType(), fetchInfo<GroupListItem[]>()])
      .then(([type, list]) => {
        setServerType(type);
        setGroups(Array.isArray(list) ? list : []);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (error) {
    return (
      <div className="animate-fade-in rounded-xl bg-red-500/10 border border-red-500/20 px-5 py-4">
        <p className="text-red-300 font-medium">Failed to load</p>
        <p className="text-red-400/90 text-sm mt-1">{error}</p>
        <p className="text-[var(--text-muted)] text-sm mt-2">Ensure Fubuki is running and the API is reachable (typical ports 3030 or 3031).</p>
        <button
          type="button"
          onClick={() => window.location.reload()}
          className="mt-3 px-3 py-1.5 text-sm font-medium rounded-lg bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/30 focus:outline-none focus:ring-2 focus:ring-cyan-400/50"
        >
          Retry
        </button>
      </div>
    );
  }

  if (serverType == null || groups == null) {
    return (
      <div className="flex flex-col items-center justify-center py-24 gap-3" role="status" aria-live="polite" aria-busy="true">
        <div className="w-8 h-8 rounded-full border-2 border-cyan-500/50 border-t-cyan-400 animate-spin" aria-hidden="true" />
        <p className="text-[var(--text-muted)] text-sm">Loading…</p>
      </div>
    );
  }

  return (
    <div className="animate-fade-in">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-[var(--text)]">
            Fubuki {serverType === 'node' ? 'Node' : 'Server'}
          </h1>
          <p className="text-[var(--text-muted)] text-sm mt-1">
            Select a group to view peers and connection status
          </p>
        </div>
        <button
          type="button"
          onClick={load}
          disabled={loading}
          aria-label="Refresh list"
          className="flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-lg bg-[var(--surface-hover)] border border-[var(--border)] text-[var(--text)] hover:bg-cyan-500/15 hover:border-cyan-500/30 disabled:opacity-50 disabled:pointer-events-none focus:outline-none focus:ring-2 focus:ring-cyan-400/50"
        >
          <svg className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh
        </button>
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
          const nodeIndex = isNodeListItem(group) ? group.index : null;
          return (
            <li key={isNodeListItem(group) ? `${group.index}-${name}` : name}>
              <Link
                to={`/group/${encodeURIComponent(name)}`}
                className="flex items-center gap-4 rounded-xl bg-[var(--surface)] border border-[var(--border)] p-4 hover:bg-[var(--surface-hover)] hover:border-cyan-500/30 transition-all no-underline text-[var(--text)]"
              >
                <span className="flex-shrink-0 w-11 h-11 rounded-xl bg-cyan-500/15 flex flex-col items-center justify-center text-cyan-400">
                  {nodeIndex != null ? (
                    <span className="text-xs font-medium leading-none">{nodeIndex}</span>
                  ) : null}
                  <svg className="w-5 h-5 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
                  {isNodeListItem(group) && group.cidr ? (
                    <div className="text-xs text-[var(--text-muted)] font-mono truncate mt-0.5">
                      CIDR {group.cidr}
                    </div>
                  ) : null}
                  {isServerListItem(group) && group.address_range ? (
                    <div className="text-xs text-[var(--text-muted)] font-mono truncate mt-0.5" title="Address range">
                      Range {group.address_range}
                    </div>
                  ) : null}
                </div>
                <div className="flex flex-shrink-0 flex-col items-end gap-1">
                  {isNodeListItem(group) ? (
                    <>
                      <div className="flex items-center gap-2 text-xs" title="UDP: round-trip time and packet loss to server">
                        <span className="text-[var(--text-muted)]">UDP</span>
                        <span className={`font-mono ${latencyQualityClass(toLatency(group.server_udp_hc?.elapsed))}`} title="Round-trip time">
                          {toLatency(group.server_udp_hc?.elapsed) >= 0 ? `${Math.round(toLatency(group.server_udp_hc!.elapsed))} ms` : EMPTY}
                        </span>
                        <span className={`font-mono ${hasHeartbeatData(group.server_udp_hc) ? lossQualityClass(toLossRate(group.server_udp_hc)) : 'text-[var(--text-muted)]'}`} title="Packet loss rate">
                          {hasHeartbeatData(group.server_udp_hc) ? `${(toLossRate(group.server_udp_hc) * 100).toFixed(1)}% loss` : EMPTY}
                        </span>
                      </div>
                      {group.server_tcp_hc ? (
                        <div className="flex items-center gap-2 text-xs" title="TCP: round-trip time and packet loss to server">
                          <span className="text-[var(--text-muted)]">TCP</span>
                          <span className={`font-mono ${latencyQualityClass(toLatency(group.server_tcp_hc?.elapsed))}`} title="Round-trip time">
                            {toLatency(group.server_tcp_hc?.elapsed) >= 0 ? `${Math.round(toLatency(group.server_tcp_hc.elapsed))} ms` : EMPTY}
                          </span>
                          <span className={`font-mono ${hasHeartbeatData(group.server_tcp_hc) ? lossQualityClass(toLossRate(group.server_tcp_hc)) : 'text-[var(--text-muted)]'}`} title="Packet loss rate">
                            {hasHeartbeatData(group.server_tcp_hc) ? `${(toLossRate(group.server_tcp_hc) * 100).toFixed(1)}% loss` : EMPTY}
                          </span>
                        </div>
                      ) : null}
                    </>
                  ) : null}
                  <span className="text-xs text-[var(--text-muted)] bg-[var(--surface-hover)] px-2.5 py-1 rounded-md" title="Number of peers in this group">
                    {nodeCount} peer{nodeCount !== 1 ? 's' : ''}
                  </span>
                </div>
                <span className="text-[var(--text-muted)] opacity-60" aria-hidden="true">→</span>
              </Link>
            </li>
          );
        })}
      </ul>

      {groups.length === 0 && (
        <div className="rounded-xl border border-[var(--border)] border-dashed bg-[var(--surface)]/50 py-16 text-center">
          <p className="text-[var(--text-muted)]">No groups yet</p>
          <p className="text-sm text-[var(--text-muted)]/80 mt-1">
            {serverType === 'server'
              ? 'Groups will appear here after you start and configure Fubuki Server.'
              : 'Groups will appear here after you start and configure Fubuki.'}
          </p>
        </div>
      )}
    </div>
  );
}
