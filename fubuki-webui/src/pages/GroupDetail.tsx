import { useEffect, useState, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { fetchInfo, fetchServerType } from '@/api/client';
import type { GroupListItem, NodeStatus, NodeStatusServer } from '@/types';
import {
  groupDisplayName,
  isNodeListItem,
  isNodeStatusServer,
} from '@/types';
import type { ServerType } from '@/api/client';
import {
  toViewName,
  toLatency,
  toLossRate,
  parseUdpStatus,
  formatDate,
  joinStrings,
  ipv4ToSortKey,
  latencyQualityClass,
  lossQualityClass,
  EMPTY,
} from '@/utils/format';
import type { HeartbeatInfo, Mode } from '@/types';
import { CopyChip } from '@/components/CopyChip';

function getActiveModes(mode: Mode | null | undefined): string[] {
  if (mode == null) return [];
  return (Object.keys(mode) as (keyof Mode)[]).filter((k) => {
    const v = mode[k];
    return Array.isArray(v) && v.length > 0;
  });
}

function nodeListFromMap(nodeMap: Record<string, NodeStatus>): NodeStatus[] {
  const list = Object.values(nodeMap);
  const withVirtualAddr = list.filter((n) => n?.node?.virtual_addr);
  withVirtualAddr.sort(
    (a, b) => ipv4ToSortKey(a.node.virtual_addr) - ipv4ToSortKey(b.node.virtual_addr)
  );
  return withVirtualAddr;
}

function getNodeHc(node: NodeStatus): HeartbeatInfo {
  if (isNodeStatusServer(node)) return node.udp_heartbeat_cache;
  return node.hc;
}

export function GroupDetail() {
  const { path } = useParams<{ path: string }>();
  const pathName = path ?? '';
  const [serverType, setServerType] = useState<ServerType | null>(null);
  const [groupList, setGroupList] = useState<GroupListItem[] | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    Promise.all([fetchServerType(), fetchInfo<GroupListItem[]>()])
      .then(([type, list]) => {
        setServerType(type);
        setGroupList(Array.isArray(list) ? list : []);
        setLastUpdated(new Date());
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 3000);
    return () => clearInterval(id);
  }, [load]);

  const group = groupList?.find((g) => groupDisplayName(g) === pathName) ?? null;
  const nodeList = group
    ? nodeListFromMap(group.node_map as Record<string, NodeStatus>)
    : [];

  if (error) {
    return (
      <div className="rounded-xl bg-red-500/10 border border-red-500/20 px-5 py-4">
        <p className="text-red-300 font-medium">Failed to load</p>
        <p className="text-red-400/90 text-sm mt-1">{error}</p>
        <Link to="/" className="inline-block text-cyan-400 text-sm mt-2 hover:underline">Back to list</Link>
      </div>
    );
  }

  if (serverType == null || groupList == null) {
    return (
      <div className="flex flex-col items-center justify-center py-24 gap-3">
        <div className="w-8 h-8 rounded-full border-2 border-cyan-500/50 border-t-cyan-400 animate-spin" />
        <p className="text-[var(--text-muted)] text-sm">Loading…</p>
      </div>
    );
  }

  if (!group) {
    return (
      <div className="rounded-xl bg-amber-500/10 border border-amber-500/20 px-5 py-4">
        <p className="text-amber-300 font-medium">Group not found</p>
        <p className="text-amber-400/90 text-sm mt-1 font-mono">{pathName}</p>
        <Link to="/" className="inline-block text-cyan-400 text-sm mt-2 hover:underline">Back to list</Link>
      </div>
    );
  }

  const isNode = isNodeListItem(group);

  return (
    <div className="animate-fade-in space-y-8">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Link to="/" className="text-[var(--text-muted)] hover:text-[var(--accent)]">Fubuki {serverType === 'node' ? 'Node' : 'Server'}</Link>
        <span className="text-[var(--text-muted)]">/</span>
        <span className="text-[var(--text)] font-medium">{pathName}</span>
        {lastUpdated && (
          <span className="ml-auto text-xs text-[var(--text-muted)]" title="Data refreshes every 3 seconds">
            Updated {lastUpdated.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}
          </span>
        )}
      </div>

      <section>
        <h2 className="text-base font-semibold text-[var(--text)] mb-1">Group info</h2>
        <p className="text-[var(--text-muted)] text-sm mb-3">Basic config and connection status for this group</p>
        <div className="table-wrap rounded-xl border border-[var(--border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-[var(--surface)] border-b border-[var(--border)]">
                {isNode
                  ? (['group_name', 'node_name', 'server_is_connected', 'addr', 'server_addr'] as const).map((k) => (
                      <th key={k} className="text-left py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">
                        {k === 'server_is_connected' ? 'Connected' : toViewName(k)}
                      </th>
                    ))
                  : (['name', 'listen_addr', 'address_range'] as const).map((k) => (
                      <th key={k} className="text-left py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">
                        {toViewName(k)}
                      </th>
                    ))}
                <th className="text-left py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">Mode</th>
                {isNode && (
                  <>
                    <th className="text-left py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">UDP status</th>
                    <th className="text-right py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">UDP latency</th>
                    <th className="text-right py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">UDP loss</th>
                    <th className="text-right py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">TCP latency</th>
                    <th className="text-right py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">TCP loss</th>
                  </>
                )}
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-[var(--border)] hover:bg-[var(--surface-hover)]">
                {isNode ? (
                  <>
                    <td className="py-3 px-4 font-mono">{(group as import('@/types').NodeInfoListItem).group_name ?? EMPTY}</td>
                    <td className="py-3 px-4 font-mono">{(group as import('@/types').NodeInfoListItem).node_name}</td>
                    <td className="py-3 px-4">
                      <span className={(group as import('@/types').NodeInfoListItem).server_is_connected ? 'text-emerald-400' : 'text-red-400'}>
                        {(group as import('@/types').NodeInfoListItem).server_is_connected ? 'Yes' : 'No'}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono">{(group as import('@/types').NodeInfoListItem).addr}</td>
                    <td className="py-3 px-4 font-mono">{(group as import('@/types').NodeInfoListItem).server_addr}</td>
                  </>
                ) : (
                  <>
                    <td className="py-3 px-4 font-mono">{(group as import('@/types').ServerInfoListItem).name}</td>
                    <td className="py-3 px-4 font-mono">{(group as import('@/types').ServerInfoListItem).listen_addr}</td>
                    <td className="py-3 px-4 font-mono">{(group as import('@/types').ServerInfoListItem).address_range}</td>
                  </>
                )}
                <td className="py-3 px-4">
                  <div className="flex flex-wrap gap-1">
                    {getActiveModes(isNode ? (group as import('@/types').NodeInfoListItem).mode : null).map((m) => (
                      <CopyChip
                        key={m}
                        label={m}
                        copyText={joinStrings((isNode ? (group as import('@/types').NodeInfoListItem).mode : null)?.[m as keyof Mode] as string[])}
                      />
                    ))}
                  </div>
                </td>
                {isNode && (
                  <>
                    <td className="py-3 px-4">
                      <CopyChip
                        label={parseUdpStatus((group as import('@/types').NodeInfoListItem).server_udp_status)}
                        copyText={JSON.stringify((group as import('@/types').NodeInfoListItem).server_udp_status)}
                      />
                    </td>
                    <td className="py-3 px-4 text-right font-mono">
                      {(() => {
                        const lat = toLatency((group as import('@/types').NodeInfoListItem).server_udp_hc?.elapsed);
                        return lat >= 0 ? <span className={latencyQualityClass(lat)}>{lat.toFixed(0)} ms</span> : EMPTY;
                      })()}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <CopyChip
                        label={`${(toLossRate((group as import('@/types').NodeInfoListItem).server_udp_hc) * 100).toFixed(2)}%`}
                        copyText={JSON.stringify((group as import('@/types').NodeInfoListItem).server_udp_hc)}
                        qualityClass={lossQualityClass(toLossRate((group as import('@/types').NodeInfoListItem).server_udp_hc))}
                      />
                    </td>
                    <td className="py-3 px-4 text-right font-mono">
                      {(group as import('@/types').NodeInfoListItem).server_tcp_hc
                        ? (() => {
                            const lat = toLatency((group as import('@/types').NodeInfoListItem).server_tcp_hc?.elapsed);
                            return lat >= 0 ? <span className={latencyQualityClass(lat)}>{lat.toFixed(0)} ms</span> : EMPTY;
                          })()
                        : EMPTY}
                    </td>
                    <td className="py-3 px-4 text-right">
                      {(group as import('@/types').NodeInfoListItem).server_tcp_hc ? (
                        <CopyChip
                          label={`${(toLossRate((group as import('@/types').NodeInfoListItem).server_tcp_hc!) * 100).toFixed(2)}%`}
                          copyText={JSON.stringify((group as import('@/types').NodeInfoListItem).server_tcp_hc)}
                          qualityClass={lossQualityClass(toLossRate((group as import('@/types').NodeInfoListItem).server_tcp_hc!))}
                        />
                      ) : (
                        EMPTY
                      )}
                    </td>
                  </>
                )}
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2 className="text-base font-semibold text-[var(--text)] mb-1">Node list</h2>
        <p className="text-[var(--text-muted)] text-sm mb-3">{nodeList.length} node(s). Latency and loss refresh every 3s.</p>
        <div className="table-wrap rounded-xl border border-[var(--border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-[var(--surface)] border-b border-[var(--border)]">
                <th className="w-8 py-3 px-2" />
                <th className="text-left py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">Name</th>
                <th className="text-left py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">Virtual IP</th>
                <th className="text-left py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">UDP status</th>
                {isNode ? (
                  <>
                    <th className="text-right py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">Latency</th>
                    <th className="text-right py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">Loss</th>
                  </>
                ) : (
                  <>
                    <th className="text-right py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">UDP latency</th>
                    <th className="text-right py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">UDP loss</th>
                    <th className="text-right py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">TCP latency</th>
                    <th className="text-right py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">TCP loss</th>
                  </>
                )}
                <th className="text-left py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">LAN address</th>
                <th className="text-left py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">WAN address</th>
                <th className="text-left py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">Mode</th>
                <th className="text-left py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">Allowed IPs</th>
                <th className="text-left py-3 px-4 text-[var(--text-muted)] font-medium text-xs uppercase tracking-wider">Registered</th>
              </tr>
            </thead>
            <tbody>
              {nodeList.length === 0 ? (
                <tr>
                  <td colSpan={20} className="py-12 text-center text-[var(--text-muted)] text-sm">
                    No nodes in this group
                  </td>
                </tr>
              ) : nodeList.map((nodeStatus) => {
                const n = nodeStatus.node;
                const hc = getNodeHc(nodeStatus);
                return (
                  <tr key={n.virtual_addr} className="border-b border-[var(--border)] hover:bg-[var(--surface-hover)]">
                    <td className="py-2 px-2 text-cyan-400">
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                      </svg>
                    </td>
                    <td className="py-2 px-4 font-mono">{n.name}</td>
                    <td className="py-2 px-4 font-mono">{n.virtual_addr}</td>
                    <td className="py-2 px-4">
                      <CopyChip
                        label={parseUdpStatus(nodeStatus.udp_status)}
                        copyText={JSON.stringify(nodeStatus.udp_status)}
                      />
                    </td>
                    {isNode ? (
                      <>
                        <td className="py-2 px-4 text-right font-mono">
                          {hc && toLatency(hc.elapsed) >= 0 ? (
                            <span className={latencyQualityClass(toLatency(hc.elapsed))}>{toLatency(hc.elapsed).toFixed(0)} ms</span>
                          ) : (
                            EMPTY
                          )}
                        </td>
                        <td className="py-2 px-4 text-right">
                          {hc ? (
                            <CopyChip
                              label={`${(toLossRate(hc) * 100).toFixed(2)}%`}
                              copyText={JSON.stringify(hc)}
                              qualityClass={lossQualityClass(toLossRate(hc))}
                            />
                          ) : (
                            EMPTY
                          )}
                        </td>
                      </>
                    ) : isNodeStatusServer(nodeStatus) ? (
                      <>
                        <td className="py-2 px-4 text-right font-mono">
                          {(() => {
                            const lat = toLatency((nodeStatus as NodeStatusServer).udp_heartbeat_cache?.elapsed);
                            return lat >= 0 ? <span className={latencyQualityClass(lat)}>{lat.toFixed(0)} ms</span> : EMPTY;
                          })()}
                        </td>
                        <td className="py-2 px-4 text-right">
                          <CopyChip
                            label={`${(toLossRate((nodeStatus as NodeStatusServer).udp_heartbeat_cache!) * 100).toFixed(2)}%`}
                            copyText={JSON.stringify((nodeStatus as NodeStatusServer).udp_heartbeat_cache)}
                            qualityClass={lossQualityClass(toLossRate((nodeStatus as NodeStatusServer).udp_heartbeat_cache!))}
                          />
                        </td>
                        <td className="py-2 px-4 text-right font-mono">
                          {(() => {
                            const lat = toLatency((nodeStatus as NodeStatusServer).tcp_heartbeat_cache?.elapsed);
                            return lat >= 0 ? <span className={latencyQualityClass(lat)}>{lat.toFixed(0)} ms</span> : EMPTY;
                          })()}
                        </td>
                        <td className="py-2 px-4 text-right">
                          <CopyChip
                            label={`${(toLossRate((nodeStatus as NodeStatusServer).tcp_heartbeat_cache!) * 100).toFixed(2)}%`}
                            copyText={JSON.stringify((nodeStatus as NodeStatusServer).tcp_heartbeat_cache)}
                            qualityClass={lossQualityClass(toLossRate((nodeStatus as NodeStatusServer).tcp_heartbeat_cache!))}
                          />
                        </td>
                      </>
                    ) : null}
                    <td className="py-2 px-4 font-mono text-[var(--text-muted)]">{n.lan_udp_addr || EMPTY}</td>
                    <td className="py-2 px-4 font-mono text-[var(--text-muted)]">{n.wan_udp_addr || EMPTY}</td>
                    <td className="py-2 px-4">
                      <div className="flex flex-wrap gap-1">
                        {getActiveModes(n.mode).length > 0 ? getActiveModes(n.mode).map((m) => (
                          <CopyChip
                            key={m}
                            label={m}
                            copyText={joinStrings((n.mode as Mode)?.[m as keyof Mode] as string[])}
                          />
                        )) : EMPTY}
                      </div>
                    </td>
                    <td className="py-2 px-4">
                      <div className="flex flex-wrap gap-1">
                        {(n.allowed_ips ?? []).length > 0 ? (n.allowed_ips ?? []).map((ip) => (
                          <CopyChip key={ip} label={ip} copyText={ip} />
                        )) : EMPTY}
                      </div>
                    </td>
                    <td className="py-2 px-4 font-mono text-[var(--text-muted)]" title={new Date(n.register_time * 1000).toISOString()}>
                      {formatDate(n.register_time)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
