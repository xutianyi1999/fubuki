import type { HeartbeatInfo, UdpStatus, Elapsed } from '@/types';

const VIEW_NAMES: Record<string, string> = {
  name: 'Group name',
  listen_addr: 'Listen address',
  virtual_addr: 'Virtual IP',
  lan_udp_addr: 'LAN address',
  wan_udp_addr: 'WAN address',
  mode: 'Protocol',
  addr: 'Local IP',
  address_range: 'Address range',
  server_addr: 'Server address',
  cidr: 'CIDR',
  index: 'Index',
  server_is_connected: 'Connected',
  udp_path: 'UDP path',
  udp_to_peer: 'UDP',  // server: direct or relay to peer
  udp_rtt: 'UDP RTT',
  udp_loss: 'UDP loss',
  tcp_rtt: 'TCP RTT',
  tcp_loss: 'TCP loss',
  udp_rtt_relay: 'UDP RTT (relay)',
  udp_loss_relay: 'UDP loss (relay)',
  tcp_rtt_relay: 'TCP RTT (relay)',
  tcp_loss_relay: 'TCP loss (relay)',
  latency: 'RTT',
  loss: 'Loss',
  allowed_ips: 'Allowed IPs',
  register_time: 'Registered',
};

export function toViewName(fieldName: string): string {
  return VIEW_NAMES[fieldName] ?? fieldName;
}

/** Consistent placeholder for empty/null values in tables */
export const EMPTY = '—';

export function toLatency(elapsed: Elapsed | null | undefined): number {
  if (elapsed == null) return -1;
  const secs = (elapsed as { secs?: number }).secs ?? 0;
  const nanos = (elapsed as { nanos?: number }).nanos ?? 0;
  return secs * 1000 + nanos / 1_000_000;
}

export function toLossRate(hc: HeartbeatInfo): number {
  if (hc.send_count === 0) return 0;
  return hc.packet_loss_count / hc.send_count;
}

/** Whether heartbeat has any data (avoids showing "0% loss" when no packets sent) */
export function hasHeartbeatData(hc: HeartbeatInfo): boolean {
  return (hc?.send_count ?? 0) > 0;
}

/** Tooltip text for heartbeat: send count, loss, continuous loss/recv */
export function formatHeartbeatTooltip(hc: HeartbeatInfo): string {
  const sent = hc.send_count;
  const loss = hc.packet_loss_count;
  const contLoss = hc.packet_continuous_loss_count ?? 0;
  const contRecv = hc.packet_continuous_recv_count ?? 0;
  const parts = [`Sent: ${sent}`, `Loss: ${loss}`];
  if (contLoss > 0 || contRecv > 0) {
    parts.push(`Continuous loss: ${contLoss}`, `Continuous recv: ${contRecv}`);
  }
  return parts.join(' · ');
}

/** Human-readable UDP path: Node = Direct / Via relay; Server = Available / Unavailable (relay to peer). */
export function parseUdpStatus(status: UdpStatus, isServer?: boolean): string {
  if (isServer) {
    if (typeof status === 'string') return status === 'Available' ? 'Available' : status === 'Unavailable' ? 'Unavailable' : status;
    const s = status as Record<string, unknown>;
    if (s.Available && typeof s.Available === 'object' && (s.Available as { dst_addr?: string }).dst_addr) return 'Available';
    return 'Unavailable';
  }
  if (typeof status === 'string') {
    return status === 'Available' ? 'Direct' : status === 'Unavailable' ? 'Via relay' : status;
  }
  if (status && typeof status === 'object') {
    const s = status as Record<string, unknown>;
    if (s.Available && typeof s.Available === 'object' && (s.Available as { dst_addr?: string }).dst_addr) return 'Direct';
    if ('Unavailable' in s || (Object.keys(s)[0] === 'Unavailable')) return 'Via relay';
    const key = Object.keys(s)[0];
    return key === 'Available' ? 'Direct' : key === 'Unavailable' ? 'Via relay' : key ?? '—';
  }
  return '—';
}

/** Copy/tooltip label. Server: "Available" or "Unavailable"; Node: "Direct (addr)" or "Via relay". */
export function udpStatusCopyLabel(status: UdpStatus, isServer?: boolean): string {
  if (isServer) return parseUdpStatus(status, true);
  if (typeof status === 'string') {
    return status === 'Available' ? 'Direct' : status === 'Unavailable' ? 'Via relay' : status;
  }
  const s = status as Record<string, { dst_addr?: string } | unknown>;
  if (s?.Available?.dst_addr) return `Direct (${s.Available.dst_addr})`;
  return parseUdpStatus(status, false);
}

export function formatDate(sec: number): string {
  return new Date(sec * 1000).toLocaleString('sv-SE', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).replace(' ', ' ');
}

export function joinStrings(arr: string[] | null | undefined): string {
  if (arr == null || arr.length === 0) return '';
  return arr.join(', ');
}

export function ipv4ToSortKey(addr: string): number {
  const parts = addr.split('.').map((s) => (`000${s}`).slice(-3));
  return Number(parts.join('')) || 0;
}

/** Latency quality for styling: good &lt; 100ms, warning &lt; 300ms, bad otherwise */
export function latencyQualityClass(latencyMs: number): 'text-emerald-400' | 'text-amber-400' | 'text-red-400' | '' {
  if (latencyMs < 0) return '';
  if (latencyMs < 100) return 'text-emerald-400';
  if (latencyMs < 300) return 'text-amber-400';
  return 'text-red-400';
}

/** Loss rate quality for styling: good 0, warning &lt; 5%, bad otherwise */
export function lossQualityClass(rate: number): 'text-emerald-400' | 'text-amber-400' | 'text-red-400' {
  if (rate <= 0) return 'text-emerald-400';
  if (rate < 0.05) return 'text-amber-400';
  return 'text-red-400';
}
