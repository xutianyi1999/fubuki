import type { HeartbeatInfo, UdpStatus, Elapsed } from '@/types';

const VIEW_NAMES: Record<string, string> = {
  listen_addr: 'Listen address',
  virtual_addr: 'IP',
  lan_udp_addr: 'LAN address',
  wan_udp_addr: 'WAN address',
  mode: 'Protocol mode',
  addr: 'IP',
  server_addr: 'Server address',
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

export function parseUdpStatus(status: UdpStatus): string {
  if (typeof status === 'string') return status;
  const keys = Object.keys(status);
  return keys[0] ?? 'Unknown';
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
