/** Elapsed time from Rust (secs + nanos) or serialized duration */
export interface Elapsed {
  secs?: number;
  nanos?: number;
}

export interface HeartbeatInfo {
  elapsed: Elapsed | null;
  send_count: number;
  packet_continuous_loss_count: number;
  packet_continuous_recv_count: number;
  packet_loss_count: number;
}

export type UdpStatus =
  | string
  | { Available: { dst_addr: string } }
  | { Unavailable?: unknown };

export interface Mode {
  p2p?: string[];
  relay?: string[];
}

export interface NodeInfo {
  name: string;
  virtual_addr: string;
  lan_udp_addr: string;
  wan_udp_addr: string;
  mode: Mode;
  allowed_ips: string[];
  register_time: number;
  register_nonce?: number;
}

/** Node-side: node map entry has `hc` */
export interface NodeStatusNode {
  node: NodeInfo;
  udp_status: UdpStatus;
  hc: HeartbeatInfo;
}

/** Server-side: node map entry has udp_heartbeat_cache, tcp_heartbeat_cache */
export interface NodeStatusServer {
  node: NodeInfo;
  udp_status: UdpStatus;
  udp_heartbeat_cache: HeartbeatInfo;
  tcp_heartbeat_cache: HeartbeatInfo;
}

export type NodeStatus = NodeStatusNode | NodeStatusServer;

export function isNodeStatusServer(s: NodeStatus): s is NodeStatusServer {
  return 'udp_heartbeat_cache' in s;
}

/** Node API: group row */
export interface NodeInfoListItem {
  index: number;
  node_name: string;
  group_name: string | null;
  addr: string;
  cidr: string;
  mode: Mode;
  server_addr: string;
  server_udp_status: UdpStatus;
  server_udp_hc: HeartbeatInfo;
  server_tcp_hc?: HeartbeatInfo;
  server_is_connected: boolean;
  node_map: Record<string, NodeStatusNode>;
}

/** Server API: group row */
export interface ServerInfoListItem {
  name: string;
  listen_addr: string;
  address_range: string;
  node_map: Record<string, NodeStatusServer>;
}

export type GroupListItem = NodeInfoListItem | ServerInfoListItem;

export function isNodeListItem(g: GroupListItem): g is NodeInfoListItem {
  return 'group_name' in g;
}

export function isServerListItem(g: GroupListItem): g is ServerInfoListItem {
  return 'listen_addr' in g;
}

export function groupDisplayName(g: GroupListItem): string {
  if (isNodeListItem(g)) return g.group_name ?? g.node_name;
  return g.name;
}
