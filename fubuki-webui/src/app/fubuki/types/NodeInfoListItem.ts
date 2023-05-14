import { HeartbeatCache } from "./HeartbeatCache";
import { Mode } from "./Mode";
import { NodeStatus } from "./NodeStatus";
import { UdpStatus } from "./UdpStatus";

export interface NodeInfoListItem {
    index: number;
    node_name: string;
    group_name: string;
    addr: string;
    cidr: string;
    mode: Mode;
    server_addr: string;
    server_udp_status: UdpStatus;
    server_udp_hc: HeartbeatCache;
    server_tcp_hc: HeartbeatCache;
    server_is_connected: true;
    node_map: Map<string, NodeStatus>;
}