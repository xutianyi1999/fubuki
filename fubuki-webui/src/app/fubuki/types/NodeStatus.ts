import { HeartbeatCache } from "./HeartbeatCache";
import { NodeInfo } from "./NodeInfo";
import { UdpStatus } from "./UdpStatus";

export interface NodeStatus {
    node: NodeInfo;
    udp_status: UdpStatus | string;
    udp_hearbeat_cache: HeartbeatCache;
    tcp_hearbeat_cache: HeartbeatCache;
}