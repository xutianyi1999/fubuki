import { NodeStatus } from "./NodeStatus";

export interface ServerInfoListItem {
    name: string;
    listen_addr: string;
    address_range: string;
    node_map: Map<string, NodeStatus>
}