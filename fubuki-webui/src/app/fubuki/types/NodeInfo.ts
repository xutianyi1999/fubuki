import { Mode } from "./Mode";

export interface NodeInfo {
    name: string;
    virtual_addr: string;
    lan_udp_addr: string;
    wan_udp_addr: string;
    mode: Mode;
    allowed_ips: string[];
    register_time: number;
    register_nonce: number;
}