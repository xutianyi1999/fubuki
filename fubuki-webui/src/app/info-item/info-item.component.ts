import { Component } from '@angular/core';
import { FubukiNodeService } from '../fubuki/fubuki.service';
import { ActivatedRoute } from '@angular/router';
import { NodeInfoListItem } from '../fubuki/types/NodeInfoListItem';
import { NodeStatus } from '../fubuki/types/NodeStatus';
import { Clipboard } from '@angular/cdk/clipboard';

@Component({
  selector: 'app-info-item',
  templateUrl: './info-item.component.html',
  styleUrls: ['./info-item.component.css']
})
export class InfoItemComponent {

  constructor(
    private fubukiNodeService: FubukiNodeService,
    private route: ActivatedRoute,
    private clipboard: Clipboard
  ) {

  }

  ngOnInit(): void {
    const routeParams = this.route.snapshot.paramMap;
    this.path = routeParams.get('path')!;

    //如果getNodeMap()和getServerType()交换顺序, 会导致MatTable读取数据时报错, 然后在后续正确渲染
    //可能是因为获取到columns数据之后, MatTable就会开始从实际列表中读取数据, 导致错误
    this.getNodeMap();
    this.fubukiNodeService.getServerType().subscribe(serverType => {
      this.serverType = serverType;
      if(serverType === "node") {
        this.basicGroupColumns = ["group_name", "node_name", "addr", "server_addr", "server_is_connected"];
        this.groupHcColumns = ["server_udp_hc", "server_tcp_hc"];
        this.viewGroupColumns = [
          "group_name", "node_name", "addr", "server_addr", "server_is_connected",
          "mode", "server_udp_status", "server_udp_hc", "server_tcp_hc"
        ];

        this.basicNodeColumns = ["name", "virtual_addr", "lan_udp_addr", "wan_udp_addr"]
        this.nodeHcColumns = ["hc"];
        this.viewNodeColumns = [
          "name", "virtual_addr", "lan_udp_addr", "wan_udp_addr",
          "mode", "allowed_ips", "udp_status", "hc"
        ];
        // JSON.stringify(this.viewGroupColumns);
      } else if(serverType === "server") {
        this.basicGroupColumns = ["name", "listen_addr", "address_range"];
        this.groupHcColumns = [];
        this.viewGroupColumns = ["name", "listen_addr", "address_range"];
        
        this.basicNodeColumns = ["name", "virtual_addr", "lan_udp_addr", "wan_udp_addr"]
        this.nodeHcColumns = ["udp_heartbeat_cache", "tcp_heartbeat_cache"];
        this.viewNodeColumns = [
          "name", "virtual_addr", "lan_udp_addr", "wan_udp_addr", 
          "mode", "allowed_ips", "udp_status", "udp_heartbeat_cache", "tcp_heartbeat_cache"
        ];
      }
    })
  }

  viewGroupColumns!: string[];
  basicGroupColumns!: string[];
  groupHcColumns!: string[];
  viewNodeColumns!: string[];
  basicNodeColumns!: string[];
  nodeHcColumns!: string[];

  path: string = "";  
  serverType!: string;

  groupList!: any[];
  groupInfo!: NodeInfoListItem;
  nodeMap!: Map<string, NodeStatus>;
  nodeList!: NodeStatus[];

  getNodeMap(): void {
    this.fubukiNodeService.getInfo().subscribe(list => {
      // this.groupList = list as any[];
      for (const groupInfo of list as any[]) {
        if (groupInfo.group_name === this.path || groupInfo.name === this.path) {
          this.groupInfo = groupInfo;
          this.nodeMap = groupInfo.node_map;
          this.nodeList = this.getNodeMapValues(this.nodeMap)
            .sort((item1, item2) => 
              this.ipv4AddressToNumber(item1.node.virtual_addr) - this.ipv4AddressToNumber(item2.node.virtual_addr)
            );
          this.groupList = [groupInfo];
        }
      }
    });
  }

  ipv4AddressToNumber(ipv4Address: string): number {
    const str = ipv4Address.split(".")
      .map(s => (`000${s}`).slice(-3))
      .reduce((a, e) => (a + e))
    return Number(str);
  }

  getNodeMapValues(nodeMap: Map<string, NodeStatus>): NodeStatus[] {
    return Object.values(nodeMap);
  }

  toJsonString(obj: Object): string {
    return JSON.stringify(obj);
  }

  toKeyValueString(obj: Object): string {
    return Object.entries(obj)
      .map(entry => entry[0] + ": " + entry[1])
      .reduce((a, e) => a + ", " + e);
  }

  reduceStringArray(stringArray: string[]): string {
    return stringArray.reduce((a, e) => a + ", " + e);
  }

  getKeys(obj: Object): string[] {
    return Object.keys(obj);
  }

  copy(text: string): void {
    this.clipboard.copy(text);
  }

}
