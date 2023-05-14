import { Component } from '@angular/core';
import { FubukiNodeService } from '../fubuki/fubuki.service';
import { ActivatedRoute } from '@angular/router';
import { NodeInfoListItem } from '../fubuki/types/NodeInfoListItem';
import { NodeStatus } from '../fubuki/types/NodeStatus';

@Component({
  selector: 'app-info-item',
  templateUrl: './info-item.component.html',
  styleUrls: ['./info-item.component.css']
})
export class InfoItemComponent {

  constructor(
    private fubukiNodeService: FubukiNodeService,
    private route: ActivatedRoute
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
        this.groupColumns = ["group_name", "node_name", "addr", "server_addr", "server_is_connected"];
        this.nodeColumns = ["name", "virtual_addr", "lan_udp_addr", "wan_udp_addr"]
      } else if(serverType === "server") {
        this.groupColumns = ["name", "listen_addr", "address_range"];
        this.nodeColumns = ["name", "virtual_addr", "lan_udp_addr", "wan_udp_addr"]
      }
    })
  }

  groupColumns!: string[];
  nodeColumns!: string[];

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
          this.nodeList = this.getNodeMapValues(this.nodeMap);
          this.groupList = [groupInfo];
        }
      }
    });
  }

  getNodeMapValues(nodeMap: Map<string, NodeStatus>): NodeStatus[] {
    return Object.values(nodeMap);
  }

}
