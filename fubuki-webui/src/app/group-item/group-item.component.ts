import { Component } from '@angular/core';
import { FubukiNodeService } from '../fubuki-node.service';
import { Observable } from 'rxjs';
import { group } from '@angular/animations';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-group-item',
  templateUrl: './group-item.component.html',
  styleUrls: ['./group-item.component.css']
})
export class GroupItemComponent {

  constructor(
    private fubukiNodeService: FubukiNodeService,
    private route: ActivatedRoute
  ) {

  }

  ngOnInit(): void {
    const routeParams = this.route.snapshot.paramMap;
    this.path = routeParams.get('path')!;


    this.getNodeMap();
  }

  groupColumns = ["group_name", "node_name", "addr", "server_addr", "server_is_connected"]
  // groupColumns = ["firstColumn", "group_name", "node_name", "addr", "server_addr", "server_is_connected"]
  nodeColumns = ["name", "virtual_addr", "lan_udp_addr", "wan_udp_addr"]

  path: string = "";  
  groupList: any;
  groupInfo: any;
  nodeMap: any;
  nodeList!: any[];

  getNodeMap(): void {
    let groupList = this.fubukiNodeService.getGroupList();
    groupList.subscribe(list => {
      // this.groupList = list;
      for (const groupInfo of list) {
        if (groupInfo.group_name === this.path) {
          this.groupInfo = groupInfo;
          this.nodeMap = groupInfo.node_map;
          this.nodeList = this.getNodeMapValues(this.nodeMap);
          this.groupList = [groupInfo];
        }
      }
    });
  }

  getNodeMapValues(nodeMap: any): any[] {
    return Object.values(nodeMap);
  }


}
