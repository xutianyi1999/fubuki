import { Component, ViewChild } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatAccordion } from '@angular/material/expansion';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';

@Component({
  selector: 'app-main-container',
  templateUrl: './main-container.component.html',
  styleUrls: ['./main-container.component.css']
})
export class MainContainerComponent {


  panelOpenState = false;

  groupColumns = ["group_name", "node_name", "addr", "server_addr", "server_is_connected"]
  nodeColumns = ["name", "virtual_addr", "lan_udp_addr", "wan_udp_addr"]

  constructor(private http: HttpClient) {
    
    const obj: any = {"10.0.0.1": {"node": {"name": "zx7"}}};
    console.log(obj);
    console.log(Object.values(obj));

    this.getInfo();
  }

  info: any;
  nodeMap: any;

  getInfo() {
    this.http.get('/info')
      .subscribe(info => {
        this.info = info;
        console.log(this.info);
        console.log(Object.values(this.info[0]["node_map"]));
      });
  }

  getNodeMapValues(nodeMap: any): any {
    return Object.values(nodeMap);
  }


  test() {
    const map: Map<string, any> = new Map();
    map.set("10.0.0.1", { node: { name: "zx7" } });
    console.log(map);
  }

}
