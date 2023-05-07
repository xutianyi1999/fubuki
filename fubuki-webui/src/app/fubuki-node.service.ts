import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, lastValueFrom } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class FubukiNodeService {

  constructor(private http: HttpClient) {

    // const obj: any = { "10.0.0.1": { "node": { "name": "zx7" } } };
    // console.log(obj);
    // console.log(Object.values(obj));

    // this.getInfo();
  }

  groupColumns = ["group_name", "node_name", "addr", "server_addr", "server_is_connected"]
  nodeColumns = ["name", "virtual_addr", "lan_udp_addr", "wan_udp_addr"]

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

  getGroupList(): Observable<any> {
    //https://rxjs.dev/deprecations/to-promise
    // return lastValueFrom(this.http.get("/info"));

    return this.http.get("/info");
  }

  getNodeMapValues(nodeMap: any): any {
    return Object.values(nodeMap);
  }


  
}
