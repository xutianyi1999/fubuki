import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, lastValueFrom } from 'rxjs';
import { NodeInfoListItem } from './types/NodeInfoListItem';
import { NodeInfo } from './types/NodeInfo';

@Injectable({
  providedIn: 'root'
})
export class FubukiNodeService {

  constructor(private http: HttpClient) {

  }

  info!: NodeInfoListItem[];

  getInfo(): Observable<Object[]> {
    return this.http.get('/info') as Observable<Object[]>;
  }

  getServerType(): Observable<string> {
    https://stackoverflow.com/questions/58941004/unexpected-token-o-in-json-at-position-0-when-i-query-an-api
    return this.http.get("/type", {responseType: "text"}) as Observable<string>;
  }

  getGroupList(): Observable<NodeInfoListItem[]> {
    //https://rxjs.dev/deprecations/to-promise
    // return lastValueFrom(this.http.get("/info"));

    return this.http.get("/info") as Observable<NodeInfoListItem[]>;
  }
  
}
