import { HttpClient } from '@angular/common/http';
import { Component } from '@angular/core';
import { FubukiNodeService } from '../fubuki/fubuki.service';
import { Observable } from 'rxjs';

@Component({
  selector: 'app-info-list',
  templateUrl: './info-list.component.html',
  styleUrls: ['./info-list.component.css']
})
export class InfoListComponent {

  constructor(
    private fubukiNodeService: FubukiNodeService
  ) {
    
  }

  ngOnInit(): void {
    this.groupList = this.fubukiNodeService.getInfo();
    this.fubukiNodeService.getServerType().subscribe(serverType => {
      this.serverType = serverType;
      this.groupNameFieldName = serverType === "node" ? "group_name" : "name"
    });
  }

  serverType!: string;
  groupNameFieldName!: string;
  groupList!: Observable<any[]>;

}
