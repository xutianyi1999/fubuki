import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { GroupListComponent } from './group-list/group-list.component';
import { GroupItemComponent } from './group-item/group-item.component';

const routes: Routes = [
  {
    path: '', pathMatch: 'full', component: GroupListComponent
  },
  // {
  //   path: '', pathMatch: 'full', redirectTo: 'group'
  // },
  {
    path: 'group', pathMatch: 'full', component: GroupListComponent
  },
  {
    path: 'group/:path', component: GroupItemComponent
  },
  {
    path: '**', redirectTo: ''
  }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
