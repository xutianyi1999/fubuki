import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { InfoListComponent } from './info-list/info-list.component';
import { InfoItemComponent } from './info-item/info-item.component';

const routes: Routes = [
  {
    path: '', pathMatch: 'full', component: InfoListComponent
  },
  // {
  //   path: '', pathMatch: 'full', redirectTo: 'group'
  // },
  {
    path: 'group', pathMatch: 'full', component: InfoListComponent
  },
  {
    path: 'group/:path', component: InfoItemComponent
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
