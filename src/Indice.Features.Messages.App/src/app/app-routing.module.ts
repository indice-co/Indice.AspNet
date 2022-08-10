import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

import { AuthCallbackComponent, AuthRenewComponent, PageNotFoundComponent } from '@indice/ng-components';
import { AuthGuardService } from '@indice/ng-auth';
import { CampaignContentEditComponent } from './features/campaigns/edit/content/campaign-edit-content.component';
import { CampaignCreateComponent } from './features/campaigns/create/campaign-create.component';
import { CampaignDetailsEditComponent } from './features/campaigns/edit/details/campaign-edit-details.component';
import { CampaignDetailsEditRightpaneComponent } from './features/campaigns/edit/details/rightpane/campaign-edit-details-rightpane.component';
import { CampaignEditComponent } from './features/campaigns/edit/campaign-edit.component';
import { CampaignReportsComponent } from './features/campaigns/edit/reports/campaign-reports.component';
import { CampaignsComponent } from './features/campaigns/campaigns.component';
import { DashboardComponent } from './features/dashboard/dashboard.component';
import { DistributionListContactCreateComponent } from './features/distribution-lists/contacts/create/distribution-list-contact-create.component';
import { DistributionListContactsComponent } from './features/distribution-lists/contacts/distribution-list-contacts.component';
import { DistributionListCreateComponent } from './features/distribution-lists/create/distribution-list-create.component';
import { DistributionListEditComponent } from './features/distribution-lists/edit/distribution-list-edit.component';
import { DistributionListsComponent } from './features/distribution-lists/distribution-lists.component';
import { HomeComponent } from './features/home/home.component';
import { LogOutComponent } from './core/services/logout/logout.component';
import { MessageTypeCreateComponent } from './features/message-types/create/message-type-create.component';
import { MessageTypeEditComponent } from './features/message-types/edit/message-type-edit.component';
import { MessageTypesComponent } from './features/message-types/message-types.component';
import { TemplatesComponent } from './features/templates/templates.component';

const routes: Routes = [
  { path: 'auth-callback', component: AuthCallbackComponent },
  { path: 'auth-renew', component: AuthRenewComponent },
  { path: '', redirectTo: 'home', pathMatch: 'full' },
  { path: 'home', component: HomeComponent, pathMatch: 'full', data: { shell: { fluid: true, showHeader: false, showFooter: false } } },
  {
    path: '', canActivate: [AuthGuardService], children: [
      { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
      { path: 'dashboard', component: DashboardComponent },
      { path: 'campaigns', component: CampaignsComponent },
      { path: 'campaigns/add', component: CampaignCreateComponent },
      {
        path: 'campaigns/:campaignId', component: CampaignEditComponent, children: [
          { path: '', redirectTo: 'details', pathMatch: 'full' },
          { path: 'details', component: CampaignDetailsEditComponent },
          { path: 'content', component: CampaignContentEditComponent },
          { path: 'reports', component: CampaignReportsComponent }
        ]
      },
      { path: 'message-types', component: MessageTypesComponent },
      { path: 'distribution-lists', component: DistributionListsComponent },
      { path: 'distribution-lists/:distributionListId/contacts', component: DistributionListContactsComponent },
      { path: 'templates', component: TemplatesComponent }
    ]
  },
  { path: 'edit-campaign', canActivate: [AuthGuardService], component: CampaignDetailsEditRightpaneComponent, outlet: 'rightpane', pathMatch: 'prefix' },
  { path: 'create-message-type', canActivate: [AuthGuardService], component: MessageTypeCreateComponent, outlet: 'rightpane', pathMatch: 'prefix' },
  { path: 'edit-message-type/:messageTypeId', canActivate: [AuthGuardService], component: MessageTypeEditComponent, outlet: 'rightpane', pathMatch: 'prefix' },
  { path: 'create-distribution-list', canActivate: [AuthGuardService], component: DistributionListCreateComponent, outlet: 'rightpane', pathMatch: 'prefix' },
  { path: 'edit-distribution-list/:distributionListId', canActivate: [AuthGuardService], component: DistributionListEditComponent, outlet: 'rightpane', pathMatch: 'prefix' },
  { path: 'create-distribution-list-contact', canActivate: [AuthGuardService], component: DistributionListContactCreateComponent, outlet: 'rightpane', pathMatch: 'prefix' },
  { path: 'logout', component: LogOutComponent, data: { shell: { fluid: true, showHeader: false, showFooter: false } } },
  { path: '**', component: PageNotFoundComponent, data: { shell: { fluid: true, showHeader: false, showFooter: false } } }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
