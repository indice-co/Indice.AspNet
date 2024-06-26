import { Component } from '@angular/core';
import { TenantService } from '@indice/ng-auth';

import { settings } from 'src/app/core/models/settings';
import { IAppSettings } from './core/models/settings.model';

@Component({
  selector: 'app-root',
  template: `
    <lib-shell-layout [sidebarFooterTemplate]="sidebarFooter"></lib-shell-layout>
    <ng-template #sidebarFooter>
      <span>
        Powered by <a class="text-blue-400" href="https://www.indice.gr">Indice</a>
        <span class="ml-1" style="color: red">♥</span> 
      </span> v{{ settings.version }}
    </ng-template>
  `
})
export class AppComponent {
  constructor(tenantService: TenantService) {
    if (settings.tenantId && settings.tenantId !== '') {
      tenantService.storeTenant(settings.tenantId);
    }
  }

  public settings: IAppSettings = settings;
}
