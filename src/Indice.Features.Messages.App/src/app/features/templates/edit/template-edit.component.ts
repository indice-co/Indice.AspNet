import { AfterViewChecked, ChangeDetectorRef, Component, OnInit, ViewChild } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

import { HeaderMetaItem, ViewLayoutComponent } from '@indice/ng-components';
import { Template } from 'src/app/core/services/messages-api.service';
import { TemplateEditStore } from './template-edit-store.service';
import { TranslateService } from '@ngx-translate/core';

@Component({
    selector: 'app-template-edit',
    templateUrl: './template-edit.component.html'
})
export class TemplateEditComponent implements OnInit, AfterViewChecked {
    @ViewChild('layout', { static: true }) private _layout!: ViewLayoutComponent;
    private _templateId?: string;

    constructor(
        private _activatedRoute: ActivatedRoute,
        private _translate: TranslateService,
        private _changeDetector: ChangeDetectorRef,
        private _templateStore: TemplateEditStore
    ) { }

    public submitInProgress = false;
    public template: Template | undefined;
    public metaItems: HeaderMetaItem[] = [];

    public ngOnInit(): void {
        this._templateId = this._activatedRoute.snapshot.params['templateId'];
        if (this._templateId) {
            this._templateStore.getTemplate(this._templateId!).subscribe((template: Template) => {
                this.template = template;
                this._layout.title = `'${this._translate.instant('templates.edit.layout-title')}' - ${template.name}`;
            });
        }
    }

    public ngAfterViewChecked(): void {
        this._changeDetector.detectChanges();
    }
}
