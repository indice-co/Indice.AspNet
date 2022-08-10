import { AfterViewChecked, ChangeDetectorRef, Component, Inject, OnInit, ViewChild } from '@angular/core';
import { Router } from '@angular/router';

import { HeaderMetaItem, Icons, LibStepperComponent, StepperType, ToasterService, ToastType } from '@indice/ng-components';
import { StepSelectedEvent } from '@indice/ng-components/lib/controls/stepper/types/step-selected-event';
import { CampaignBasicInfoComponent } from './steps/basic-info/campaign-basic-info.component';
import { CampaignContentComponent } from './steps/content/campaign-content.component';
import { CampaignPreview } from './steps/preview/campaign-preview';
import { CampaignPreviewComponent } from './steps/preview/campaign-preview.component';
import { CampaignRecipientsComponent } from './steps/recipients/campaign-recipients.component';
import { CreateCampaignRequest, MessagesApiClient, MessageChannelKind, Period, Hyperlink, Campaign, MessageContent, Template } from 'src/app/core/services/messages-api.service';
import { UtilitiesService } from 'src/app/shared/utilities.service';

@Component({
    selector: 'app-campaign-create',
    templateUrl: './campaign-create.component.html'
})
export class CampaignCreateComponent implements OnInit, AfterViewChecked {
    @ViewChild('createCampaignStepper', { static: true }) private _stepper!: LibStepperComponent;
    @ViewChild('basicInfoStep', { static: true }) private _basicInfoStep!: CampaignBasicInfoComponent;
    @ViewChild('contentStep', { static: true }) private _contentStep!: CampaignContentComponent;
    @ViewChild('recipientsStep', { static: true }) private _recipientsStep!: CampaignRecipientsComponent;
    @ViewChild('previewStep', { static: true }) private _previewStep!: CampaignPreviewComponent;

    constructor(
        private _api: MessagesApiClient,
        private _router: Router,
        private _changeDetector: ChangeDetectorRef,
        private _utilities: UtilitiesService,
        @Inject(ToasterService) private _toaster: ToasterService
    ) { }

    public now: Date = new Date();
    public submitInProgress = false;
    public StepperType = StepperType;
    public previewData = new CampaignPreview();
    public basicInfoData: any = {};
    public templateId: string | undefined;
    public metaItems: HeaderMetaItem[] | null = [];

    public get okLabel(): string {
        return this._stepper.currentStep?.isLast
            ? this._previewStep.published.value === true
                ? 'Αποθήκευση & Δημοσίευση'
                : 'Αποθήκευση'
            : 'Επόμενο';
    }

    public ngOnInit(): void {
        this.metaItems = [
            { key: 'info', icon: Icons.Details, text: 'Ακολουθήστε τα παρακάτω βήματα για να δημιουργήσετε ένα νέο campaign.' }
        ];
    }

    public ngAfterViewChecked(): void {
        this._changeDetector.detectChanges();
    }

    public onSubmitCampaign(): void {
        const isLastStep = this._stepper.currentStep?.isLast;
        if (!isLastStep) {
            this._stepper.goToNextStep();
            return;
        }
        this.submitInProgress = true;
        const data = this._prepareDataToSubmit();
        this._api
            .createCampaign(data)
            .subscribe({
                next: (campaign: Campaign) => {
                    this.submitInProgress = false;
                    this._router.navigate(['campaigns']);
                    this._toaster.show(ToastType.Success, 'Επιτυχής αποθήκευση', `Η καμπάνια με τίτλο '${campaign.title}' δημιουργήθηκε με επιτυχία.`);
                }
            });
    }

    public onStepperStepChanged(event: StepSelectedEvent) {
        if (event.selectedIndex === 1) {
            if (this.templateId) {
                this._api.getTemplateById(this.templateId).subscribe((template: Template) => {
                    this._contentStep.init(this._basicInfoStep.channelsState.map(x => ({ channel: x.value, checked: x.checked })), template.content);
                });
            } else {
                this._contentStep.init(this._basicInfoStep.channelsState.map(x => ({ channel: x.value, checked: x.checked })), undefined);
            }
        }
        this.previewData.title = this._basicInfoStep.title.value;
        this.previewData.type = this._basicInfoStep.type.value?.text;
        this.previewData.template = this._basicInfoStep.template.value?.text;
        this.previewData.distributionList = this._recipientsStep.distributionList.value?.text;
        this.previewData.period = new Period({
            from: this._basicInfoStep.from.value,
            to: this._basicInfoStep.to.value
        });
        this.previewData.actionLink = new Hyperlink({
            text: this._basicInfoStep.actionLinkText.value,
            href: this._basicInfoStep.actionLinkHref.value
        });
        this.basicInfoData.title = this._basicInfoStep.title.value;
        this.basicInfoData.type = this._basicInfoStep.type.value?.text;
        this.basicInfoData.actionLink = new Hyperlink({
            text: this._basicInfoStep.actionLinkText.value,
            href: this._basicInfoStep.actionLinkHref.value
        });
    }

    private _prepareDataToSubmit(): CreateCampaignRequest {
        const data = new CreateCampaignRequest({
            actionLink: new Hyperlink({
                href: this._basicInfoStep.actionLinkHref.value,
                text: this._basicInfoStep.actionLinkText.value
            }),
            activePeriod: new Period({
                from: this._basicInfoStep.from.value ? new Date(this._basicInfoStep.from.value) : undefined,
                to: this._basicInfoStep.to.value ? new Date(this._basicInfoStep.to.value) : undefined
            }),
            isGlobal: this._recipientsStep.sendVia.value === 'user-base',
            messageChannelKind: this._basicInfoStep.channels.value,
            published: this._previewStep.published.value,
            title: this._basicInfoStep.title.value,
            data: this._contentStep.data.value,
            typeId: this._basicInfoStep.type.value?.value || undefined,
            recipientIds: this._recipientsStep.recipientIds.value ? this._recipientsStep.recipientIds.value.split('\n') : null,
            recipientListId: this._recipientsStep.distributionList.value?.value || undefined,
            content: {}
        });
        for (const channel of this._basicInfoStep.channels.value) {
            switch (channel) {
                case MessageChannelKind.Inbox:
                    data.content![this._utilities.toCamelCase(channel)] = new MessageContent({ title: this._contentStep.inboxSubject.value, body: this._contentStep.inboxBody.value });
                    break;
                case MessageChannelKind.Email:
                    data.content![this._utilities.toCamelCase(channel)] = new MessageContent({ title: this._contentStep.emailSubject.value, body: this._contentStep.emailBody.value });
                    break;
                case MessageChannelKind.PushNotification:
                    data.content![this._utilities.toCamelCase(channel)] = new MessageContent({ title: this._contentStep.pushNotificationSubject.value, body: this._contentStep.pushNotificationBody.value });
                    break;
                case MessageChannelKind.SMS:
                    data.content![this._utilities.toCamelCase(channel)] = new MessageContent({ title: this._contentStep.smsSubject.value, body: this._contentStep.smsBody.value });
                    break;
            }
        }
        return data;
    }
}
