import { Component, OnInit, ViewChild, ComponentFactoryResolver, ChangeDetectorRef } from '@angular/core';
import { FormGroup, FormControl, FormBuilder, Validators } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';

import { Subscription } from 'rxjs';
import { WizardStepDescriptor } from 'src/app/shared/components/step-base/models/wizard-step-descriptor';
import { WizardStepDirective } from 'src/app/shared/components/step-base/wizard-step.directive';
import { StepBaseComponent } from 'src/app/shared/components/step-base/step-base.component';
import { ApiResourceWizardModel } from '../models/api-resource-wizard-model';
import { CreateResourceRequest, IdentityApiService, ApiResourceInfo } from 'src/app/core/services/identity-api.service';
import { BasicInfoStepComponent } from './wizard/steps/basic-info/basic-info-step.component';
import { UserClaimsStepComponent } from './wizard/steps/user-claims/user-claims-step.component';
import { ApiResourceWizardService } from './wizard/api-resource-wizard.service';
import { ToastService } from 'src/app/layout/services/app-toast.service';

@Component({
    selector: 'app-api-resource-add',
    templateUrl: './api-resource-add.component.html',
    providers: [ApiResourceWizardService]
})
export class ApiResourceAddComponent implements OnInit {
    @ViewChild(WizardStepDirective, { static: false }) private _wizardStepHost: WizardStepDirective;
    private _loadedStepInstance: StepBaseComponent<ApiResourceWizardModel>;
    private _formValidatedSubscription: Subscription;

    constructor(private _componentFactoryResolver: ComponentFactoryResolver, private _formBuilder: FormBuilder, private _changeDetectionRef: ChangeDetectorRef, 
                private _api: IdentityApiService, private _toast: ToastService, private _router: Router, private _route: ActivatedRoute) { }

    public wizardStepIndex = 0;
    public apiResourceSteps: WizardStepDescriptor[] = [];
    public form: FormGroup;
    public hostFormValidated = false;
    public resource: CreateResourceRequest = new CreateResourceRequest();

    public get canGoFront(): boolean {
        return this.wizardStepIndex >= 0 && this.wizardStepIndex < this.apiResourceSteps.length - 1;
    }

    public get canGoBack(): boolean {
        return this.wizardStepIndex > 0 && this.wizardStepIndex <= this.apiResourceSteps.length - 1;
    }

    public get isSummaryStep(): boolean {
        return this.wizardStepIndex === this.apiResourceSteps.length - 1;
    }

    public ngOnInit(): void {
        this.form = this._formBuilder.group({
            name: ['', [Validators.required, Validators.maxLength(200)]],
            displayName: ['', [Validators.maxLength(200)]],
            description: ['', [Validators.maxLength(1000)]],
            userClaims: [[]]
        });
        this.apiResourceSteps = [
            new WizardStepDescriptor('Basic Details', BasicInfoStepComponent),
            new WizardStepDescriptor('User Claims', UserClaimsStepComponent)
        ];
        this._changeDetectionRef.detectChanges();
        this.loadStep(this.apiResourceSteps[0]);
    }

    public goToNextStep(): void {
        if (!this.canGoFront) {
            return;
        }
        if (this._loadedStepInstance.isValid()) {
            this.hostFormValidated = false;
            this.wizardStepIndex += 1;
            this.loadStep(this.apiResourceSteps[this.wizardStepIndex]);
        } else {
            this.hostFormValidated = true;
            this.validateFormFields(this.form);
        }
        this._loadedStepInstance.formValidated.emit(this.hostFormValidated);
    }

    public goToPreviousStep(): void {
        if (!this.canGoBack) {
            return;
        }
        this.hostFormValidated = false;
        this.wizardStepIndex -= 1;
        this.loadStep(this.apiResourceSteps[this.wizardStepIndex]);
    }

    public saveApiResource(): void {
        this._api.createProtectedResource({
            name: this.form.get('name').value,
            displayName: this.form.get('displayName').value,
            description: this.form.get('description').value,
            userClaims: this.form.get('userClaims').value
        } as CreateResourceRequest).subscribe((resource: ApiResourceInfo) => {
            this._toast.showSuccess(`API resource '${resource.name}' was created successfully.`);
            this._router.navigate(['../'], { relativeTo: this._route });
        });
    }

    private validateFormFields(formGroup: FormGroup) {
        Object.keys(formGroup.controls).forEach((field: string) => {
            const control = formGroup.get(field);
            if (control instanceof FormControl) {
                control.markAsTouched({ onlySelf: true });
            } else if (control instanceof FormGroup) {
                this.validateFormFields(control);
            }
        });
    }

    private loadStep(step: WizardStepDescriptor): void {
        const componentFactory = this._componentFactoryResolver.resolveComponentFactory(step.component);
        const viewContainerRef = this._wizardStepHost.viewContainerRef;
        viewContainerRef.clear();
        const componentRef = viewContainerRef.createComponent(componentFactory);
        // Keep a reference of the instance of the step component.
        this._loadedStepInstance = componentRef.instance as StepBaseComponent<ApiResourceWizardModel>;
        // Pass data to the dynamically loaded component.
        this._loadedStepInstance.data = {
            apiResource: this.resource,
            form: this.form
        } as ApiResourceWizardModel;
        if (this._formValidatedSubscription) {
            this._formValidatedSubscription.unsubscribe();
        }
        this._formValidatedSubscription = this._loadedStepInstance.formValidated.subscribe((value: boolean) => {
            this.hostFormValidated = value;
        });
    }
}
