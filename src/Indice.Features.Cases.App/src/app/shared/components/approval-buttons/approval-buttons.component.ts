import { Component, Input, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { MenuOption, ToasterService, ToastType } from '@indice/ng-components';
import { Observable } from 'rxjs';
import { map, tap } from 'rxjs/operators';
import { Approval, ApprovalRequest, CasesApiService, RejectReason } from 'src/app/core/services/cases-api.service';

@Component({
  selector: 'app-approval-buttons',
  templateUrl: './approval-buttons.component.html'
})
export class ApprovalButtonsComponent implements OnInit {
  @Input() formUnSavedChanges: boolean = false;
  @Input() formValid: boolean = false;
  @Input() caseId: string | undefined;
  @Input() enabled: boolean | undefined;
  public buttonsDisabled: boolean | undefined = false;
  public approveButtonDisabled: boolean | undefined = false;
  public comment: string | undefined;

  rejectionOptions$: Observable<MenuOption[]> | undefined;
  selectedRejectReason = '';

  constructor(
    private _toaster: ToasterService,
    private _api: CasesApiService,
    private router: Router
  ) { }

  ngOnInit() {
    this.rejectionOptions$ = this._api.getCaseRejectReasons(this.caseId!)
      .pipe(
        map((response: RejectReason[]) => response.map(item => new MenuOption(item.value!, item.key!))),
        tap((reasons: MenuOption[]) => this.selectedRejectReason = reasons[0].value)
      );
  }

  public onToggleButtonChange() {
    this.approveButtonDisabled = !this.approveButtonDisabled;
    this.comment = this.approveButtonDisabled ? this.selectedRejectReason : undefined;
  }

  public onOptionChange(value: any): void {
    this.comment = value;
  }

  public approveCase(): void {
    if (!this.formValid) {
      return;
    }
    if (this.formUnSavedChanges) {
      this._toaster.show(ToastType.Success, 'Έχετε μη αποθηκευμένες αλλαγές!', `Παρακαλούμε αποθηκεύστε τις αλλαγές σας`, 5000);
      return;
    }
    this.caseDecision(Approval.Approve);
  }

  public rejectCase(): void {
    this.caseDecision(Approval.Reject);
  }

  private caseDecision(action: Approval): void {
    this.buttonsDisabled = true;
    const approvalRequest = new ApprovalRequest({ action: action, comment: this.comment });
    this._api.submitApproval(this.caseId!, undefined, approvalRequest)
      .subscribe(_ => {
        this._toaster.show(ToastType.Success, 'Επιτυχής Επεξεργασία', `Η επεξεργασία της αίτησης ολοκληρώθηκε.`, 5000);
        this.router.navigate(['/cases']);
      }, _ => {
        this._toaster.show(ToastType.Error, 'Αποτυχία Επεξεργασίας', `Δεν κατέστη εφικτή η επεξεργασία της αίτησης.`, 5000);
        this.router.navigate(['/cases']);
      });
  }

}