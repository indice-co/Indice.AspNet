import { IShellConfig } from '@indice/ng-components';

export class ShellConfig implements IShellConfig {
    public appLogo = 'assets/images/branding/logo_small.svg';
    public appLogoAlt = 'ChaniaBank';
    public fluid = true;
    public showFooter = false;
    public showHeader = true;
    public showUserNameOnHeader = true;
}
