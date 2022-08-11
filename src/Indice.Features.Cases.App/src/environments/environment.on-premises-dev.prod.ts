export const environment = {
    api_url: 'https://dev-cases.chaniabank.gr', // cases api url
    auth_settings: {
      accessTokenExpiringNotificationTime: 60,
      authority: 'https://dev-identity.chaniabank.gr', // identity api url
      automaticSilentRenew: true,
      client_id: 'cases-backoffice-app',
      filterProtocolClaims: true,
      loadUserInfo: true,
      monitorSession: true,
      post_logout_redirect_uri: 'https://dev-nbe-bo.chaniabank.gr',
      redirect_uri: 'https://dev-nbe-bo.chaniabank.gr/auth-callback',
      response_type: 'code',
      revokeAccessTokenOnSignout: true,
      scope: 'openid profile role email cases-api',
      silent_redirect_uri: 'https://dev-nbe-bo.chaniabank.gr/auth-renew',
      useRefreshToken: true
    },
    culture: 'el-GR',
    isTemplate: false,
    production: true
  };