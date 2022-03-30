﻿using Indice.AspNetCore.Features.Campaigns.Events;
using Indice.Services;
using Microsoft.Extensions.Logging;

namespace Indice.AspNetCore.Features.Campaigns.Workers
{
    internal class InboxDistributionJobHandler : CampaignJobHandlerBase
    {
        public InboxDistributionJobHandler(
            ILogger<InboxDistributionJobHandler> logger,
            Func<string, IEventDispatcher> getEventDispatcher,
            Func<string, IPushNotificationService> getPushNotificationService
        ) : base(getEventDispatcher, getPushNotificationService) {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public ILogger<InboxDistributionJobHandler> Logger { get; }

        public async Task Process(InboxDistributionEvent campaign) => await DistributeInbox(campaign);
    }
}
