﻿using Indice.Features.Messages.Core;
using Indice.Features.Messages.Core.Events;
using Indice.Hosting;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Extension methods on <see cref="WorkPublisherBuilder"/> type.</summary>
public static class WorkPublisherExtensions
{
    /// <summary>Adds the events required the for campaigns feature.</summary>
    /// <param name="workPublisherBuilder">A helper class to configure the work publisher.</param>
    /// <returns>The <see cref="WorkPublisherBuilder"/> used to configure the worker host.</returns>
    public static WorkPublisherBuilder AddCampaignsEvents(this WorkPublisherBuilder workPublisherBuilder) =>
        workPublisherBuilder.ForEvent<CampaignCreatedEvent>(EventNames.CampaignCreated)
                            .ForEvent<ResolveMessageEvent>(EventNames.ResolveMessage)
                            .ForEvent<SendPushNotificationEvent>(EventNames.SendPushNotification)
                            .ForEvent<SendEmailEvent>(EventNames.SendEmail)
                            .ForEvent<SendSmsEvent>(EventNames.SendSms);
}
