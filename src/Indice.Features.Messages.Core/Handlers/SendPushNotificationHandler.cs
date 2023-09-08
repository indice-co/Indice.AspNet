﻿using System.Dynamic;
using System.Text.Json;
using Indice.Features.Messages.Core.Events;
using Indice.Serialization;
using Indice.Services;

namespace Indice.Features.Messages.Core.Handlers;

/// <summary>Job handler for <see cref="SendPushNotificationEvent"/>.</summary>
public class SendPushNotificationHandler : ICampaignJobHandler<SendPushNotificationEvent>
{
    /// <summary>Creates a new instance of <see cref="SendPushNotificationHandler"/>.</summary>
    /// <param name="getPushNotificationService">Push notification service abstraction in order to support different providers.</param>
    /// <exception cref="ArgumentNullException"></exception>
    public SendPushNotificationHandler(Func<string, IPushNotificationService> getPushNotificationService) {
        GetPushNotificationService = getPushNotificationService ?? throw new ArgumentNullException(nameof(getPushNotificationService));
    }

    private Func<string, IPushNotificationService> GetPushNotificationService { get; }

    /// <summary>Sends a push notification to all users or a single one.</summary>
    /// <param name="pushNotification">The event model used when sending a push notification.</param>
    public async Task Process(SendPushNotificationEvent pushNotification) {
        ExpandoObject data = pushNotification.Data is not null && (pushNotification.Data is not string || !string.IsNullOrWhiteSpace(pushNotification.Data))
            ? JsonSerializer.Deserialize<ExpandoObject>(pushNotification.Data, JsonSerializerOptionDefaults.GetDefaultSettings())
            : new ExpandoObject();

        if (pushNotification.MessageId.HasValue) {
            data.TryAdd("messageId", pushNotification.MessageId);
        }
        var pushNotificationService = GetPushNotificationService(KeyedServiceNames.PushNotificationServiceKey);
        var pushBody = pushNotification.Body ?? "-";
        if (pushNotification.Broadcast) {
            await pushNotificationService.BroadcastAsync(pushNotification.Title, pushBody, data, pushNotification.MessageType?.Name);
        } else {
            await pushNotificationService.SendToUserAsync(pushNotification.Title, pushBody, data, pushNotification.RecipientId, classification: pushNotification.MessageType?.Name, pushNotification.RecipientId);
        }
    }
}
