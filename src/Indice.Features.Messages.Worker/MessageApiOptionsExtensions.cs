﻿using Indice.Features.Messages.Core;
using Indice.Hosting.Services;
using Indice.Services;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Extensions on <see cref="MessageEndpointOptions"/>.</summary>
public static class MessageApiOptionsExtensions
{
    /// <summary>Adds <see cref="IEventDispatcher"/> using Indice worker host as a queuing mechanism.</summary>
    /// <param name="options">Options used to configure the Campaigns API feature.</param>
    public static void UseEventDispatcherHosting(this MessageEndpointOptions options) =>
        options.Services.AddKeyedService<IEventDispatcher, EventDispatcherHosting, string>(
            key: KeyedServiceNames.EventDispatcherServiceKey,
            serviceProvider => new EventDispatcherHosting(new MessageQueueFactory(serviceProvider)),
            serviceLifetime: ServiceLifetime.Transient
        );
}
