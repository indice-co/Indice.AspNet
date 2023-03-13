﻿using Indice.Features.Messages.Core.Models;

namespace Indice.Features.Messages.Core.Data.Models;

/// <summary>Message sender.</summary>
public class DbMessageSender
{
    /// <summary>Id.</summary>
    public Guid Id { get; set; }
    /// <summary>Sender id.</summary>
    public string Sender { get; set; }
    /// <summary>Sender Name.</summary>
    public string DisplayName { get; set; }
    /// <summary>Channel kind.</summary>
    public MessageChannelKind Kind { get; set; }
}