﻿using System;
using System.Collections.Generic;
using Indice.AspNetCore.Features.Campaigns.Data.Models;
using Indice.AspNetCore.Features.Campaigns.Events;
using Indice.Types;

namespace Indice.AspNetCore.Features.Campaigns.Models
{
    /// <summary>
    /// Models a campaign.
    /// </summary>
    public class Campaign
    {
        /// <summary>
        /// The unique identifier of the campaign.
        /// </summary>
        public Guid Id { get; set; }
        /// <summary>
        /// The title of the campaign.
        /// </summary>
        public string Title { get; set; }
        /// <summary>
        /// The content of the campaign.
        /// </summary>
        public CampaignContent Content { get; set; }
        /// <summary>
        /// Defines a CTA (call-to-action) text.
        /// </summary>
        public string ActionText { get; set; }
        /// <summary>
        /// Defines a CTA (call-to-action) URL.
        /// </summary>
        public string ActionUrl { get; set; }
        /// <summary>
        /// Specifies when a campaign was created.
        /// </summary>
        public DateTimeOffset CreatedAt { get; set; }
        /// <summary>
        /// Determines if a campaign is published.
        /// </summary>
        public bool Published { get; set; }
        /// <summary>
        /// Specifies the time period that a campaign is active.
        /// </summary>
        public Period ActivePeriod { get; set; }
        /// <summary>
        /// Determines if campaign targets all user base.
        /// </summary>
        public bool IsGlobal { get; set; }
        /// <summary>
        /// The type details of the campaign.
        /// </summary>
        public MessageType Type { get; set; }
        /// <summary>
        /// The distribution list of the campaign.
        /// </summary>
        public DistributionList DistributionList { get; set; }
        /// <summary>
        /// The delivery channel of a campaign.
        /// </summary>
        public MessageDeliveryChannel DeliveryChannel { get; set; }
        /// <summary>
        /// Optional data for the campaign.
        /// </summary>
        public dynamic Data { get; set; }
    }

    /// <summary>
    /// Extension methods on <see cref="Campaign"/> model.
    /// </summary>
    internal static class CampaignExtensions
    {
        public static CampaignCreatedEvent ToCampaignCreatedEvent(this Campaign campaign, List<string> selectedUserCodes = null) => new() {
            ActionText = campaign.ActionText,
            ActionUrl = campaign.ActionUrl,
            ActivePeriod = campaign.ActivePeriod,
            Content = campaign.Content,
            CreatedAt = campaign.CreatedAt,
            Data = campaign.Data,
            DeliveryChannel = campaign.DeliveryChannel,
            Id = campaign.Id,
            IsGlobal = campaign.IsGlobal,
            Published = campaign.Published,
            SelectedUserCodes = selectedUserCodes ?? new List<string>(),
            Title = campaign.Title,
            Type = campaign.Type
        };

        public static DbCampaign ToDbCampaign(this CreateCampaignRequest request) => new() {
            ActionText = request.ActionText,
            ActionUrl = request.ActionUrl,
            ActivePeriod = request.ActivePeriod,
            Content = request.Content,
            CreatedAt = DateTime.UtcNow,
            Data = request.Data,
            DeliveryChannel = request.DeliveryChannel,
            DistributionListId = request.DistributionListId,
            Id = Guid.NewGuid(),
            IsGlobal = request.IsGlobal,
            Published = request.Published,
            Title = request.Title,
            TypeId = request.TypeId
        };
    }
}
