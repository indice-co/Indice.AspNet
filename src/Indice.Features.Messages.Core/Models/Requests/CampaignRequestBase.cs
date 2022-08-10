﻿using Indice.Types;

namespace Indice.Features.Messages.Core.Models.Requests
{
    /// <summary>Base class for all campaign requests.</summary>
    public class CampaignRequestBase
    {
        private Dictionary<string, MessageContent> _content = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Determines if campaign targets all user base. Defaults to false.</summary>
        public bool IsGlobal { get; set; }
        /// <summary>The delivery channel of a campaign. Default is <see cref="MessageChannelKind.Inbox"/>.</summary>
        public MessageChannelKind MessageChannelKind { get; set; } = MessageChannelKind.Inbox;
        /// <summary>The title of the campaign.</summary>
        public string Title { get; set; }
        /// <summary>The contents of the campaign.</summary>
        public Dictionary<string, MessageContent> Content {
            get { return _content; }
            set { _content = new Dictionary<string, MessageContent>(value, StringComparer.OrdinalIgnoreCase); }
        }
        /// <summary>Defines a (call-to-action) link.</summary>
        public Hyperlink ActionLink { get; set; }
        /// <summary>Specifies the time period that a campaign is active.</summary>
        public Period ActivePeriod { get; set; }
        /// <summary>The id of the type this campaign belongs.</summary>
        public Guid? TypeId { get; set; }
        /// <summary>The id of the distribution list.</summary>
        public Guid? RecipientListId { get; set; }
        /// <summary>Optional data for the campaign.</summary>
        public dynamic Data { get; set; }
    }
}
