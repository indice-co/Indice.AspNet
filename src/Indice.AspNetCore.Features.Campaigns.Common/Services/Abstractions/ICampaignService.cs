﻿using Indice.AspNetCore.Features.Campaigns.Models;
using Indice.Types;

namespace Indice.AspNetCore.Features.Campaigns.Services
{
    /// <summary>
    /// A service that contains campaign related operations.
    /// </summary>
    public interface ICampaignService
    {
        /// <summary>
        /// Gets a list of all campaigns in the system.
        /// </summary>
        /// <param name="options">List parameters used to navigate through collections. Contains parameters such as sort, search, page number and page size.</param>
        Task<ResultSet<Campaign>> GetList(ListOptions<CampaignsFilter> options);
        /// <summary>
        /// Gets a campaign by it's unique id.
        /// </summary>
        /// <param name="id">The id of the campaign.</param>
        Task<CampaignDetails> GetById(Guid id);
        /// <summary>
        /// Creates a new campaign.
        /// </summary>
        /// <param name="request">The data for the campaign to create.</param>
        Task<Campaign> Create(CreateCampaignRequest request);
        /// <summary>
        /// Updates an existing campaign.
        /// </summary>
        /// <param name="id">The id of the campaign.</param>
        /// <param name="request">The data for the campaign to update.</param>
        Task Update(Guid id, UpdateCampaignRequest request);
        /// <summary>
        /// Deletes an existing campaign.
        /// </summary>
        /// <param name="id">The id of the campaign.</param>
        Task Delete(Guid id);
        /// <summary>
        /// Publishes an existing campaign.
        /// </summary>
        /// <param name="id">The id of the campaign.</param>
        Task Publish(Guid id);
        /// <summary>
        /// Creates a new attachment.
        /// </summary>
        /// <param name="fileAttachment">The file attachment.</param>
        Task<AttachmentLink> CreateAttachment(FileAttachment fileAttachment);
        /// <summary>
        /// Associates a campaign with an attachment.
        /// </summary>
        /// <param name="id">The id of the campaign.</param>
        /// <param name="attachmentId">The id of the attachment.</param>
        Task AssociateAttachment(Guid id, Guid attachmentId);
        /// <summary>
        /// Gets some statistics for the campaign.
        /// </summary>
        /// <param name="id">The id of the campaign.</param>
        Task<CampaignStatistics> GetStatistics(Guid id);
        /// <summary>
        /// Records a visit for the specified campaign.
        /// </summary>
        /// <param name="id">The id of the campaign.</param>
        Task UpdateHit(Guid id);
    }
}
