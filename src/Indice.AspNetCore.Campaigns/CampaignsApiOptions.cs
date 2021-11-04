﻿using System;
using Microsoft.EntityFrameworkCore;

namespace Indice.AspNetCore.Features.Campaigns.Configuration
{
    /// <summary>
    /// Options used to configure the Campaigns API feature.
    /// </summary>
    public class CampaignsApiOptions
    {
        /// <summary>
        /// Configuration <see cref="Action"/> for internal <see cref="DbContext"/>. 
        /// If not provided the underlying store defaults to SQL Server expecting the setting <i>ConnectionStrings:DefaultConnection</i> to be present.
        /// </summary>
        public Action<DbContextOptionsBuilder> ConfigureDbContext { get; set; }
        /// <summary>
        /// The default scope name to be used for Campaigns API. Defaults to <see cref="CampaignsApi.Scope"/>.
        /// </summary>
        public string ExpectedScope { get; set; } = CampaignsApi.Scope;
        /// <summary>
        /// Specifies a prefix for the API endpoints. Defaults to <i>api</i>
        /// </summary>
        public string ApiPrefix { get; set; } = "api";
    }
}
