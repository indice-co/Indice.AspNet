﻿using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Indice.Features.Cases.Data.Models
{
    /// <summary>
    /// Define the status for the customer. It is defined at the <see cref="DbCheckpointType.PublicStatus"/>.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))] // unfortunately, Elsa uses Newtonsoft.Json and overwrites our Converters...
    public enum CasePublicStatus : short
    {
        /// <summary>
        /// Submitted.
        /// </summary>
        Submitted,
        /// <summary>
        /// InProgress.
        /// </summary>
        InProgress,
        /// <summary>
        /// Completed.
        /// </summary>
        Completed,
        /// <summary>
        /// Deleted.
        /// </summary>
        Deleted,
        /// <summary>
        /// Rejected.
        /// </summary>
        Rejected
    }
}