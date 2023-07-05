﻿using Indice.Types;

namespace Indice.Features.Cases.Models;

/// <summary>
/// Options used to filter the list of cases.
/// 
/// Will be used internally to filter cases further, based on authentication parameters
/// </summary>
public class GetCasesListFilter
{
    /// <summary>The Id of the customer to filter.</summary>
    public List<FilterClause> CustomerIds { get; set; } = new List<FilterClause>();

    /// <summary>The name of the customer to filter.</summary>
    public List<FilterClause> CustomerNames { get; set; } = new List<FilterClause>();

    /// <summary>The created date of the case, starting from, to filter.</summary>
    public DateTimeOffset? From { get; set; }

    /// <summary>The create date of the case, ending to, to filter.</summary>
    public DateTimeOffset? To { get; set; }

    /// <summary>The list of case type codes to filter.</summary>
    public List<FilterClause> CaseTypeCodes { get; set; } = new List<FilterClause>();

    /// <summary>The list of checkpoint type Ids to filter.</summary>
    internal List<FilterClause> CheckpointTypeIds { get; set; } = new List<FilterClause>();

    /// <summary>The list of checkpoint type codes to filter.</summary>
    public List<FilterClause> CheckpointTypeCodes { get; set; } = new List<FilterClause>();

    /// <summary>The list of groupIds to filter.</summary>
    public List<FilterClause> GroupIds { get; set; } = new List<FilterClause>();

    /// <summary>Construct filter clauses based on the metadata you are adding to the cases in your installation.</summary>
    public List<FilterClause> Metadata { get; set; }
}
