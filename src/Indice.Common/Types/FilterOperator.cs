﻿namespace Indice.Types;

/// <summary>Represents an operator when querying for data.</summary>
public enum FilterOperator : short
{
    /// <summary>Equal.</summary>
    Eq = 0,
    /// <summary>Not equal</summary>
    Neq,
    /// <summary>Greater than.</summary>
    Gt,
    /// <summary>Less than.</summary>
    Lt,
    /// <summary>Greater than or equal.</summary>
    Gte,
    /// <summary>Less than or equal.</summary>
    Lte,
    /// <summary>Contains.</summary>
    Contains,
    /// <summary>Any one of a range of values.</summary>
    In,
    /// <summary>Between a couple of values.</summary>
    Between,
    /// <summary>Starts with a specified value.</summary>
    StartsWith
}
