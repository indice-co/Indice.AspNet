﻿namespace Indice.Features.Identity.UI.Models;

/// <summary>Class that allows for extending the register request with custom attributes as needed per application.</summary>
public class AttributeModel
{
    /// <summary>The equivalent for a claim type.</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>The value.</summary>
    public string Value { get; set; } = string.Empty;
}
