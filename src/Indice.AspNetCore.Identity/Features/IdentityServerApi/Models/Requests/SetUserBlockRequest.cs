﻿namespace Indice.AspNetCore.Identity.Api.Models;

/// <summary>Models toggling a user's 'Blocked' property.</summary>
public class SetUserBlockRequest
{
    /// <summary>Indicates whether the user is forcefully blocked.</summary>
    public bool Blocked { get; set; }
}
