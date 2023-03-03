﻿using System.ComponentModel.DataAnnotations;

namespace Indice.AspNetCore.Identity.Api.Models;

/// <summary>Models the request to update the email for the user.</summary>
public class UpdateUserEmailRequest
{
    /// <summary>The URL to return to.</summary>
    public string ReturnUrl { get; set; }
    /// <summary>The new user email.</summary>
    [Required(AllowEmptyStrings = false)]
    [EmailAddress]
    public string Email { get; set; }
}
