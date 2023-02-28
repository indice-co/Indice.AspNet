﻿using Humanizer;
using IdentityModel;
using Indice.Features.Identity.Core.Data.Models;

namespace Indice.Features.Identity.Core.Data;

/// <summary>Provides functionality to generate test claim types for development purposes.</summary>
internal class InitialClaimTypes
{
    private static readonly List<DbClaimType> ClaimTypes = new() {
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.BirthDate, DisplayName = nameof(JwtClaimTypes.BirthDate).Humanize(), Reserved = true, Required = false, UserEditable = true, ValueType = ClaimValueType.DateTime, Description = "End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.Email, DisplayName = nameof(JwtClaimTypes.Email).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ClaimValueType.String, Description = "End-User's preferred e-mail address." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.EmailVerified, DisplayName = nameof(JwtClaimTypes.EmailVerified).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ClaimValueType.Boolean, Description = "'true' if the End-User's e-mail address has been verified; otherwise 'false'." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.FamilyName, DisplayName = "Last Name", Reserved = true, Required = true, UserEditable = false, ValueType = ClaimValueType.String, Description = "Surname(s) or last name(s) of the End-User." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.Gender, DisplayName = nameof(JwtClaimTypes.Gender).Humanize(), Reserved = true, Required = false, UserEditable = true, ValueType = ClaimValueType.String, Description = "End-User's gender." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.GivenName, DisplayName = "First Name", Reserved = true, Required = true, UserEditable = true, ValueType = ClaimValueType.String, Description = "Given name(s) or first name(s) of the End-User." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.MiddleName, DisplayName = nameof(JwtClaimTypes.MiddleName).Humanize(), Reserved = true, Required = false, UserEditable = true, ValueType = ClaimValueType.String, Description = "Middle name(s) of the End-User." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.Name, DisplayName = nameof(JwtClaimTypes.Name).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ClaimValueType.String, Description = "End-User's full name in displayable form including all name parts, possibly including titles and suffixes, ordered according to the End-User's locale and preferences." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.NickName, DisplayName = nameof(JwtClaimTypes.NickName).Humanize(), Reserved = true, Required = false, UserEditable = true, ValueType = ClaimValueType.String, Description = "Casual name of the End-User that may or may not be the same as the given_name." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.PhoneNumber, DisplayName = nameof(JwtClaimTypes.PhoneNumber).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ClaimValueType.String, Description = "End-User's preferred telephone number" },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.PhoneNumberVerified, DisplayName = nameof(JwtClaimTypes.PhoneNumberVerified).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ClaimValueType.Boolean, Description = "True if the End-User's phone number has been verified; otherwise false" },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.Picture, DisplayName = nameof(JwtClaimTypes.Picture).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ClaimValueType.String, Description = "URL of the End-User's profile picture." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.PreferredUserName, DisplayName = nameof(JwtClaimTypes.PreferredUserName).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ClaimValueType.String, Description = "Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.Profile, DisplayName = nameof(JwtClaimTypes.Profile).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ClaimValueType.String, Description = "URL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.Role, DisplayName = nameof(JwtClaimTypes.Role).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ClaimValueType.String, Description = "The role." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.Subject, DisplayName = nameof(JwtClaimTypes.Subject).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ClaimValueType.String, Description = "Unique Identifier for the End-User at the Issuer." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.WebSite, DisplayName = nameof(JwtClaimTypes.WebSite).Humanize(), Reserved = true, Required = false, UserEditable = true, ValueType = ClaimValueType.String, Description = "URL of the End-User's Web page or blog." },
        new DbClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.ZoneInfo, DisplayName = nameof(JwtClaimTypes.ZoneInfo).Humanize(), Reserved = true, Required = false, UserEditable = true, ValueType = ClaimValueType.String, Description = "String from the time zone database (http://www.twinsun.com/tz/tz-link.htm) representing the End-User's time zone. For example, Europe/Paris or America/Los_Angeles." }
    };

    /// <summary>Gets a collection of test claim types.</summary>
    public static IReadOnlyCollection<DbClaimType> Get() => ClaimTypes;
}
