﻿using System;
using System.Collections.Generic;
using Humanizer;
using IdentityModel;
using Indice.AspNetCore.Identity.Data.Models;
using ValueType = Indice.AspNetCore.Identity.Data.Models.ValueType;

namespace Indice.AspNetCore.Identity.Data
{
    /// <summary>
    /// Provides functionality to generate test claim types for development purposes.
    /// </summary>
    internal class InitialClaimTypes
    {
        private static readonly List<ClaimType> ClaimTypes = new() {
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.BirthDate, DisplayName = nameof(JwtClaimTypes.BirthDate).Humanize(), Reserved = true, Required = false, UserEditable = true, ValueType = ValueType.DateTime, Description = "End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.Email, DisplayName = nameof(JwtClaimTypes.Email).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ValueType.String, Description = "End-User's preferred e-mail address." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.EmailVerified, DisplayName = nameof(JwtClaimTypes.EmailVerified).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ValueType.Boolean, Description = "'true' if the End-User's e-mail address has been verified; otherwise 'false'." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.FamilyName, DisplayName = "Last Name", Reserved = true, Required = true, UserEditable = false, ValueType = ValueType.String, Description = "Surname(s) or last name(s) of the End-User." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.Gender, DisplayName = nameof(JwtClaimTypes.Gender).Humanize(), Reserved = true, Required = false, UserEditable = true, ValueType = ValueType.String, Description = "End-User's gender." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.GivenName, DisplayName = "First Name", Reserved = true, Required = true, UserEditable = true, ValueType = ValueType.String, Description = "Given name(s) or first name(s) of the End-User." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.MiddleName, DisplayName = nameof(JwtClaimTypes.MiddleName).Humanize(), Reserved = true, Required = false, UserEditable = true, ValueType = ValueType.String, Description = "Middle name(s) of the End-User." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.Name, DisplayName = nameof(JwtClaimTypes.Name).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ValueType.String, Description = "End-User's full name in displayable form including all name parts, possibly including titles and suffixes, ordered according to the End-User's locale and preferences." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.NickName, DisplayName = nameof(JwtClaimTypes.NickName).Humanize(), Reserved = true, Required = false, UserEditable = true, ValueType = ValueType.String, Description = "Casual name of the End-User that may or may not be the same as the given_name." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.PhoneNumber, DisplayName = nameof(JwtClaimTypes.PhoneNumber).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ValueType.String, Description = "End-User's preferred telephone number" },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.PhoneNumberVerified, DisplayName = nameof(JwtClaimTypes.PhoneNumberVerified).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ValueType.Boolean, Description = "True if the End-User's phone number has been verified; otherwise false" },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.Picture, DisplayName = nameof(JwtClaimTypes.Picture).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ValueType.String, Description = "URL of the End-User's profile picture." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.PreferredUserName, DisplayName = nameof(JwtClaimTypes.PreferredUserName).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ValueType.String, Description = "Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.Profile, DisplayName = nameof(JwtClaimTypes.Profile).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ValueType.String, Description = "URL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.Role, DisplayName = nameof(JwtClaimTypes.Role).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ValueType.String, Description = "The role." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.Subject, DisplayName = nameof(JwtClaimTypes.Subject).Humanize(), Reserved = true, Required = false, UserEditable = false, ValueType = ValueType.String, Description = "Unique Identifier for the End-User at the Issuer." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.WebSite, DisplayName = nameof(JwtClaimTypes.WebSite).Humanize(), Reserved = true, Required = false, UserEditable = true, ValueType = ValueType.String, Description = "URL of the End-User's Web page or blog." },
            new ClaimType { Id = $"{Guid.NewGuid()}", Name = JwtClaimTypes.ZoneInfo, DisplayName = nameof(JwtClaimTypes.ZoneInfo).Humanize(), Reserved = true, Required = false, UserEditable = true, ValueType = ValueType.String, Description = "String from the time zone database (http://www.twinsun.com/tz/tz-link.htm) representing the End-User's time zone. For example, Europe/Paris or America/Los_Angeles." }
        };

        /// <summary>
        /// Gets a collection of test claim types.
        /// </summary>
        public static IReadOnlyCollection<ClaimType> Get() => ClaimTypes;
    }
}
