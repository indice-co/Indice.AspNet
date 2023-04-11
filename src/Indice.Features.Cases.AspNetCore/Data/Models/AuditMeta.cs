﻿using System.Security.Claims;
using Indice.Security;

namespace Indice.Features.Cases.Data.Models;

/// <summary>Audit metadata related with the user principal that "did" the action.</summary>
public class AuditMeta
{
    /// <summary>The Id of the user.</summary>
    public string Id { get; set; }

    /// <summary>The name of the user.</summary>
    public string Name { get; set; }

    /// <summary>The email of the user.</summary>
    public string Email { get; set; }

    /// <summary>The timestamp the audit happened.</summary>
    public DateTimeOffset? When { get; set; } = DateTimeOffset.Now;

    /// <summary>Clear the data of the instance.</summary>
    public void Clear() {
        Id = null;
        Name = null;
        Email = null;
        When = null;
    }

    /// <summary>Update the current instance with a new principal.</summary>
    /// <param name="user">The new principal to update the instance.</param>
    /// <param name="now">The timestamp.</param>
    public void Update(ClaimsPrincipal user, DateTimeOffset? now = null) {
        Populate(this, user, now);
    }

    /// <summary>Create a new instance from a <see cref="ClaimsPrincipal"/> object.</summary>
    /// <param name="user">The <see cref="ClaimsPrincipal"/>.</param>
    /// <param name="now">The timestamp</param>
    /// <returns></returns>
    public static AuditMeta Create(ClaimsPrincipal user, DateTimeOffset? now = null) {
        return Populate(null, user, now);
    }

    private static AuditMeta Populate(AuditMeta meta, ClaimsPrincipal user, DateTimeOffset? now = null) {
        meta ??= new AuditMeta();

        var subject = user.FindFirstValue(BasicClaimTypes.Subject);
        var hasSubject = !string.IsNullOrWhiteSpace(subject);

        string email;
        string name;
        if (hasSubject) {
            email = user.FindFirstValue(BasicClaimTypes.Email);
            name = $"{user.FindFirstValue(BasicClaimTypes.GivenName)} {user.FindFirstValue(BasicClaimTypes.FamilyName)}".Trim();
        } else {
            subject = user.FindFirstValue(BasicClaimTypes.ClientId);
            email = user.FindFirstValue(BasicClaimTypes.ClientId);
            name = "system_user";
        }


        meta.Id = subject;
        meta.Email = email;
        meta.Name = name;
        meta.When = now ?? DateTimeOffset.UtcNow;
        return meta;
    }
}