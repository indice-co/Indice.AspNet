﻿using System.Linq.Expressions;
using Indice.Features.Identity.SignInLogs.Models;

namespace Indice.Features.Identity.SignInLogs.EntityFrameworkCore;

internal static class ObjectMapping
{
    public static Expression<Func<DbSignInLogEntry, SignInLogEntry>> ToSignInLogEntry = (entry) => new() {
        ActionName = entry.ActionName,
        ApplicationId = entry.ApplicationId,
        ApplicationName = entry.ApplicationName,
        Coordinates = entry.Coordinates,
        CountryIsoCode = entry.CountryIsoCode,
        CreatedAt = entry.CreatedAt,
        Description = entry.Description,
        ExtraData = entry.ExtraData,
        Id = entry.Id,
        IpAddress = entry.IpAddress,
        Location = entry.Location,
        MarkForReview = entry.MarkForReview,
        RequestId = entry.RequestId,
        ResourceId = entry.ResourceId,
        ResourceType = entry.ResourceType,
        SessionId = entry.SessionId,
        SignInType = entry.SignInType,
        SubjectId = entry.SubjectId,
        SubjectName = entry.SubjectName,
        Succedded = entry.Succedded
    };

    public static DbSignInLogEntry ToDbSignInLogEntry(this SignInLogEntry entry) => new() {
        ActionName = entry.ActionName,
        ApplicationId = entry.ApplicationId,
        ApplicationName = entry.ApplicationName,
        Coordinates = entry.Coordinates,
        CountryIsoCode = entry.CountryIsoCode,
        CreatedAt = entry.CreatedAt,
        Description = entry.Description,
        ExtraData = entry.ExtraData,
        Id = entry.Id,
        IpAddress = entry.IpAddress,
        Location = entry.Location,
        MarkForReview = entry.MarkForReview,
        RequestId = entry.RequestId,
        ResourceId = entry.ResourceId,
        ResourceType = entry.ResourceType,
        SessionId = entry.SessionId,
        SignInType = entry.SignInType,
        SubjectId = entry.SubjectId,
        SubjectName = entry.SubjectName,
        Succedded = entry.Succedded
    };
}
