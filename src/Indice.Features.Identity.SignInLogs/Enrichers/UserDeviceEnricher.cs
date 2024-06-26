﻿using Indice.Features.Identity.Core;
using Indice.Features.Identity.Core.Data.Models;
using Indice.Features.Identity.SignInLogs.Abstractions;
using Indice.Features.Identity.SignInLogs.Models;
using Microsoft.EntityFrameworkCore;

namespace Indice.Features.Identity.SignInLogs.Enrichers;

/// <summary>Enriches the sign in log entry with user device data.</summary>
public sealed class UserDeviceEnricher : ISignInLogEntryEnricher
{
    private readonly ExtendedUserManager<User> _userManager;

    /// <summary>Creates a new instance of <see cref="SubjectNameEnricher"/> class.</summary>
    /// <param name="userManager">Provides the APIs for managing users and their related data in a persistence store.</param>
    /// <exception cref="ArgumentNullException"></exception>
    public UserDeviceEnricher(ExtendedUserManager<User> userManager) {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
    }

    /// <inheritdoc />
    public int Order => 5;
    /// <inheritdoc />
    public SignInLogEnricherRunType RunType => SignInLogEnricherRunType.Asynchronous;

    /// <inheritdoc />
    public async ValueTask EnrichAsync(SignInLogEntry logEntry) {
        var success = await EnrichFromDeviceId(logEntry);
        if (!success) { 
            await EnrichFromRegistrationId(logEntry);
        }
    }

    private async ValueTask<bool> EnrichFromDeviceId(SignInLogEntry logEntry) {
        if (string.IsNullOrWhiteSpace(logEntry.DeviceId)) {
            return false;
        }
        logEntry.User ??= (!string.IsNullOrWhiteSpace(logEntry.SubjectId) ? await _userManager.FindByIdAsync(logEntry.SubjectId) : default);
        if (logEntry.User is null) {
            return true;
        }
        var device = await _userManager.GetDeviceByIdAsync(logEntry.User, logEntry.DeviceId);
        if (device is null) {
            return true;
        }
        logEntry.ExtraData.UserDevice = new SignInLogEntryUserDevice {
            Id = device.Id,
            Blocked = device.Blocked,
            ClientType = device.ClientType,
            DateCreated = device.DateCreated,
            IsPendingTrustActivation = device.IsPendingTrustActivation,
            IsPushNotificationsEnabled = device.IsPushNotificationsEnabled,
            IsTrusted = device.IsTrusted,
            LastSignInDate = device.LastSignInDate,
            MfaSessionExpirationDate = device.MfaSessionExpirationDate,
            Model = device.Model,
            Name = device.Name,
            OsVersion = device.OsVersion,
            Platform = device.Platform,
            RequiresPassword = device.RequiresPassword,
            SupportsFingerprintLogin = device.SupportsFingerprintLogin,
            SupportsPinLogin = device.SupportsPinLogin,
            Tags = device.Tags,
            TrustActivationDate = device.TrustActivationDate,
            Data = device.Data
        };
        return true;
    }

    private async ValueTask<bool> EnrichFromRegistrationId(SignInLogEntry logEntry) {
        if (logEntry.ExtraData?.UserDevice?.Id is null) {
            return false;
        }
        var device = await _userManager.UserDevices.FirstOrDefaultAsync(x => x.Id == logEntry.ExtraData.UserDevice.Id);
        if (device is null) {
            return true;
        }
        logEntry.SubjectId = device.UserId;
        logEntry.User ??= await _userManager.FindByIdAsync(logEntry.SubjectId);
        if (logEntry.User is null) {
            return true;
        }
        logEntry.ExtraData.UserDevice = new SignInLogEntryUserDevice {
            Id = device.Id,
            Blocked = device.Blocked,
            ClientType = device.ClientType,
            DateCreated = device.DateCreated,
            IsPendingTrustActivation = device.IsPendingTrustActivation,
            IsPushNotificationsEnabled = device.IsPushNotificationsEnabled,
            IsTrusted = device.IsTrusted,
            LastSignInDate = device.LastSignInDate,
            MfaSessionExpirationDate = device.MfaSessionExpirationDate,
            Model = device.Model,
            Name = device.Name,
            OsVersion = device.OsVersion,
            Platform = device.Platform,
            RequiresPassword = device.RequiresPassword,
            SupportsFingerprintLogin = device.SupportsFingerprintLogin,
            SupportsPinLogin = device.SupportsPinLogin,
            Tags = device.Tags,
            TrustActivationDate = device.TrustActivationDate,
            Data = device.Data
        };
        return true;
    }
}
