﻿using Indice.Features.Identity.Core.Data.Models;
using Indice.Services;

namespace Indice.Features.Identity.Core.Events;

/// <summary>An event that is raised when a device is deleted through <see cref="ExtendedUserManager{TUser}"/>.</summary>
/// <typeparam name="TDevice">The type of the device.</typeparam>
/// <typeparam name="TUser">The type of the user.</typeparam>
public class DeviceDeletedEvent<TDevice, TUser> : IPlatformEvent
    where TDevice : DbUserDevice
    where TUser : DbUser
{
    /// <summary>Creates a new instance of <see cref="DeviceDeletedEvent{TDevice, TUser}"/>.</summary>
    /// <param name="device">The device entity.</param>
    /// <param name="user">The user entity.</param>
    public DeviceDeletedEvent(TDevice device, TUser user) {
        Device = device;
        User = user;
    }

    /// <summary>The device deleted.</summary>
    public TDevice Device { get; }
    /// <summary>Related user.</summary>
    public TUser User { get; }
}

/// <summary>An event that is raised when a device is deleted through <see cref="ExtendedUserManager{TUser}"/>.</summary>
public class DeviceDeletedEvent : DeviceDeletedEvent<DbUserDevice, DbUser>
{
    /// <summary>Creates a new instance of <see cref="DeviceDeletedEvent{TDevice, TUser}"/>.</summary>
    /// <param name="device">The device entity.</param>
    /// <param name="user">The user entity.</param>
    public DeviceDeletedEvent(DbUserDevice device, DbUser user) : base(device, user) { }
}
