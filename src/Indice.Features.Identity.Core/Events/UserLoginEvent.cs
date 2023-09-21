﻿using Indice.Features.Identity.Core.Data.Models;
using Indice.Services;

namespace Indice.Features.Identity.Core.Events;

/// <summary>An event that is raised when a user fully signs in.</summary>
/// <typeparam name="TUser">The type of user.</typeparam>
public class UserLoginEvent<TUser> : IPlatformEvent where TUser : User
{
    /// <summary>Creates a new instance of <see cref="UserLoginEvent{TUser}"/>.</summary>
    /// <param name="user">The user entity.</param>
    /// <param name="succeeded">Indicates whether the login was successful or not.</param>
    /// <param name="warning">Describes a warning that may occur during a sign in event.</param>
    public UserLoginEvent(TUser user, bool succeeded, SignInWarning? warning = null) {
        User = user;
        Succeeded = succeeded;
        Warning = warning;
    }

    /// <summary>The user entity.</summary>
    public TUser User { get; }
    /// <summary>Indicates whether the login was successful or not.</summary>
    public bool Succeeded { get; }
    /// <summary>Describes a warning that may occur during a sign in event.</summary>
    public SignInWarning? Warning { get; }

    /// <summary>Creates a new instance of <see cref="UserLoginEvent{TUser}"/> and sets the value true to <see cref="Succeeded"/> property.</summary>
    /// <param name="user">The user entity.</param>
    /// <param name="warning">Describes a warning that may occur during a sign in event.</param>
    public static UserLoginEvent Success(TUser user, SignInWarning? warning = null) => new(user, true, warning);
    /// <summary>Creates a new instance of <see cref="UserLoginEvent{TUser}"/> and sets the value false to <see cref="Succeeded"/> property.</summary>
    /// <param name="user">The user entity.</param>
    public static UserLoginEvent Fail(TUser user) => new(user, false);
}

/// <summary>An event that is raised when a user fully signs in.</summary>
public class UserLoginEvent : UserLoginEvent<User>
{
    /// <summary>Creates a new instance of <see cref="UserLoginEvent"/>.</summary>
    /// <param name="user">The user entity.</param>
    /// <param name="succeeded">Indicates whether the login was successful or not.</param>
    /// <param name="warning">Describes a warning that may occur during a sign in event.</param>
    public UserLoginEvent(User user, bool succeeded, SignInWarning? warning = null) : base(user, succeeded, warning) { }
}