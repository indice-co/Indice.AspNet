using Indice.Events;
using Indice.Features.Identity.Core.Events.Models;

namespace Indice.Features.Identity.Core.Events;

/// <summary>An event that is raised when a user's email is changed through <see cref="ExtendedUserManager{User}"/>.</summary>
/// <remarks>Creates a new instance of <see cref="EmailChangedEvent"/>.</remarks>
/// <param name="user">The user context.</param>
/// <param name="previousValue"></param>
public class EmailChangedEvent(UserEventContext user, string previousValue) : IPlatformEvent
{
    /// <summary>The user context.</summary>
    public UserEventContext User { get; } = user;
    /// <summary>The previous email of the user.</summary>
    public string PreviousValue { get; } = previousValue;
}
