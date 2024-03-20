using Indice.Events;
using Indice.Features.Identity.Core.Events.Models;

namespace Indice.Features.Identity.Core.Events;

/// <summary>An event that is raised when a user's phone number is changed through <see cref="ExtendedUserManager{User}"/>.</summary>
/// <remarks>Creates a new instance of <see cref="PhoneNumberChangedEvent"/>.</remarks>
/// <param name="user">The user context.</param>
/// <param name="previousValue"></param>
public class PhoneNumberChangedEvent(UserEventContext user, string previousValue) : IPlatformEvent
{
    /// <summary>The user context.</summary>
    public UserEventContext User { get; } = user;
    /// <summary>The previous phone number of the user.</summary>
    public string PreviousValue { get; } = previousValue;
}
