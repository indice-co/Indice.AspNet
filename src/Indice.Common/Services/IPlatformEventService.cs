﻿namespace Indice.Services;

/// <summary>Models the event mechanism used to raise events inside the platform.</summary>
public interface IPlatformEventService

{
    /// <summary>Raises the specified event.</summary>
    /// <typeparam name="TEvent">The type of the event.</typeparam>
    /// <param name="event">The event to raise.</param>
    Task Publish<TEvent>(TEvent @event) where TEvent : IPlatformEvent;
}

/// <summary>Represents an event that is raised inside the platform.</summary>
public interface IPlatformEvent { }
