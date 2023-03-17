﻿using Indice.Features.Identity.SignInLogs.Models;

namespace Indice.Features.Identity.SignInLogs.Abstractions;

/// <summary>An abstraction used to describe the implementation of a service that enriches the <see cref="SignInLogEntry"/> class.</summary>
public interface ISignInLogEntryEnricher
{
    /// <summary>Enrich the <see cref="SignInLogEntry"/> class.</summary>
    /// <param name="logEntry">The instance of <see cref="SignInLogEntry"/> to enrich.</param>
    Task Enrich(SignInLogEntry logEntry);
}