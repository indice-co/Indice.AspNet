﻿using Indice.Types;
using Microsoft.Extensions.Logging;

namespace Indice.Services;

/// TODO: This seems to be broken implementation wize. The internal semaphore seems to be related to the manager instance instead of the LockLease instance 
/// hence it will not work with two instances competing for the same name/topic
/// <summary>Implementation of <see cref="ILockManager"/>.</summary>
/// <remarks>https://docs.microsoft.com/en-us/dotnet/api/system.threading.monitor</remarks>
public class LockManagerInMemory : ILockManager
{
    private readonly ILogger<LockManagerInMemory> _logger;
    private readonly SemaphoreSlim _signal = new SemaphoreSlim(0);

    /// <summary>Create a new instance of <see cref="LockManagerInMemory"/>.</summary>
    /// <param name="logger">Represents a type used to perform logging.</param>
    public LockManagerInMemory(ILogger<LockManagerInMemory> logger) {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _signal.Release();
    }

    /// <inheritdoc />
    public async Task<ILockLease> AcquireLock(string name, TimeSpan? timeout = null, CancellationToken cancellationToken = default) {
        await _signal.WaitAsync();
        var leaseId = new Base64Id(Guid.NewGuid()).ToString();
        _logger.LogInformation("Item with lease id {0} acquired the lock.", leaseId);
        return new LockLease(leaseId, name, this);
    }

    /// <inheritdoc />
    public Task Cleanup() {
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task ReleaseLock(ILockLease @lock) {
        _signal.Release();
        _logger.LogInformation("Item with lease id {0} released the lock.", @lock.LeaseId);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<ILockLease> Renew(string name, string leaseId, CancellationToken cancellationToken = default) {
        return Task.FromResult((ILockLease)new LockLease(leaseId, name, this));
    }
}
