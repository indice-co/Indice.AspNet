﻿using System.Diagnostics;
using Indice.Hosting.Data.Models;
using Indice.Hosting.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;

namespace Indice.Hosting.Data;

/// <summary>A <see cref="DbContext"/> for hosting multiple <see cref="IMessageQueue{T}"/>.</summary>
public class TaskDbContext : DbContext
{
    private static bool _alreadyCreated = false;

    /// <summary>Creates a new instance of <see cref="TaskDbContext"/>.</summary>
    /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
    public TaskDbContext(DbContextOptions<TaskDbContext> options) : base(options) => EnsuredCreated();

    /// <summary>Creates a new instance of <see cref="TaskDbContext"/>.</summary>
    /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
    protected TaskDbContext(DbContextOptions options) : base(options) => EnsuredCreated();

    /// <summary>Queue messages.</summary>
    public DbSet<DbQMessage> Queue { get; set; }
    /// <summary>Tasks.</summary>
    public DbSet<DbScheduledTask> Tasks { get; set; }
    /// <summary>Locks.</summary>
    public DbSet<DbLock> Locks { get; set; }

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder builder) {
        base.OnModelCreating(builder);
        builder.ApplyConfiguration(new DbQMessageMap());
        builder.ApplyConfiguration(new DbScheduledTaskMap());
        builder.ApplyConfiguration(new DbLockMap());
    }

    private void EnsuredCreated() {
        if (Debugger.IsAttached) {
            var exists = Database.GetService<IRelationalDatabaseCreator>().Exists();
            if (!exists && !_alreadyCreated) {
                // When no databases have been created, this ensures that the database creation process will run once.
                _alreadyCreated = true;
                Database.EnsureCreated();
            }
        }
    }
}
