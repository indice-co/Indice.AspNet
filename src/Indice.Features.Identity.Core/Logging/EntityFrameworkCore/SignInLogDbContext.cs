﻿using Microsoft.EntityFrameworkCore;

namespace Indice.Features.Identity.Core.Logging.EntityFrameworkCore;

/// <summary><see cref="DbContext"/> for the Entity Framework Core that stores all user sign in log data.</summary>
public class SignInLogDbContext : DbContext
{
    /// <summary>Constructs the <see cref="SignInLogDbContext"/> passing the configured options.</summary>
    /// <param name="options">The options to be used by a <see cref="SignInLogDbContext"/>.</param>
    public SignInLogDbContext(DbContextOptions options) : base(options) {
#if DEBUG
        Database.EnsureCreated();
#endif
    }

    /// <summary>Stores all sign log entries.</summary>
    public DbSet<DbSignInLogEntry> SignInLogs { get; set; }

    /// <summary>Configures schema needed for the Entity Framework Core.</summary>
    /// <param name="modelBuilder">Class used to create and apply a set of data model conventions.</param>
    protected override void OnModelCreating(ModelBuilder modelBuilder) {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyConfiguration(new DbSignInLogEntryMap());
    }
}
