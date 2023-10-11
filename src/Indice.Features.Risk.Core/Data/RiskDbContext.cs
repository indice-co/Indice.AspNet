﻿using System.Diagnostics;
using Indice.Configuration;
using Indice.Features.Risk.Core.Data.Models;
using Microsoft.EntityFrameworkCore;

namespace Indice.Features.Risk.Core.Data;

/// <summary>A <see cref="DbContext"/> for persisting events and it's related data.</summary>
public class RiskDbContext : DbContext
{
    /// <summary>Creates a new instance of <see cref="RiskDbContext"/> class.</summary>
    /// <param name="dbContextOptions"></param>
    public RiskDbContext(DbContextOptions<RiskDbContext> dbContextOptions) : base(dbContextOptions) {
    }

    /// <summary>Risk events table.</summary>
    public DbSet<RiskEvent> RiskEvents => Set<RiskEvent>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder) {
        base.OnModelCreating(modelBuilder);
        // Risk event configuration.
        modelBuilder.Entity<RiskEvent>().ToTable("RiskEvent");
        modelBuilder.Entity<RiskEvent>().HasKey(x => x.Id);
        modelBuilder.Entity<RiskEvent>().HasIndex(x => x.CreatedAt);
        modelBuilder.Entity<RiskEvent>().HasIndex(x => x.SubjectId);
        modelBuilder.Entity<RiskEvent>().HasIndex(x => x.Type);
        modelBuilder.Entity<RiskEvent>().Property(x => x.Amount).HasColumnType("money");
        modelBuilder.Entity<RiskEvent>().Property(x => x.IpAddress).HasMaxLength(TextSizePresets.M128);
        modelBuilder.Entity<RiskEvent>().Property(x => x.Name).HasMaxLength(TextSizePresets.M256);
        modelBuilder.Entity<RiskEvent>().Property(x => x.SubjectId).HasMaxLength(TextSizePresets.M256).IsRequired();
        modelBuilder.Entity<RiskEvent>().Property(x => x.Type).HasMaxLength(TextSizePresets.M256).IsRequired();
    }
}