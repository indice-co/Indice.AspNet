﻿using Indice.Extensions.Configuration.Database.Data.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Indice.Extensions.Configuration.Database.Data;

/// <summary>Database configuration for <see cref="AppSetting"/> entity.</summary>
public class AppSettingMap : IEntityTypeConfiguration<AppSetting>
{
    /// <inheritdoc />
    public void Configure(EntityTypeBuilder<AppSetting> builder) {
        // Configure table name and schema.
        builder.ToTable(nameof(AppSetting), AppSetting.TableSchema);
        // Configure primary key.
        builder.HasKey(x => x.Key);
        // Configure fields.
        builder.Property(x => x.Key).HasMaxLength(512);
        builder.Property(x => x.Value).HasMaxLength(2048).IsRequired();
    }
}
