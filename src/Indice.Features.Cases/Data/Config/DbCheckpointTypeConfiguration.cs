﻿using Indice.Configuration;
using Indice.Features.Cases.Data.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Indice.Features.Cases.Data.Config
{
    internal class DbCheckpointTypeConfiguration : IEntityTypeConfiguration<DbCheckpointType>
    {
        public void Configure(EntityTypeBuilder<DbCheckpointType> builder) {
            builder
                .ToTable("CheckpointType");
            builder
                .HasKey(p => p.Id);
            builder
                .HasIndex(p => p.Code);
            builder
                .Property(p => p.Code)
                .HasMaxLength(TextSizePresets.M256);
            builder
                .Property(p => p.Description)
                .HasMaxLength(TextSizePresets.M512);
            builder
                .Ignore(p => p.CaseTypeCode);
            builder
                .Ignore(p => p.Name);
        }
    }
}