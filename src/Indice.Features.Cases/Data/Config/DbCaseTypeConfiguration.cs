﻿using Indice.Configuration;
using Indice.Features.Cases.Data.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Indice.Features.Cases.Data.Config
{
    internal class DbCaseTypeConfiguration : IEntityTypeConfiguration<DbCaseType>
    {
        public void Configure(EntityTypeBuilder<DbCaseType> builder) {
            builder
                .ToTable("CaseType");
            builder
                .HasKey(p => p.Id);
            builder
                .HasIndex(p => p.Code);
            builder
                .Property(p => p.Code)
                .HasMaxLength(TextSizePresets.S64);
            builder
                .Property(p => p.Title)
                .HasMaxLength(TextSizePresets.M128);
            builder
                .Property(p => p.Translations);
            //builder
            //    .Property(p => p.DataSchema)
            //    .HasConversion(new JsonStringValueConverter()) // todo fix dynamic/object value conversion
            //    .IsRequired(false);
            builder
                .Property(p => p.Layout)
                .IsRequired(false); 
            builder
                .Property(p => p.LayoutTranslations)
                .IsRequired(false);
        }
    }
}