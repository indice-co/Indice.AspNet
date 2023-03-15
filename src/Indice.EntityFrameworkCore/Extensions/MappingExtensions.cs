﻿using System.Collections.Concurrent;
using System.Text.Json;
using Indice.EntityFrameworkCore.ValueConversion;
using Microsoft.EntityFrameworkCore.ChangeTracking;

namespace Microsoft.EntityFrameworkCore.Metadata.Builders;

/// <summary>Extension methods on <see cref="PropertyBuilder{TProperty}"/>.</summary>
public static class MappingExtensions
{
    /// <summary>Static map of Dynamic JSON Columns.</summary>
    internal static readonly ConcurrentDictionary<Type, HashSet<string>> JsonColumns = new();

    /// <summary>Configures the property so that the property value is converted to and from the database using the <see cref="JsonStringValueConverter{T}"/>.</summary>
    /// <typeparam name="TProperty">The store type generated by the converter.</typeparam>
    /// <param name="builder">The builder instance.</param>
    /// <returns>The same builder instance so that multiple configuration calls can be chained.</returns>
    public static PropertyBuilder HasJsonConversion<TProperty>(this PropertyBuilder<TProperty> builder) where TProperty : class {
        // https://docs.microsoft.com/en-us/ef/core/modeling/value-comparers
        var valueComparer = new ValueComparer<TProperty>(
            equalsExpression: (obj1, obj2) => 
                (obj1 != default(TProperty) ? JsonSerializer.Serialize(obj1, JsonStringValueConverter<TProperty>.SerializerOptions) : null) == 
                (obj2 != default(TProperty) ? JsonSerializer.Serialize(obj2, JsonStringValueConverter<TProperty>.SerializerOptions) : null),
            hashCodeExpression: obj => obj.GetHashCode(),
            snapshotExpression: obj => JsonSerializer.Deserialize<TProperty>(JsonSerializer.Serialize(obj, JsonStringValueConverter<TProperty>.SerializerOptions), JsonStringValueConverter<TProperty>.SerializerOptions)
        );
#if NET5_0_OR_GREATER
        builder.HasConversion(new JsonStringValueConverter<TProperty>(), valueComparer);
#else
        builder.HasConversion(new JsonStringValueConverter<TProperty>()).Metadata.SetValueComparer(valueComparer);
#endif
        var jsonColumns = JsonColumns.GetOrAdd(builder.Metadata.DeclaringType.ClrType, type => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        jsonColumns.Add(builder.Metadata.Name);
        return builder;
    }

    /// <summary>Configures the property so that the property value is converted to and from the database using the <see cref="StringArrayValueConverter"/>.</summary>
    /// <param name="builder">The builder instance.</param>
    /// <returns>The same builder instance so that multiple configuration calls can be chained.</returns>
    public static PropertyBuilder HasStringArrayConversion(this PropertyBuilder<string[]> builder) {
        builder.HasConversion(new StringArrayValueConverter());
        return builder;
    }
}
