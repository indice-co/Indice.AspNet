﻿using Microsoft.AspNetCore.Routing;

namespace Indice.AspNetCore.TagHelpers;

/// <summary>Tag helper extensions</summary>
public static class TagHelperExtensions
{
    internal static RouteValueDictionary ToRouteValueDictionary(this IEnumerable<KeyValuePair<string, string>> routeValues) {
        var values = new RouteValueDictionary();
        foreach (var item in routeValues) {
            values.Add(item.Key, item.Value);
        }
        return values;
    }
}
