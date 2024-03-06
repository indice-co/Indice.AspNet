﻿using System.Text;
using System.Text.Json;
using Indice.Extensions.Configuration.Database.Data.Models;
using Indice.Features.Risk.Core.Abstractions;
using Indice.Features.Risk.Core.Data;
using Indice.Features.Risk.Core.Models;
using Indice.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace Indice.Features.Risk.Core.Stores;
internal class RiskRuleStoreEntityFrameworkCore : IRiskRuleOptionsStore
{
    private readonly RiskDbContext _context;

    public RiskRuleStoreEntityFrameworkCore(RiskDbContext context) {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public async Task<Dictionary<string, string>> GetRiskRuleOptions(string ruleName) {
        if (string.IsNullOrWhiteSpace(ruleName)) {
            return new Dictionary<string, string>();
        }
        var results = await _context.AppSettings
            .AsNoTracking()
            .Where(x => x.Key.StartsWith($"{Constants.RuleOptionsSectionName}:{ruleName}:"))
            .ToDictionaryAsync(
                x => x.Key.Replace($"{Constants.RuleOptionsSectionName}:{ruleName}:", string.Empty),
                x => x.Value
            );
        return results;
    }

    public async Task UpdateRiskRuleOptions(string ruleName, RuleOptions jsonElement) {
        if (string.IsNullOrWhiteSpace(ruleName)) {
            return;
        }
        var jsonString = JsonSerializer.Serialize(jsonElement, JsonSerializerOptionDefaults.GetDefaultSettings());
        using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(jsonString))) {
            var configurationBuilder = new ConfigurationBuilder();
            configurationBuilder.AddJsonStream(stream);
            var configuration = configurationBuilder.Build();
            var settings = configuration.AsEnumerable().Where(x => x.Value is not null);
            foreach (var item in settings) {
                var key = $"{Constants.RuleOptionsSectionName}:{ruleName}:{item.Key}";
                var existingItem = await _context.AppSettings.FirstOrDefaultAsync(x => x.Key.ToLower() == key.ToLower());
                if (existingItem is not null) {
                    existingItem.Value = item.Value;
                } else {
                    var newItem = new DbAppSetting {
                        Key = key,
                        Value = item.Value
                    };
                    await _context.AppSettings.AddAsync(newItem);
                }
            }
            await _context.SaveChangesAsync();
        }
    }
}
