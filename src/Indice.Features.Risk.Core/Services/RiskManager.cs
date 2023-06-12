﻿using Indice.Features.Risk.Core.Abstractions;
using Indice.Features.Risk.Core.Configuration;
using Indice.Features.Risk.Core.Data.Models;

namespace Indice.Features.Risk.Core.Services;

internal class RiskManager<TTransaction> where TTransaction : Transaction
{
    public RiskManager(
        IEnumerable<IRule<TTransaction>> rules,
        IEnumerable<RuleConfig> ruleConfigurations
    ) {
        Rules = rules ?? throw new ArgumentNullException(nameof(rules));
        RuleConfigurations = ruleConfigurations ?? throw new ArgumentNullException(nameof(ruleConfigurations));
    }

    public IEnumerable<IRule<TTransaction>> Rules { get; }
    public IEnumerable<RuleConfig> RuleConfigurations { get; }
}
