﻿using FluentValidation;
using Indice.Features.Identity.UI.Models;
using Indice.Validation;
using Microsoft.Extensions.Localization;

namespace Indice.Features.Identity.UI.Validators;

/// <summary>Validator for <see cref="EnableMfaSmsInputModel"/> class.</summary>
public class EnableMfaSmsInputModelValidator : AbstractValidator<EnableMfaSmsInputModel>
{
    private readonly IStringLocalizer<EnableMfaSmsInputModelValidator> _localizer;

    /// <summary>Creates a new instance of <see cref="EnableMfaSmsInputModelValidator"/> class.</summary>
    /// <param name="localizer">Represents a service that provides localized strings.</param>
    /// <exception cref="ArgumentNullException"></exception>
    public EnableMfaSmsInputModelValidator(IStringLocalizer<EnableMfaSmsInputModelValidator> localizer) {
        _localizer = localizer ?? throw new ArgumentNullException(nameof(localizer));
        RuleFor(x => x.PhoneNumber).NotEmpty().WithName(_localizer["Phone Number"]).GreekPhoneNumber().WithMessage(_localizer["Mobile phone must start with '69' and have 10 digits."]);
    }
}
