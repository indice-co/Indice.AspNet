﻿using System;
using System.Collections.Generic;
using System.Linq;
using Bogus;
using IdentityModel;
using Indice.Features.Identity.Core.Models;
using Microsoft.AspNetCore.Identity;

namespace Indice.Features.Identity.Core.Data
{
    /// <summary>
    /// Provides functionality to generate test users for development purposes.
    /// </summary>
    internal class InitialUsers<TUser> where TUser : User
    {
        private const int DefaultNumberOfUsers = 100;

        private static readonly Faker<TUser> UserFaker = new Faker<TUser>()
            .RuleFor(x => x.Id, faker => $"{Guid.NewGuid()}")
            .RuleFor(x => x.Admin, faker => false)
            .RuleFor(x => x.ConcurrencyStamp, faker => $"{Guid.NewGuid()}")
            .RuleFor(x => x.SecurityStamp, faker => $"{Guid.NewGuid()}")
            .RuleFor(x => x.CreateDate, faker => faker.Date.BetweenOffset(DateTimeOffset.UtcNow.AddYears(-4), DateTimeOffset.UtcNow))
            .RuleFor(x => x.PhoneNumber, faker => faker.Phone.PhoneNumber())
            .RuleFor(x => x.PhoneNumberConfirmed, faker => faker.PickRandom(true, false))
            .RuleFor(x => x.EmailConfirmed, faker => faker.PickRandom(true, false))
            .RuleFor(x => x.LastSignInDate, faker => faker.Date.PastOffset(2))
            .RuleFor(x => x.Claims, (faker, user) => {
                user.Claims.Add(new IdentityUserClaim<string> {
                    ClaimType = JwtClaimTypes.GivenName,
                    ClaimValue = faker.Name.FirstName(),
                    UserId = user.Id
                });
                user.Claims.Add(new IdentityUserClaim<string> {
                    ClaimType = JwtClaimTypes.FamilyName,
                    ClaimValue = faker.Name.LastName(),
                    UserId = user.Id
                });
                return user.Claims;
            })
            .RuleFor(x => x.Email, (faker, user) => faker.Internet.Email(
                firstName: user.Claims.Single(x => x.ClaimType == JwtClaimTypes.GivenName).ClaimValue,
                lastName: user.Claims.Single(x => x.ClaimType == JwtClaimTypes.FamilyName).ClaimValue
            ))
            .RuleFor(x => x.UserName, (faker, user) => user.Email)
            .RuleFor(x => x.NormalizedEmail, (faker, user) => user.Email.ToUpper())
            .RuleFor(x => x.NormalizedUserName, (faker, user) => user.Email.ToUpper());

        /// <summary>
        /// Gets a collection of test users.
        /// </summary>
        /// <param name="numberOfUsers">The number of test users to generate. Default is 100.</param>
        public static IReadOnlyCollection<TUser> Get(int? numberOfUsers = null) {
            var random = new Random(1);
            Randomizer.Seed = random;
            return UserFaker.Generate(numberOfUsers ?? DefaultNumberOfUsers).ToList();
        }
    }
}
