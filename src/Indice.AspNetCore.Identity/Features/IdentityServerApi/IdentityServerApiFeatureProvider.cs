﻿using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace Indice.AspNetCore.Identity.Features
{
    /// <summary>
    /// A provider for <see cref="ControllerFeature"/>.
    /// </summary>
    internal class IdentityServerApiFeatureProvider : IApplicationFeatureProvider<ControllerFeature>
    {
        private static IReadOnlyList<TypeInfo> ControllerTypes => new List<TypeInfo>() {
            typeof(ClaimTypeController).GetTypeInfo(),
            typeof(ClientController).GetTypeInfo(),
            typeof(DashboardController).GetTypeInfo(),
            typeof(ResourcesController).GetTypeInfo(),
            typeof(RoleController).GetTypeInfo(),
            typeof(UserController).GetTypeInfo()
        };

        /// <summary>
        /// Updates the feature instance ny adding the IdentityServer API controllers.
        /// </summary>
        /// <param name="parts">The list of <see cref="ApplicationPart"/> instances in the application.</param>
        /// <param name="feature">The feature instance to populate.</param>
        public void PopulateFeature(IEnumerable<ApplicationPart> parts, ControllerFeature feature) {
            foreach (var controllerType in ControllerTypes) {
                if (!feature.Controllers.Any(x => x.Name == controllerType.Name)) {
                    feature.Controllers.Add(controllerType);
                }
            }
        }
    }
}
