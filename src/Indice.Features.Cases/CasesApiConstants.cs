﻿using System.Reflection;
using Indice.Features.Cases.Interfaces;

namespace Indice.Features.Cases
{
    /// <summary>
    /// Constant values for Cases Api
    /// </summary>
    public static class CasesApiConstants
    {
        /// <summary>
        /// The assembly name.
        /// </summary>
        public static readonly string AssemblyName = Assembly.GetExecutingAssembly().GetName().Name;
        
        /// <summary>
        /// Authentication scheme name used by Cases API.
        /// </summary>
        public const string AuthenticationScheme = "Bearer";
        
        /// <summary>
        /// Cases API scope.
        /// </summary>
        public const string Scope = "cases-api";
        
        /// <summary>
        /// Default database schema.
        /// </summary>
        public const string DatabaseSchema = "case";

        /// <summary>
        /// The default language key that will be used at <see cref="IJsonTranslationService"/>.
        /// </summary>
        public static string DefaultTranslationLanguage = "el";

        /// <summary>
        /// The default groupId claim type
        /// </summary>
        public static string DefaultGroupIdClaimType = "groupId";

        /// <summary>
        /// Cases API policies.
        /// </summary>
        public static class Policies
        {
            /// <summary>
            /// A user must have the BeCasesManager role to be authorized for AdminCases Feature 
            /// </summary>
            public const string BeCasesManager = nameof(BeCasesManager);
          
            /// <summary>
            /// A user must have the BeCasesUser role to be authorized for MyCases Feature 
            /// </summary>
            public const string BeCasesUser = nameof(BeCasesUser);
        }

        /// <summary>
        /// Cases Api default channels.
        /// </summary>
        public static class Channels
        {
            /// <summary>
            /// Customer channel, for the cases that have been created through MyCases interface
            /// </summary>
            public const string Customer = nameof(Customer);

            /// <summary>
            /// Agent channel, for the cases that have been created through AdminCases interface
            /// </summary>
            public const string Agent = nameof(Agent);
        }
    }
}
