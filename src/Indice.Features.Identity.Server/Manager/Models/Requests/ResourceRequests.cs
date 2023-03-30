﻿using System.Collections.Generic;
using Indice.Types;

namespace Indice.Features.Identity.Server.Manager.Models.Requests;

/// <summary>Models a resource (API or identity) that will be created on the server.</summary>
public class CreateResourceRequest : BasicResourceRequest
{
    /// <summary>The unique name of the resource.</summary>
    public string Name { get; set; }
    /// <summary>List of allowed signing algorithms for access token. If empty, will use the server default signing algorithm.</summary>
    public string AllowedAccessTokenSigningAlgorithms { get; set; }
    /// <summary>List of associated user claims that should be included when this resource is requested.</summary>
    public List<string> UserClaims { get; set; }
    /// <summary>Translations.</summary>
    public TranslationDictionary<ApiScopeTranslation> Translations { get; set; } = new TranslationDictionary<ApiScopeTranslation>();
}

/// <summary>Models an API scope that will be created on the server.</summary>
public class CreateApiScopeRequest : CreateResourceRequest
{
    /// <summary>Determines whether this scope is required or not.</summary>
    public bool Required { get; set; }
    /// <summary>Determines whether this scope should be displayed emphasized or not.</summary>
    public bool Emphasize { get; set; }
    /// <summary>Determines whether this scope should be displayed in the discovery document or not.</summary>
    public bool ShowInDiscoveryDocument { get; set; }
}

/// <summary>Models an API resource that will be updated on the server.</summary>
public class UpdateApiResourceRequest : BasicResourceRequest
{
    /// <summary>Specifies whether the resource is enabled.</summary>
    public bool Enabled { get; set; }
}

/// <summary>Models an identity resource that will be updated on the server.</summary>
public class UpdateIdentityResourceRequest : BasicResourceRequest
{
    /// <summary>Specifies whether the resource is enabled.</summary>
    public bool Enabled { get; set; }
    /// <summary>Determines whether this resource should be displayed emphasized or not.</summary>
    public bool Emphasize { get; set; }
    /// <summary>Determines whether this resource is required or not.</summary>
    public bool Required { get; set; }
    /// <summary>Determines whether this scope should be displayed in the discovery document or not.</summary>
    public bool ShowInDiscoveryDocument { get; set; }
}

/// <summary>Models an API scope that will be updated on the server.</summary>
public class UpdateApiScopeRequest : BasicResourceRequest
{
    /// <summary>Determines whether this scope is required or not.</summary>
    public bool Required { get; set; }
    /// <summary>Determines whether this scope should be displayed emphasized or not.</summary>
    public bool Emphasize { get; set; }
    /// <summary>Determines whether this scope should be displayed in the discovery document or not.</summary>
    public bool ShowInDiscoveryDocument { get; set; }
    /// <summary>Translations.</summary>
    public TranslationDictionary<ApiScopeTranslation> Translations { get; set; } = new TranslationDictionary<ApiScopeTranslation>();
}

/// <summary>Models a resource request (identity or API).</summary>
public class BasicResourceRequest
{
    /// <summary>Display name of the resource.</summary>
    public string DisplayName { get; set; }
    /// <summary>Description of the resource.</summary>
    public string Description { get; set; }
}
