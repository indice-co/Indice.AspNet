﻿// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Indice.AspNetCore.Identity.Models;

/// <summary>Logout request model.</summary>
public class LogoutInputModel
{
    /// <summary>The logout id.</summary>
    public string LogoutId { get; set; }
    /// <summary>The id of the current client in the request. </summary>
    public string ClientId { get; set; }
}
