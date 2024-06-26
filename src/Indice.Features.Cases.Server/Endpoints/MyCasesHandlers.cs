﻿using System;
using Indice.Features.Cases.Interfaces;
using Indice.Features.Cases.Models;
using Indice.Features.Cases.Models.Responses;
using Indice.Types;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Indice.Features.Cases.Server.Endpoints;
internal static class MyCasesHandlers
{
    public static async Task<Ok<ResultSet<CaseTypePartial>>> GetCaseTypes(
        IMyCaseService myCaseService,
        [AsParameters] ListOptions options, [AsParameters] GetMyCaseTypesListFilter filter) {
        var results = await myCaseService.GetCaseTypes(ListOptions.Create(options, filter));
        return TypedResults.Ok(results);
    }
    public static async Task<Ok<CaseTypePartial>> GetCaseType(
        IMyCaseService myCaseService,
        string caseTypeCode)
    {
        var result = await myCaseService.GetCaseType(caseTypeCode);
        return TypedResults.Ok(result);
    }
}
