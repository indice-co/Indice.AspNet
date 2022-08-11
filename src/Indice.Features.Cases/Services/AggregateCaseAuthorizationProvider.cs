﻿using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Indice.Features.Cases.Interfaces;
using Indice.Features.Cases.Models;
using Indice.Features.Cases.Models.Responses;

namespace Indice.Features.Cases.Services
{
    internal class AggregateCaseAuthorizationProvider : ICaseAuthorizationProvider
    {
        private readonly IEnumerable<ICaseAuthorizationService> _listOfServices;

        public AggregateCaseAuthorizationProvider(IEnumerable<ICaseAuthorizationService> listOfServices) {
            _listOfServices = listOfServices ?? throw new ArgumentNullException(nameof(listOfServices));
        }

        public async Task<GetCasesListFilter> Filter(ClaimsPrincipal user, GetCasesListFilter filter) {
            foreach (var authorizationService in _listOfServices) {
                filter = await authorizationService.ApplyFilterFor(user, filter);
            }
            return filter;
        }

        public async Task<bool> IsValid(ClaimsPrincipal user, CaseDetails caseDetails) {
            foreach (var authorizationService in _listOfServices) {
                if (!await authorizationService.IsValid(user, caseDetails)) {
                    return false;
                }
            }
            return true;
        }
    }
}
