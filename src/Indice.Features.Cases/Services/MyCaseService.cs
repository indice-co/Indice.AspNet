﻿using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Indice.Features.Cases.Data;
using Indice.Features.Cases.Data.Models;
using Indice.Features.Cases.Events;
using Indice.Features.Cases.Interfaces;
using Indice.Features.Cases.Models;
using Indice.Features.Cases.Models.Responses;
using Indice.Security;
using Indice.Types;
using Microsoft.EntityFrameworkCore;

namespace Indice.Features.Cases.Services
{
    internal class MyCaseService : BaseCaseService, IMyCaseService
    {
        private const string SchemaSelector = "frontend";
        private readonly CasesDbContext _dbContext;
        private readonly ICaseTypeService _caseTypeService;
        private readonly ICaseEventService _caseEventService;
        private readonly IMyCaseMessageService _caseMessageService;
        private readonly IJsonTranslationService _jsonTranslationService;

        public MyCaseService(
            CasesDbContext dbContext,
            ICaseTypeService caseTypeService,
            ICaseEventService caseEventService,
            IMyCaseMessageService caseMessageService,
            IJsonTranslationService jsonTranslationService) : base(dbContext) {
            _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
            _caseTypeService = caseTypeService ?? throw new ArgumentNullException(nameof(caseTypeService));
            _caseEventService = caseEventService ?? throw new ArgumentNullException(nameof(caseEventService));
            _caseMessageService = caseMessageService ?? throw new ArgumentNullException(nameof(caseMessageService));
            _jsonTranslationService = jsonTranslationService ?? throw new ArgumentNullException(nameof(jsonTranslationService));
        }

        public async Task<CreateCaseResponse> CreateDraft(ClaimsPrincipal user,
            string caseTypeCode,
            string groupId,
            CustomerMeta customer,
            Dictionary<string, string> metadata,
            string? channel) {
            if (user is null) throw new ArgumentNullException(nameof(user));
            if (caseTypeCode == null) throw new ArgumentNullException(nameof(caseTypeCode));

            var caseType = await _caseTypeService.Get(caseTypeCode);
            var entity = await CreateDraftInternal(
                _caseMessageService,
                user,
                caseType,
                groupId,
                customer,
                metadata,
                channel ?? CasesApiConstants.Channels.Customer);

            return new CreateCaseResponse {
                Id = entity.Id,
                Created = entity.CreatedBy!.When!.Value
            };
        }

        public async Task UpdateData(ClaimsPrincipal user, Guid caseId, string data) {
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (caseId == default) throw new ArgumentNullException(nameof(caseId));
            if (data == null) throw new ArgumentNullException(nameof(data));
            await _caseMessageService.Send(caseId, user, new Message { Data = data });
        }

        public async Task Submit(ClaimsPrincipal user, Guid caseId) {
            if (caseId == default) throw new ArgumentNullException(nameof(caseId));

            var @case = await GetDbCaseForCustomer(caseId, user);
            if (!@case.Draft) {
                throw new Exception("Case status is not draft."); // todo proper exception (BadRequest)
            }

            @case.Draft = false;
            await _dbContext.SaveChangesAsync();
            await _caseEventService.Publish(new CaseSubmittedEvent(@case, @case.CaseType.Code));
        }

        public async Task<CaseDetails> GetCaseById(ClaimsPrincipal user, Guid caseId) {
            var userId = user.FindSubjectId();
            var @case = await _dbContext.Cases
                .AsNoTracking()
                .Include(c => c.CaseType)
                .Include(c => c.PublicCheckpoint)
                .Include(c => c.Attachments)
                .SingleOrDefaultAsync(dbCase => dbCase.Id == caseId && (dbCase.CreatedBy.Id == userId || dbCase.Customer.UserId == userId));

            if (@case is null) {
                return null!;
            }

            var caseDataQueryable = _dbContext.CaseData
                .AsNoTracking()
                .Where(dbCaseData => dbCaseData.CaseId == caseId)
                .AsQueryable();

            // If the case has been created from the Customer itself, return his own data (most recent)
            if (@case.Channel == CasesApiConstants.Channels.Customer) {
                caseDataQueryable = caseDataQueryable
                    .Where(dbCaseData => dbCaseData.CreatedBy.Id == userId)
                    .OrderByDescending(c => c.CreatedBy.When);
            }

            // If the case has been created from an Agent, return the first record of Agent's data
            if (@case.Channel == CasesApiConstants.Channels.Agent) {
                caseDataQueryable = caseDataQueryable.OrderBy(c => c.CreatedBy.When);
            }

            var caseData = await caseDataQueryable.FirstOrDefaultAsync();
            var caseDetails = await GetCaseByIdInternal(@case, caseData, true, schemaKey: SchemaSelector);
            if (caseDetails == null) {
                throw new Exception("Case not found."); // todo  proper exception & handle from problemConfig (NotFound)
            }
            return caseDetails;
        }

        public async Task<MyCasePartial> GetMyCaseById(ClaimsPrincipal user, Guid caseId) {
            var userId = user.FindSubjectId();
            var query = await _dbContext.Cases
                .Include(c => c.CaseType)
                .Include(c => c.Comments)
                .Include(c => c.Checkpoints)
                .ThenInclude(ch => ch.CheckpointType)
                .AsQueryable()
                .SingleOrDefaultAsync(dbCase => dbCase.Id == caseId && (dbCase.CreatedBy.Id == userId || dbCase.Customer.UserId == userId));

            var myCase = new MyCasePartial {
                Id = query.Id,
                Created = query.CreatedBy.When,
                CaseTypeCode = query.CaseType.Code,
                PublicStatus = query.Checkpoints
                    .OrderByDescending(c => c.CreatedBy.When)
                    .FirstOrDefault(c => !c.CheckpointType.Private)!
                    .CheckpointType.PublicStatus,
                Checkpoint = query.Checkpoints
                    .OrderByDescending(c => c.CreatedBy.When)
                    .FirstOrDefault(c => !c.CheckpointType.Private)!
                    .CheckpointType.Name,
                Message = query.Comments
                    .OrderByDescending(p => p.CreatedBy.When)
                    .FirstOrDefault(c => !c.Private)?
                    .Text
            };
            return myCase;
        }

        public async Task<ResultSet<MyCasePartial>> GetCases(ClaimsPrincipal user, ListOptions<GetMyCasesListFilter> options) {
            var userId = user.FindSubjectId();
            var query = _dbContext.Cases
                .Include(c => c.CaseType)
                .Include(c => c.Comments)
                .Include(c => c.Checkpoints)
                .ThenInclude(ch => ch.CheckpointType)
                .AsQueryable()
                .Where(p => (p.CreatedBy.Id == userId || p.Customer.UserId == userId) && !p.Draft) // todo na filtrarei kai me CustomerId 
                .Select(p => new MyCasePartial {
                    Id = p.Id,
                    Created = p.CreatedBy.When,
                    CaseTypeCode = p.CaseType.Code,
                    PublicStatus = p.Checkpoints
                        .OrderByDescending(c => c.CreatedBy.When)
                        .FirstOrDefault(c => !c.CheckpointType.Private)!
                        .CheckpointType.PublicStatus,
                    Checkpoint = p.Checkpoints
                        .OrderByDescending(c => c.CreatedBy.When)
                        .FirstOrDefault(c => !c.CheckpointType.Private)!
                        .CheckpointType.Name,
                    Message = p.Comments
                        .OrderByDescending(p => p.CreatedBy.When)
                        .FirstOrDefault(c => !c.Private)
                        .Text,
                    Translations = TranslationDictionary<MyCasePartialTranslation>.FromJson(p.CaseType.Translations)
                })
                .Where(p => p.PublicStatus != CasePublicStatus.Deleted);// Do not fetch cases in deleted checkpoint

            if (string.IsNullOrEmpty(options.Sort)) {
                options.Sort = $"{nameof(MyCasePartial.Created)}-";
            }

            var result = await query.ToResultSetAsync(options);
            // translate
            for (var i = 0; i < result.Items.Length; i++) {
                result.Items[i] = result.Items[i].Translate(CultureInfo.CurrentCulture.TwoLetterISOLanguageName, true);
            }
            return result;
        }

        public async Task<CaseType> GetCaseType(string caseTypeCode) {
            var dbCaseType = await GetCaseTypeInternal(caseTypeCode);
            if (dbCaseType == null) {
                throw new Exception("Case type not found."); // todo  proper exception & handle from problemConfig (NotFound)
            }

            var caseType = new CaseType {
                Code = dbCaseType.Code,
                DataSchema = GetSingleOrMultiple(SchemaSelector, dbCaseType.DataSchema),
                Layout = GetSingleOrMultiple(SchemaSelector, dbCaseType.Layout),
                Title = dbCaseType.Title,
                Translations = TranslationDictionary<CaseTypeTranslation>.FromJson(dbCaseType.Translations)
            };

            // translate case type
            caseType = caseType.Translate(CultureInfo.CurrentCulture.TwoLetterISOLanguageName, true);
            caseType.Layout = _jsonTranslationService.Translate(caseType.Layout, dbCaseType.LayoutTranslations, CultureInfo.CurrentCulture.TwoLetterISOLanguageName);
            caseType.DataSchema = _jsonTranslationService.Translate(caseType.DataSchema, dbCaseType.LayoutTranslations, CultureInfo.CurrentCulture.TwoLetterISOLanguageName);

            return caseType;
        }
    }
}