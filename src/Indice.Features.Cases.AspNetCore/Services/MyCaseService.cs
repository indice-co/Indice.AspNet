﻿using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Indice.Features.Cases.Data;
using Indice.Features.Cases.Data.Models;
using Indice.Features.Cases.Events;
using Indice.Features.Cases.Interfaces;
using Indice.Features.Cases.Models;
using Indice.Features.Cases.Models.Responses;
using Indice.Features.Cases.Resources;
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
        private readonly CaseSharedResourceService _caseSharedResourceService;

        public MyCaseService(
            CasesDbContext dbContext,
            ICaseTypeService caseTypeService,
            ICaseEventService caseEventService,
            IMyCaseMessageService caseMessageService,
            IJsonTranslationService jsonTranslationService,
            CaseSharedResourceService caseSharedResourceService) : base(dbContext) {
            _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
            _caseTypeService = caseTypeService ?? throw new ArgumentNullException(nameof(caseTypeService));
            _caseEventService = caseEventService ?? throw new ArgumentNullException(nameof(caseEventService));
            _caseMessageService = caseMessageService ?? throw new ArgumentNullException(nameof(caseMessageService));
            _jsonTranslationService = jsonTranslationService ?? throw new ArgumentNullException(nameof(jsonTranslationService));
            _caseSharedResourceService = caseSharedResourceService;
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
            var @case = await GetDbCaseById(caseId, userId);
            if (@case is null) {
                return null!;
            }

            // the customer should be able to see only cases that have been created from him/herself!
            if (@case.Channel == CasesApiConstants.Channels.Agent) {
                throw new Exception("Case not found.");
            }

            var caseData = await GetDbCaseData(caseId, userId, @case);
            var caseDetails = await GetCaseByIdInternal(@case, caseData, true, schemaKey: SchemaSelector);
            return caseDetails ?? throw new Exception("Case not found."); // todo  proper exception 
        }

        public async Task<ResultSet<MyCasePartial>> GetCases(ClaimsPrincipal user, ListOptions<GetMyCasesListFilter> options) {
            var userId = user.FindSubjectId();
            var dbCaseQueryable = _dbContext.Cases
                .Include(c => c.CaseType)
                .Include(c => c.Comments)
                .Include(c => c.Checkpoints)
                .ThenInclude(ch => ch.CheckpointType)
                .AsQueryable()
                .Where(p => (p.CreatedBy.Id == userId || p.Customer.UserId == userId) && !p.Draft);

            foreach (var tag in options.Filter?.CaseTypeTags ?? new List<string>()) {
                // If there are more than 1 tag, the linq will be translated into "WHERE [Tag] LIKE %tag1% AND [Tag] LIKE %tag2% ..."
                dbCaseQueryable = dbCaseQueryable.Where(dbCase => EF.Functions.Like(dbCase.CaseType.Tags, $"%{tag}%"));
            }

            // filter PublicStatuses
            if (options.Filter?.PublicStatuses != null && options.Filter.PublicStatuses.Count() > 0) {
                var expressions = options.Filter.PublicStatuses.Select(status => (Expression<Func<DbCase, bool>>)(c => c.PublicCheckpoint.CheckpointType.PublicStatus == status));
                // Aggregate the expressions with OR that resolves to SQL: dbCase.PublicCheckpoint.CheckpointType.PublicStatus == status1 OR == status2 etc
                var aggregatedExpression = expressions.Aggregate((expression, next) => {
                    var orExp = Expression.OrElse(expression.Body, Expression.Invoke(next, expression.Parameters));
                    return Expression.Lambda<Func<DbCase, bool>>(orExp, expression.Parameters);
                });
                dbCaseQueryable = dbCaseQueryable.Where(aggregatedExpression);
            }

            // filter CreatedFrom
            if (options.Filter?.CreatedFrom != null) {
                dbCaseQueryable = dbCaseQueryable.Where(c => c.CreatedBy.When >= options.Filter.CreatedFrom);
            }
            // filter CreatedTo
            if (options.Filter?.CreatedTo != null) {
                dbCaseQueryable = dbCaseQueryable.Where(c => c.CreatedBy.When <= options.Filter.CreatedTo);
            }
            // filter CompletedFrom
            if (options.Filter?.CompletedFrom != null) {
                dbCaseQueryable = dbCaseQueryable.Where(c => c.CompletedBy != null && c.CompletedBy.When != null && c.CompletedBy.When >= options.Filter.CompletedFrom);
            }
            // filter CompletedTo
            if (options.Filter?.CompletedTo != null) {
                dbCaseQueryable = dbCaseQueryable.Where(c => c.CompletedBy != null && c.CompletedBy.When != null && c.CompletedBy.When <= options.Filter.CompletedTo);
            }

            // filter CaseTypeCodes
            if (options.Filter?.CaseTypeCodes != null && options.Filter.CaseTypeCodes.Count() > 0) {
                dbCaseQueryable = dbCaseQueryable.Where(c => options.Filter.CaseTypeCodes.Contains(c.CaseType.Code));
            }

            var myCasePartialQueryable =
                    dbCaseQueryable.Select(p => new MyCasePartial {
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
                        Message = _caseSharedResourceService.GetLocalizedHtmlString(p.Comments // get the translated version of the comment (if exist)
                            .OrderByDescending(p => p.CreatedBy.When)
                            .FirstOrDefault(c => !c.Private)
                            .Text ?? string.Empty),
                        Translations = TranslationDictionary<MyCasePartialTranslation>.FromJson(p.CaseType.Translations)
                    })
                    .Where(p => p.PublicStatus != CasePublicStatus.Deleted);// Do not fetch cases in deleted checkpoint

            // sorting option
            if (string.IsNullOrEmpty(options.Sort)) {
                options.Sort = $"{nameof(MyCasePartial.Created)}-";
            }

            var result = await myCasePartialQueryable.ToResultSetAsync(options);

            if (options.Filter?.Data != null) {
                var casesIdList = result.Items.Select(c => c.Id).ToList();
                // note: this searches all "data history" of case
                var filteredcasesIdList = await _dbContext.CaseData
                    .AsNoTracking()
                    .Where(dbCaseData => casesIdList.Contains(dbCaseData.CaseId))
                    .Where(options.Filter.Data)
                    .Select(d => d.CaseId)
                    .Distinct()
                    .AsQueryable()
                    .ToListAsync();

                result.Items = result.Items.Where(x => filteredcasesIdList.Contains(x.Id)).ToArray();
                result.Count = result.Items.Count();
            }

            // translate
            for (var i = 0; i < result.Items.Length; i++) {
                result.Items[i] = result.Items[i].Translate(CultureInfo.CurrentCulture.TwoLetterISOLanguageName, true);
            }

            return result;
        }

        public async Task<CaseTypePartial> GetCaseType(string caseTypeCode) {
            if (caseTypeCode == null) throw new ArgumentNullException(nameof(caseTypeCode));
            var dbCaseType = await GetCaseTypeInternal(caseTypeCode);
            if (dbCaseType == null) {
                throw new Exception("Case type not found."); // todo  proper exception & handle from problemConfig (NotFound)
            }

            var caseType = new CaseTypePartial {
                Code = dbCaseType.Code,
                DataSchema = GetSingleOrMultiple(SchemaSelector, dbCaseType.DataSchema),
                Layout = GetSingleOrMultiple(SchemaSelector, dbCaseType.Layout),
                LayoutTranslations = dbCaseType.LayoutTranslations,
                Title = dbCaseType.Title,
                Translations = TranslationDictionary<CaseTypeTranslation>.FromJson(dbCaseType.Translations)
            };

            // translate case type
            caseType = TranslateCaseType(caseType, CultureInfo.CurrentCulture.TwoLetterISOLanguageName, true);

            return caseType;
        }

        public async Task<ResultSet<CaseTypePartial>> GetCaseTypes(ListOptions<GetMyCaseTypesListFilter> options) {
            var caseTypesQueryable = _dbContext.CaseTypes.AsQueryable();

            foreach (var tag in options.Filter?.CaseTypeTags ?? new List<string>()) {
                // If there are more than 1 tag, the linq will be translated into "WHERE [Tag] LIKE %tag1% AND [Tag] LIKE %tag2% ..."
                caseTypesQueryable = caseTypesQueryable.Where(caseType => EF.Functions.Like(caseType.Tags, $"%{tag}%"));
            }

            var caseTypes = await caseTypesQueryable
                .Select(dbCaseType => new CaseTypePartial {
                    Id = dbCaseType.Id,
                    Title = dbCaseType.Title,
                    Description = dbCaseType.Description,
                    Category = dbCaseType.Category,
                    DataSchema = GetSingleOrMultiple(SchemaSelector, dbCaseType.DataSchema),
                    Layout = GetSingleOrMultiple(SchemaSelector, dbCaseType.Layout),
                    LayoutTranslations = dbCaseType.LayoutTranslations,
                    Config = dbCaseType.Config,
                    Code = dbCaseType.Code,
                    Translations = TranslationDictionary<CaseTypeTranslation>.FromJson(dbCaseType.Translations)
                })
                .ToListAsync();

            // sort by Config.Order
            caseTypes = caseTypes.OrderBy(c => c, new CaseTypeComparer()).ToList();

            // translate case types
            for (var i = 0; i < caseTypes.Count; i++) {
                caseTypes[i] = TranslateCaseType(caseTypes[i], CultureInfo.CurrentCulture.TwoLetterISOLanguageName, true);
            }

            return caseTypes.ToResultSet();
        }

        private CaseTypePartial TranslateCaseType(CaseTypePartial caseTypePartial, string culture, bool includeTranslations) {
            var caseType = caseTypePartial.Translate(culture, includeTranslations);
            caseType.Layout = _jsonTranslationService.Translate(caseType.Layout, caseTypePartial.LayoutTranslations, CultureInfo.CurrentCulture.TwoLetterISOLanguageName);
            caseType.DataSchema = _jsonTranslationService.Translate(caseType.DataSchema, caseTypePartial.LayoutTranslations, CultureInfo.CurrentCulture.TwoLetterISOLanguageName);
            return caseType;
        }

        private async Task<DbCase?> GetDbCaseById(Guid caseId, string userId) {
            return await _dbContext.Cases
                .AsNoTracking()
                .Include(c => c.CaseType)
                .Include(c => c.PublicCheckpoint)
                .Include(c => c.Attachments)
                .SingleOrDefaultAsync(dbCase => dbCase.Id == caseId && (dbCase.CreatedBy.Id == userId || dbCase.Customer.UserId == userId));
        }

        private async Task<DbCaseData?> GetDbCaseData(Guid caseId, string userId, DbCase? @case) {
            var caseDataQueryable = _dbContext.CaseData
                .AsNoTracking()
                .Where(dbCaseData => dbCaseData.CaseId == caseId)
                .AsQueryable();

            // If the case is not Completed, return customer's own data (most recent)
            if (@case?.CompletedBy?.When == null) {
                caseDataQueryable = caseDataQueryable.Where(dbCaseData => dbCaseData.CreatedBy.Id == userId);
            }

            caseDataQueryable = caseDataQueryable.OrderByDescending(c => c.CreatedBy.When);
            return await caseDataQueryable.FirstOrDefaultAsync();
        }
    }

    /// <summary>
    /// A Comparer for case types.
    /// </summary>
    public class CaseTypeComparer : IComparer<CaseTypePartial>
    {
        /// <summary>
        /// Compares case types.
        /// </summary>
        /// <param name="ct1"></param>
        /// <param name="ct2"></param>
        public int Compare(CaseTypePartial? ct1, CaseTypePartial? ct2) {
            if (string.IsNullOrEmpty(ct1?.Config)) {
                return -1;
            }
            if (string.IsNullOrEmpty(ct2?.Config)) {
                return 1;
            }

            var ct1Config = JsonSerializer.Deserialize<JsonDocument>(ct1.Config);
            var ct2Config = JsonSerializer.Deserialize<JsonDocument>(ct2.Config);

            var ct1OrderExists = ct1Config!.RootElement.TryGetProperty("Order", out var ct1Order);
            var ct2OrderExists = ct2Config!.RootElement.TryGetProperty("Order", out var ct2Order);

            return (ct1OrderExists ? ct1Order.GetInt32() : 0) - (ct2OrderExists ? ct2Order.GetInt32() : 0);
        }
    }
}