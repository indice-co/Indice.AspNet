﻿namespace Indice.Features.Cases.Data.Models;

#pragma warning disable 1591
public class DbCaseData
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CaseId { get; set; }
    public AuditMeta CreatedBy { get; set; }
    public dynamic Data { get; set; }
    public virtual DbCase Case { get; set; }
}
#pragma warning restore 1591
