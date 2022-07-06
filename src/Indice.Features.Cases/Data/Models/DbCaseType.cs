﻿using System;
using System.Collections.Generic;

namespace Indice.Features.Cases.Data.Models
{
    public class DbCaseType
    {
        public Guid Id { get; set; }
        public string Code { get; set; }
        public string Title { get; set; }
        public string DataSchema { get; set; }
        public string Layout { get; set; }
        public string? Translations { get; set; }
        public string? LayoutTranslations { get; set; }
        public virtual List<DbCheckpointType> CheckpointTypes { get; set; } // Available checkpoints for this case
    }
}