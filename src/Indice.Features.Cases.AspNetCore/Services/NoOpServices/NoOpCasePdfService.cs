﻿using Indice.Features.Cases.Interfaces;

namespace Indice.Features.Cases.Services.NoOpServices
{
    internal class NoOpCasePdfService : ICasePdfService
    {
        public Task<byte[]> HtmlToPdfAsync(string htmlTemplate, bool isPortrait = true) =>
            throw new NotImplementedException("Implement this interface with your own data sources.");
    }
}
