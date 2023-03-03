﻿using Indice.Features.Cases.Models;
using Indice.Features.Cases.Models.Responses;

namespace Indice.Features.Cases.Interfaces
{
    /// <summary>
    /// The pdf service for generating PDF from case data.
    /// </summary>
    public interface ICasePdfService
    {
        /// <summary>
        /// Render a html template to PDF.
        /// </summary>
        /// <param name="htmlTemplate">The html template.</param>
        /// <param name="pdfOptions">The pdfOptions.</param>
        /// <param name="case">The case.</param>
        /// <returns></returns>
        Task<byte[]> HtmlToPdfAsync(string htmlTemplate, PdfOptions pdfOptions, Case @case);
    }
}
