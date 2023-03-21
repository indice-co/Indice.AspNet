﻿using System.Net.Mime;
using Indice.Extensions;
using Indice.Features.Messages.Core;
using Indice.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace Indice.Features.Messages.AspNetCore.Controllers;

internal abstract class CampaignsControllerBase : ControllerBase
{
    public CampaignsControllerBase(Func<string, IFileService> getFileService) {
        FileService = getFileService(KeyedServiceNames.FileServiceKey) ?? throw new ArgumentNullException(nameof(getFileService));
    }

    public IFileService FileService { get; }

    protected virtual async Task<IActionResult> GetFile(string rootFolder, Guid fileGuid, string format) {
        if (format.StartsWith('.')) {
            format = format.TrimStart('.');
        }
        var path = $"{rootFolder}/{fileGuid.ToString("N")[..2]}/{fileGuid:N}.{format}";
        var properties = await FileService.GetPropertiesAsync(path);
        if (properties is null) {
            return NotFound();
        }
        var data = await FileService.GetAsync(path);
        var contentType = properties.ContentType;
        if (contentType == MediaTypeNames.Application.Octet && !string.IsNullOrEmpty(format)) {
            contentType = FileExtensions.GetMimeType($".{format}");
        }
        return File(data, contentType, properties.LastModified, new EntityTagHeaderValue(properties.ETag, true));
    }
}
