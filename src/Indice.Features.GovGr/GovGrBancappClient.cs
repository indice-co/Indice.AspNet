using System.Net.Http.Headers;
using Indice.Features.GovGr.Configuration;
using Indice.Features.GovGr.Interfaces;
using Indice.Features.GovGr.Models;

namespace Indice.Features.GovGr;

/// <inheritdoc />
internal class GovGrBancappClient : IBancappService
{
    
    private const string FunctionFqdnProd = "https://bancapp-api.aade.gr";
    private const string FunctionFqdnStage = "https://testbancapp-api.aade.gr";
    private readonly HttpClient _httpClient;
    private readonly GovGrOptions.BancappOptions _settings;

    internal GovGrBancappClient(
        HttpClient httpClient,
        GovGrOptions.BancappOptions settings) {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
    }
    
    private string FunctionUrl => _settings.IsProduction ? FunctionFqdnProd : FunctionFqdnStage;


    /// <inheritdoc />
    public async Task<BancappGCloudUploadResponse> UploadFile(Stream stream, string fileName, string token) {
        if (!stream.CanSeek) {
            return BancappGCloudUploadResponse.Fail("Stream needs to be open/seekable!");
        }
        
        stream.Position = 0;
        
        if (_settings.IsMock) {
            return BancappGCloudUploadResponse.Success();
        }
        
        if (stream is not { Length: > 0 }) {
            return BancappGCloudUploadResponse.Fail("File content to upload is empty. Please review!");
        }
        
        if (string.IsNullOrWhiteSpace(fileName)) {
            return BancappGCloudUploadResponse.Fail("Filename to upload is empty. Please review!");
        }
        
        using var streamContent = new StreamContent(stream);
        streamContent.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data") {
            Name = "\"file\"",
            FileName = $"\"{fileName}\""
        };
        
        streamContent.Headers.ContentType = new MediaTypeHeaderValue("text/csv");
        using var formData = new MultipartFormDataContent();
        formData.Add(streamContent);

        if (!string.IsNullOrWhiteSpace(token)) {
            streamContent.Headers.Add("token", token);
        }
        
        try {
            return await BancappGCloudUploadResponse.FromHttpResponseMessage(
                await _httpClient.PostAsync($"{FunctionUrl}/api/uploadFile", formData));
        } catch (Exception ex) {
            return BancappGCloudUploadResponse.Fail(ex.InnerException?.Message ?? ex.Message);
        }
    }
}
