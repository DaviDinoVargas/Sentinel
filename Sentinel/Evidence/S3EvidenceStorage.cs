using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;

namespace Sentinel.Evidence;

// Only trusted service configuration chooses this endpoint. Plugins never receive S3 credentials.
public sealed class S3EvidenceStorage : IDisposable
{
    private readonly IAmazonS3 _client;
    private readonly string _bucket;
    public string StorageId { get; }
    public string? RetentionMode { get; }
    public S3EvidenceStorage(IConfiguration config, IHostEnvironment environment)
    {
        var section = config.GetSection("Evidence:S3");
        if (!Uri.TryCreate(section["Endpoint"], UriKind.Absolute, out var endpoint) || endpoint.Scheme is not ("http" or "https") ||
            endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 || endpoint.Fragment.Length != 0 || endpoint.AbsolutePath != "/" ||
            endpoint.Scheme == "http" && !(environment.IsDevelopment() && (endpoint.Host == "localhost" || IPAddress.TryParse(endpoint.Host, out var ip) && IPAddress.IsLoopback(ip))))
            throw new InvalidOperationException("S3 exige endpoint HTTPS; HTTP somente em loopback no desenvolvimento.");
        _bucket = section["Bucket"] ?? ""; StorageId = section["StorageId"] ?? "";
        if (!Regex.IsMatch(_bucket, "^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$") || !Regex.IsMatch(StorageId, "^s3:[A-Za-z0-9._:-]{1,96}$"))
            throw new InvalidOperationException("S3 exige bucket privado e StorageId explícito com prefixo s3:.");
        RetentionMode = section["RetentionMode"];
        if (RetentionMode is not (null or "GOVERNANCE" or "COMPLIANCE")) throw new InvalidOperationException("Modo de retenção S3 desconhecido.");
        var access = section["AccessKey"]; var secret = section["SecretKey"];
        if (string.IsNullOrWhiteSpace(access) || string.IsNullOrWhiteSpace(secret)) throw new InvalidOperationException("Credencial restrita de S3 não configurada.");
        _client = new AmazonS3Client(new BasicAWSCredentials(access, secret), new AmazonS3Config
        {
            ServiceURL = endpoint.AbsoluteUri,
            ForcePathStyle = true,
            AuthenticationRegion = section["Region"] ?? "us-east-1",
            Timeout = TimeSpan.FromSeconds(10),
            MaxErrorRetry = 1,
        });
    }
    internal static string Key(Guid projectId, Guid auditId, string reference)
    {
        if (!Regex.IsMatch(reference, "^sha256:[a-f0-9]{64}$")) throw new CryptographicException("Referência de artefato inválida.");
        return $"evidence/{projectId:N}/{auditId:N}/{reference[7..]}.blob";
    }
    private static string Version(string? version) => string.IsNullOrWhiteSpace(version) || version == "null" || version.Length > 1024
        ? throw new EvidenceStorageUnavailableException() : version;
    public async Task<string> PutAsync(Guid projectId, Guid auditId, string reference, byte[] encrypted, CancellationToken ct, DateTimeOffset? retainUntil = null)
    {
        try
        {
            var versioning = await _client.GetBucketVersioningAsync(new GetBucketVersioningRequest { BucketName = _bucket }, ct);
            if (versioning.VersioningConfig?.Status != VersionStatus.Enabled) throw new EvidenceStorageUnavailableException();
            if (RetentionMode is not null && retainUntil is null) throw new InvalidOperationException("Object Lock exige prazo explícito.");
            using var input = new MemoryStream(encrypted, writable: false);
            var response = await _client.PutObjectAsync(new PutObjectRequest
            {
                BucketName = _bucket,
                Key = Key(projectId, auditId, reference),
                InputStream = input,
                ContentType = "application/octet-stream",
                IfNoneMatch = "*",
                ObjectLockMode = RetentionMode is null ? null : new ObjectLockMode(RetentionMode),
                ObjectLockRetainUntilDate = RetentionMode is null ? null : retainUntil!.Value.UtcDateTime
            }, ct);
            return Version(response.VersionId);
        }
        catch (AmazonS3Exception e) when (e.StatusCode == HttpStatusCode.PreconditionFailed)
        {
            var existing = await ReadAsync(projectId, auditId, reference, null, ct); return existing.Version;
        }
        catch (AmazonS3Exception) { throw new EvidenceStorageUnavailableException(); }
        catch (AmazonClientException) { throw new EvidenceStorageUnavailableException(); }
        catch (HttpRequestException) { throw new EvidenceStorageUnavailableException(); }
    }
    public async Task<(byte[] Bytes, string Version)> ReadAsync(Guid projectId, Guid auditId, string reference, string? version, CancellationToken ct)
    {
        try
        {
            using var response = await _client.GetObjectAsync(new GetObjectRequest { BucketName = _bucket, Key = Key(projectId, auditId, reference), VersionId = version }, ct);
            var actual = Version(response.VersionId);
            if (version is not null && actual != version) throw new CryptographicException("Versão de objeto divergente.");
            if (response.ContentLength > 128 * 1024) throw new CryptographicException("Tamanho de artefato inválido.");
            using var output = new MemoryStream(); var buffer = new byte[8192];
            while (true) { var count = await response.ResponseStream.ReadAsync(buffer, ct); if (count == 0) break; if (output.Length + count > 128 * 1024) throw new CryptographicException("Tamanho de artefato inválido."); await output.WriteAsync(buffer.AsMemory(0, count), ct); }
            return (output.ToArray(), actual);
        }
        catch (AmazonS3Exception e) when (e.StatusCode == HttpStatusCode.NotFound) { throw new FileNotFoundException("Objeto de evidência indisponível."); }
        catch (AmazonS3Exception) { throw new EvidenceStorageUnavailableException(); }
        catch (AmazonClientException) { throw new EvidenceStorageUnavailableException(); }
        catch (HttpRequestException) { throw new EvidenceStorageUnavailableException(); }
    }
    public async Task DeleteAsync(Guid projectId, Guid auditId, string reference, string version, CancellationToken ct)
    {
        try { await _client.DeleteObjectAsync(new DeleteObjectRequest { BucketName = _bucket, Key = Key(projectId, auditId, reference), VersionId = Version(version) }, ct); }
        catch (AmazonS3Exception) { throw new EvidenceStorageUnavailableException(); }
        catch (AmazonClientException) { throw new EvidenceStorageUnavailableException(); }
        catch (HttpRequestException) { throw new EvidenceStorageUnavailableException(); }
    }
    internal sealed record StoredVersion(Guid ProjectId, Guid AuditId, string Reference, string Version, DateTimeOffset Modified);
    internal async Task<(IReadOnlyList<StoredVersion> Items, string? KeyMarker, string? VersionMarker)> ListAsync(string? keyMarker, string? versionMarker, CancellationToken ct)
    {
        try
        {
            var response = await _client.ListVersionsAsync(new ListVersionsRequest { BucketName = _bucket, Prefix = "evidence/", MaxKeys = 100, KeyMarker = keyMarker, VersionIdMarker = versionMarker }, ct);
            var items = new List<StoredVersion>();
            foreach (var item in response.Versions ?? [])
            {
                var match = Regex.Match(item.Key, "^evidence/([a-f0-9]{32})/([a-f0-9]{32})/([a-f0-9]{64})\\.blob$");
                if (!match.Success || item.IsDeleteMarker == true || item.LastModified is null) continue;
                items.Add(new(Guid.ParseExact(match.Groups[1].Value, "N"), Guid.ParseExact(match.Groups[2].Value, "N"), "sha256:" + match.Groups[3].Value, Version(item.VersionId), new DateTimeOffset(DateTime.SpecifyKind(item.LastModified.Value, DateTimeKind.Utc))));
            }
            return (items, response.IsTruncated == true ? response.NextKeyMarker : null, response.IsTruncated == true ? response.NextVersionIdMarker : null);
        }
        catch (AmazonS3Exception) { throw new EvidenceStorageUnavailableException(); }
        catch (AmazonClientException) { throw new EvidenceStorageUnavailableException(); }
    }
    public void Dispose() => _client.Dispose();
}
