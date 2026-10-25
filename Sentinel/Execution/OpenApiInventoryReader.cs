using System.Security.Cryptography;
using System.Text.Json;
using Sentinel.Core;
using Sentinel.Evidence;
using Sentinel.Persistence;

namespace Sentinel.Execution;

// Artifact decryption/hash/provenance verification belongs to EvidenceArtifactStore.
// This layer additionally verifies that every exported part belongs to one complete
// inventory of the source binding recorded for this audit, in the requested origin.
internal static class OpenApiInventoryReader
{
    internal const string PluginId = "sentinel.source.openapi";
    internal static async Task<InventoryAssemblyResult> ReadAsync(Audit audit, OutboxMessagePayload? payload, string expectedOrigin,
        Func<AuditEvidence, CancellationToken, Task<VerifiedEvidenceArtifact>> read, InventoryAssemblyLimits limits, CancellationToken ct)
    {
        InventoryAssemblyResult Rejected(string issue) => new(null, false, 0, 0, 0, 0, [issue]);
        if (audit.State != AuditState.Completed || audit.DataOrigin != expectedOrigin || !DataOrigins.Valid(expectedOrigin))
            return Rejected("audit-origin-or-state-mismatch");
        if (payload is not { Action: "source-analysis", Source: { } source } || payload.AuditId != audit.Id ||
            payload.ProjectId != audit.ProjectId || payload.ScopeId != audit.ScopeId ||
            !Uri.TryCreate(payload.TargetUrl, UriKind.Absolute, out var target) || target != audit.TargetUri ||
            source.Sha256 is not { Length: 64 } || !source.Sha256.All(Uri.IsHexDigit))
            return Rejected("source-binding-unavailable");
        var controls = audit.Controls.Where(row => row.PluginId == PluginId && row.ControlId == "SRC-API-01").ToArray();
        if (controls.Length != 1 || controls[0].State != "Informational") return Rejected("producer-partial");
        var parts = new List<string>();
        string? preview = null;
        var totalBytes = 0;
        var readArtifacts = 0;
        foreach (var evidence in audit.Evidence.Where(row => row.Artifact?.SourcePluginId == PluginId))
        {
            ct.ThrowIfCancellationRequested();
            if (++readArtifacts > limits.MaximumParts + 1) return Rejected("part-budget-exceeded");
            try
            {
                var verified = await read(evidence, ct);
                if (!verified.IntegrityVerified || verified.Metadata.SourcePluginId != PluginId || verified.Metadata.Truncated)
                    return Rejected("artifact-integrity-or-truncation");
                using var wrapper = JsonDocument.Parse(verified.Content);
                var root = wrapper.RootElement;
                if (root.GetProperty("auditId").GetGuid() != audit.Id || root.GetProperty("projectId").GetGuid() != audit.ProjectId ||
                    root.GetProperty("sourcePluginId").GetString() != PluginId || root.GetProperty("truncated").GetBoolean())
                    return Rejected("artifact-provenance-mismatch");
                var text = root.GetProperty("details").GetString();
                if (text is null) return Rejected("artifact-details-unavailable");
                var bytes = System.Text.Encoding.UTF8.GetByteCount(text);
                if (bytes > limits.MaximumUtf8Bytes - totalBytes) return Rejected("input-budget-exceeded");
                totalBytes += bytes;
                using var document = JsonDocument.Parse(text);
                var kind = document.RootElement.GetProperty("kind").GetString();
                if (kind == "sentinel-openapi-inventory-v2") parts.Add(text);
                else if (kind == "sentinel-openapi-inventory-v1" && preview is null) preview = text;
                else return Rejected("unknown-or-duplicate-inventory-report");
            }
            catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or
                CryptographicException or IOException or EvidenceExpiredException or EvidenceStorageUnavailableException)
            { return Rejected("artifact-unavailable-or-malformed"); }
        }
        if (preview is null) return Rejected("inventory-report-unavailable");
        try
        {
            using var document = JsonDocument.Parse(preview);
            var report = document.RootElement;
            if (!string.Equals(report.GetProperty("sourceSha256").GetString(), source.Sha256, StringComparison.OrdinalIgnoreCase))
                return Rejected("report-source-hash-mismatch");
            if (report.GetProperty("candidateFiles").GetInt32() < 1 ||
                report.GetProperty("unassessedFiles").GetInt32() != 0 || report.GetProperty("rejectedPaths").GetInt32() != 0 ||
                report.GetProperty("parsedFiles").GetInt32() != report.GetProperty("candidateFiles").GetInt32() ||
                report.GetProperty("diagnostics").GetArrayLength() != 0)
                return Rejected("producer-partial");
            var declared = report.GetProperty("operationCount").GetInt32();
            if (declared < 1) return Rejected("no-operations");
            if (parts.Count != 0)
                // v1's preview may be truncated at 60 while every v2 operation is present.
                // Completeness is established from the v2 parts and the declared total.
                return OpenApiInventoryAssembler.Assemble(parts, source.Sha256, declared, true, limits);
            if (report.GetProperty("truncated").GetBoolean()) return Rejected("legacy-preview-partial");
            // A complete small legacy report is safe to retain; never fall back to it
            // after observing an invalid/missing v2 part.
            var legacy = JsonSerializer.Serialize(new { kind = "sentinel-openapi-inventory-v2", chunk = 1, chunks = 1,
                sourceSha256 = source.Sha256, operations = report.GetProperty("operations") });
            return OpenApiInventoryAssembler.Assemble([legacy], source.Sha256, declared, true, limits);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        { return Rejected("inventory-report-malformed"); }
    }
}
