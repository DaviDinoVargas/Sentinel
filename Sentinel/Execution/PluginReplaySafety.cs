using Sentinel.Persistence;
using Sentinel.Source;

namespace Sentinel.Execution;

// This is a host assertion about the physical sandbox, never a claim supplied by
// a plugin. Only the source worker path has no network and a read-only mount.
internal static class PluginReplaySafety
{
    internal const string Uncertain = "Uncertain";
    internal const string ReadOnlySourceSandbox = "ReadOnlySourceSandbox";

    internal static bool MatchesOriginalSnapshot(OutboxMessagePayload? payload, AuditRow audit, SourceSnapshotRow? snapshot, DateTimeOffset now)
    {
        if (payload is not { Action: "source-analysis", Source: { } binding } || snapshot is null) return false;
        if (payload.AuditId != audit.Id || payload.ProjectId != audit.ProjectId || payload.ScopeId != audit.ScopeId ||
            snapshot.Id != binding.Id || snapshot.ProjectId != audit.ProjectId || snapshot.ScopeId != audit.ScopeId) return false;
        if (snapshot.PurgedAtUtc is not null || snapshot.RevokedAtUtc is not null || snapshot.ExpiresAtUtc <= now ||
            binding.ExpiresAtUtc != snapshot.ExpiresAtUtc || snapshot.DataOrigin != audit.DataOrigin) return false;
        if (string.IsNullOrEmpty(binding.Sha256) || binding.Sha256.Length != 64 || !binding.Sha256.All(Uri.IsHexDigit) || binding.Sha256 != snapshot.Sha256 ||
            string.IsNullOrWhiteSpace(binding.StorageId) || binding.StorageId != snapshot.StorageId ||
            binding.SourceKey != snapshot.SourceKey || binding.RevisionLabel != snapshot.RevisionLabel) return false;
        return Uri.TryCreate(audit.TargetUrl, UriKind.Absolute, out var target) && target.Scheme == "source" &&
            Uri.TryCreate(payload.TargetUrl, UriKind.Absolute, out var queued) && target == queued &&
            Uri.TryCreate($"source://{snapshot.ProjectId:N}/{snapshot.SourceKey}", UriKind.Absolute, out var original) && target == original;
    }
}
