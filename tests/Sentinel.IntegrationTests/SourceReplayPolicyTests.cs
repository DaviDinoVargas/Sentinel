using Sentinel.Execution;
using Sentinel.Persistence;
using Sentinel.Source;

namespace Sentinel.IntegrationTests;

public sealed class SourceReplayPolicyTests
{
    [Theory]
    [InlineData("valid", true)]
    [InlineData("action", false)]
    [InlineData("network-target", false)]
    [InlineData("binding-missing", false)]
    [InlineData("snapshot-missing", false)]
    [InlineData("project", false)]
    [InlineData("snapshot", false)]
    [InlineData("scope", false)]
    [InlineData("expired", false)]
    [InlineData("purged", false)]
    [InlineData("revoked", false)]
    [InlineData("hash", false)]
    [InlineData("hash-null", false)]
    [InlineData("storage", false)]
    [InlineData("origin", false)]
    [InlineData("revision", false)]
    [InlineData("source-key", false)]
    [InlineData("audit", false)]
    public void Retomada_exige_contexto_original_integro_nao_expirado_e_sem_substituicao(string variant, bool expected)
    {
        var now = DateTimeOffset.UtcNow;
        var audit = new AuditRow { Id = Guid.NewGuid(), ProjectId = Guid.NewGuid(), ScopeId = Guid.NewGuid(), DataOrigin = "SyntheticCorpus" };
        SourceSnapshotRow? snapshot = new()
        {
            Id = Guid.NewGuid(), ProjectId = audit.ProjectId, ScopeId = audit.ScopeId!.Value, SourceKey = "reference", Sha256 = new string('a', 64),
            StorageId = "synthetic-store", RevisionLabel = "r1", ExpiresAtUtc = now.AddHours(1), DataOrigin = audit.DataOrigin,
        };
        audit.TargetUrl = SourceSnapshotStore.Target(snapshot).AbsoluteUri;
        var binding = new SourceSnapshotBinding(snapshot.Id, snapshot.Sha256, snapshot.SourceKey, snapshot.StorageId, snapshot.ExpiresAtUtc, snapshot.RevisionLabel);
        var payload = new OutboxMessagePayload(audit.Id, audit.ProjectId, audit.ScopeId.Value, audit.TargetUrl, "source-analysis", Source: binding);
        switch (variant)
        {
            case "action": payload = payload with { Action = "lab-active" }; break;
            case "network-target": audit.TargetUrl = "http://localhost:12345/"; payload = payload with { TargetUrl = audit.TargetUrl }; break;
            case "binding-missing": payload = payload with { Source = null }; break;
            case "snapshot-missing": snapshot = null; break;
            case "project": payload = payload with { ProjectId = Guid.NewGuid() }; break;
            case "snapshot": payload = payload with { Source = binding with { Id = Guid.NewGuid() } }; break;
            case "scope": snapshot.ScopeId = Guid.NewGuid(); break;
            case "expired": snapshot.ExpiresAtUtc = now.AddSeconds(-1); payload = payload with { Source = binding with { ExpiresAtUtc = snapshot.ExpiresAtUtc } }; break;
            case "purged": snapshot.PurgedAtUtc = now; break;
            case "revoked": snapshot.RevokedAtUtc = now; break;
            case "hash": payload = payload with { Source = binding with { Sha256 = new string('b', 64) } }; break;
            case "hash-null": payload = payload with { Source = binding with { Sha256 = null! } }; break;
            case "storage": payload = payload with { Source = binding with { StorageId = "other-store" } }; break;
            case "origin": snapshot.DataOrigin = "SoftwareUnderTest"; break;
            case "revision": payload = payload with { Source = binding with { RevisionLabel = "r2" } }; break;
            case "source-key": audit.TargetUrl = $"source://{audit.ProjectId:N}/other"; payload = payload with { TargetUrl = audit.TargetUrl }; break;
            case "audit": payload = payload with { AuditId = Guid.NewGuid() }; break;
        }
        Assert.Equal(expected, PluginReplaySafety.MatchesOriginalSnapshot(payload, audit, snapshot, now));
    }
}
