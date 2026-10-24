using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Persistence;
using Sentinel.Source;

namespace Sentinel.IntegrationTests;

// A cota de snapshots (100 na instalação) vale para todo o banco de testes. Testes que enviam um snapshot só
// para gerar o inventário OpenAPI não precisam dele depois que a auditoria de fonte termina: expirar e purgar
// logo em seguida impede que a suíte inteira estoure a cota e derrube SourceSnapshotTests por poluição.
internal static class SnapshotHygiene
{
    internal static void PurgeSnapshots(this SentinelApiFactory host, Guid projectId)
    {
        using (var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext())
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var row in db.Set<SourceSnapshotRow>().Where(r => r.ProjectId == projectId)) row.ExpiresAtUtc = now;
            db.SaveChanges();
        }
        host.Services.GetRequiredService<SourceSnapshotStore>().PurgeAsync(CancellationToken.None).GetAwaiter().GetResult();
    }
}
