using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Identity;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

// Exercises the PostgreSQL candidate projection, not artifact authenticity.
// Cryptographic completeness is covered separately by OpenApiInventoryProvenanceTests.
public sealed class EvidenceAuditCandidateTests
{
    [Fact]
    public async Task Busca_SQL_pagina_sem_lookback_e_isola_projeto_origem_produtor_estado_e_organizacao()
    {
        using var host = new SentinelApiFactory { StartWorkers = false };
        using var client = host.CreateClient();
        var store = host.Services.GetRequiredService<ISentinelStore>();
        var at = DateTimeOffset.UtcNow;
        var project = store.CreateProject("Inventory projection " + Guid.NewGuid().ToString("N"), "Synthetic query fixture", at, ProjectPurposes.Validation);
        var otherProject = store.CreateProject("Other inventory projection " + Guid.NewGuid().ToString("N"), null, at, ProjectPurposes.Validation);
        const string producer = "sentinel.source.openapi";
        using var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
        AuditRow Row(Guid projectId, string origin, string state, DateTimeOffset created, string? source)
        {
            var row = new AuditRow { Id = Guid.NewGuid(), ProjectId = projectId, DataOrigin = origin, State = state,
                TargetUrl = "http://localhost:21340/synthetic-query/", CreatedAtUtc = created, CorrelationId = "projection-fixture" };
            if (source is not null) row.Evidence.Add(new AuditEvidenceRow { Id = Guid.NewGuid(), AuditId = row.Id,
                EvidenceReference = "fixture-" + Guid.NewGuid().ToString("N"), Sha256 = new string('a', 64), Summary = "Synthetic metadata, not a verified artifact",
                CollectedAtUtc = created, ArtifactMetadataJson = JsonSerializer.Serialize(new { SourcePluginId = source }) });
            return row;
        }
        var expected = Enumerable.Range(0, 75).Select(_ => Row(project.Id, DataOrigins.Synthetic, "Completed", at, producer)).ToArray();
        db.Audits.AddRange(expected);
        db.Audits.AddRange(Enumerable.Range(0, 1200).Select(_ => Row(project.Id, DataOrigins.Synthetic, "Completed", at.AddMinutes(1), null)));
        db.Audits.AddRange(Enumerable.Range(0, 12).Select(_ => Row(project.Id, DataOrigins.Software, "Completed", at, producer)));
        db.Audits.Add(Row(project.Id, DataOrigins.Unknown, "Completed", at, producer));
        db.Audits.Add(Row(project.Id, DataOrigins.Synthetic, "Running", at, producer));
        db.Audits.Add(Row(project.Id, DataOrigins.Synthetic, "Completed", at, "sentinel.source.other"));
        db.Audits.Add(Row(otherProject.Id, DataOrigins.Synthetic, "Completed", at, producer));
        await db.SaveChangesAsync();

        var found = new List<Guid>();
        EvidenceAuditCandidate? cursor = null;
        while (true)
        {
            var page = await store.FindEvidenceAuditsAsync(project.Id, DataOrigins.Synthetic, producer, cursor, 7, CancellationToken.None);
            Assert.InRange(page.Count, 0, 7);
            if (page.Count == 0) break;
            Assert.All(page, item => Assert.DoesNotContain(item.Id, found));
            found.AddRange(page.Select(item => item.Id));
            Assert.InRange(found.Count, 1, expected.Length);
            cursor = page[^1];
            if (found.Count == 7)
            {
                // A newer observation arriving during traversal belongs to the next lookup.
                db.Audits.Add(Row(project.Id, DataOrigins.Synthetic, "Completed", at.AddMinutes(2), producer));
                await db.SaveChangesAsync();
            }
        }
        Assert.Equal(75, found.Count);
        Assert.Equal(75, found.Distinct().Count());
        Assert.Equal(expected.Select(item => item.Id).Order(), found.Order());
        Assert.Equal(12, (await store.FindEvidenceAuditsAsync(project.Id, DataOrigins.Software, producer, null, 100, CancellationToken.None)).Count);
        Assert.Single(await store.FindEvidenceAuditsAsync(project.Id, DataOrigins.Unknown, producer, null, 100, CancellationToken.None));

        var wrongTarget = Row(project.Id, DataOrigins.Synthetic, "Completed", at.AddSeconds(-1), producer);
        wrongTarget.TargetUrl = "http://localhost:21340/other-source/";
        db.Audits.Add(wrongTarget); await db.SaveChangesAsync();
        var boundedTarget = await store.FindEvidenceAuditsAsync(project.Id, DataOrigins.Synthetic, producer, null, 100, CancellationToken.None,
            targetUrl: expected[0].TargetUrl, createdBeforeUtc: at.AddSeconds(1));
        Assert.Equal(expected.Select(item => item.Id).Order(), boundedTarget.Select(item => item.Id).Order());
        Assert.Empty(await store.FindEvidenceAuditsAsync(project.Id, DataOrigins.Synthetic, producer, null, 100, CancellationToken.None,
            targetUrl: expected[0].TargetUrl, createdBeforeUtc: at.AddSeconds(-1)));

        // A separate non-system context cannot see the same project's candidate IDs.
        var accessor = new HttpContextAccessor { HttpContext = new DefaultHttpContext() };
        accessor.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("organization_id", Guid.NewGuid().ToString())], "fixture"));
        var options = host.Services.GetRequiredService<DbContextOptions<SentinelDbContext>>();
        var foreignStore = new PostgresSentinelStore(new TenantFactory(options, new TenantAccess(accessor)));
        Assert.Empty(await foreignStore.FindEvidenceAuditsAsync(project.Id, DataOrigins.Synthetic, producer, null, 7, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => store.FindEvidenceAuditsAsync(project.Id, "invalid", producer, null, 7, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => store.FindEvidenceAuditsAsync(project.Id, DataOrigins.Synthetic, producer, null, 101, CancellationToken.None));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.FindEvidenceAuditsAsync(project.Id, DataOrigins.Synthetic, producer, null, 7, cancelled.Token));
    }

    private sealed class TenantFactory(DbContextOptions<SentinelDbContext> options, TenantAccess tenant) : IDbContextFactory<SentinelDbContext>
    {
        public SentinelDbContext CreateDbContext() => new(options, tenant);
    }
}
