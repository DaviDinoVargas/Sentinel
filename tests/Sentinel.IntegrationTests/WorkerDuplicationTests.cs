using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// Prova o critério de saída do P0 (Roadmap.md): duas instâncias da API, cada uma com seu
// próprio AuditWorker, não duplicam a execução de uma auditoria. As duas instâncias
// competem pela mesma fila quorum real do RabbitMQ, separada da topologia de
// desenvolvimento. São dois hosts lógicos no processo de teste; cada controle roda
// em um processo filho isolado. Testar hosts em processos distintos continua pendente.
public sealed class WorkerDuplicationTests : IAsyncLifetime
{
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    private SentinelApiFactory _instanceA = null!;
    private SentinelApiFactory _instanceB = null!;

    public Task InitializeAsync()
    {
        _instanceA = new SentinelApiFactory();
        _instanceB = new SentinelApiFactory();
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        _instanceA.Dispose();
        _instanceB.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Duas_instancias_de_worker_nao_duplicam_execucao_de_auditorias()
    {
        var clientA = _instanceA.CreateClient();
        // Cria o cliente B também: isso sobe o host (e o AuditWorker) da segunda
        // instância, que passa a competir pelos mesmos jobs no mesmo banco.
        var clientB = _instanceB.CreateClient();

        var projectResponse = await clientA.PostAsJsonAsync(
            "/api/v1/projects",
            new CreateProjectRequest($"Duplicacao {Guid.NewGuid():N}", "Teste de duas instâncias."));
        Assert.Equal(HttpStatusCode.Created, projectResponse.StatusCode);
        var project = await ReadRequiredAsync<SentinelProject>(projectResponse);

        var targetBaseUrl = $"{_instanceA.LabTarget.BaseUri}aplicacao/";
        var scopeResponse = await clientA.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/scopes",
            new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)));
        Assert.Equal(HttpStatusCode.Created, scopeResponse.StatusCode);

        const int auditCount = 8;
        var auditIds = new List<Guid>();
        for (var i = 0; i < auditCount; i++)
        {
            var auditResponse = await clientA.PostAsJsonAsync(
                $"/api/v1/projects/{project.Id}/audits",
                new RequestAuditRequest($"{targetBaseUrl}area-segura", "simulated"));
            Assert.Equal(HttpStatusCode.Accepted, auditResponse.StatusCode);
            auditIds.Add((await ReadRequiredAsync<Audit>(auditResponse)).Id);
        }

        var completed = new List<Audit>();
        var deadline = DateTime.UtcNow.AddSeconds(60);
        while (completed.Count < auditCount && DateTime.UtcNow < deadline)
        {
            completed.Clear();
            foreach (var auditId in auditIds)
            {
                var response = await clientA.GetAsync($"/api/v1/audits/{auditId}");
                var audit = await ReadRequiredAsync<Audit>(response);
                if (AuditStates.IsTerminal(audit.State))
                {
                    completed.Add(audit);
                }
            }

            if (completed.Count < auditCount)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(150));
            }
        }

        Assert.Equal(auditCount, completed.Count);
        Assert.All(completed, audit => Assert.Equal(AuditState.Completed, audit.State));
        // O ponto central do teste: se as duas instâncias tivessem processado a mesma
        // auditoria, cada uma teria 18 controles (9 plugins x 2 execuções) em vez de 9.
        Assert.All(completed, audit => Assert.Equal(9, audit.Controls.Count));
        Assert.All(completed, audit => Assert.Equal(9, audit.Evidence.Count));
    }

    private static async Task<T> ReadRequiredAsync<T>(HttpResponseMessage response)
        => await response.Content.ReadFromJsonAsync<T>(JsonOptions)
           ?? throw new InvalidOperationException("A API não retornou o conteúdo esperado.");

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}
