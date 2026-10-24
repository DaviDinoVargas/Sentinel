using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// SUP-03: snapshot ZIP real, análise estática offline em container, igual a UnusedDependenciesTests.cs.
public sealed class ModelIntegrityTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    private static PluginCheckResultView[] Sup03(Audit audit) => audit.Controls.Where(item => item.ControlId == "SUP-03").Select(item => new PluginCheckResultView(item.State, item.Severity, item.Summary, item.SourceRuleId ?? "")).ToArray();
    private sealed record PluginCheckResultView(string State, string Severity, string Summary, string Rule);

    [Fact]
    public async Task Formato_pickle_reprova_citando_o_arquivo()
    {
        var results = Sup03(await RunSourceAuditAsync(("models/classificador.pkl", "conteudo-sintetico-do-modelo")));
        var unsafeFormat = Assert.Single(results, item => item.Rule == "sup03:unsafe-format:models/classificador.pkl");
        Assert.Equal("Failed", unsafeFormat.State);
        Assert.Equal("Medium", unsafeFormat.Severity);
        Assert.Contains("models/classificador.pkl", unsafeFormat.Summary);
    }

    [Fact]
    public async Task Pesos_sem_hash_fixado_reprovam_e_com_hash_fixado_junto_do_nome_aprovam()
    {
        const string weights = "pesos-sinteticos-v1";
        var unpinned = Sup03(await RunSourceAuditAsync(("models/pesos.safetensors", weights)));
        Assert.Contains(unpinned, item => item.State == "Failed" && item.Rule == "sup03:unpinned:models/pesos.safetensors");

        var sha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(weights))).ToLowerInvariant();
        var pinned = Sup03(await RunSourceAuditAsync(("models/pesos.safetensors", weights), ("models/SHA256SUMS.txt", sha + "  pesos.safetensors\n")));
        Assert.Equal("Passed", Assert.Single(pinned).State);
    }

    [Fact]
    public async Task Hash_presente_mas_sem_o_nome_do_artefato_por_perto_nao_e_fixacao()
    {
        const string weights = "pesos-sinteticos-v2";
        var sha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(weights))).ToLowerInvariant();
        var results = Sup03(await RunSourceAuditAsync(("models/pesos.safetensors", weights), ("docs/hashes.txt", sha + "  outro-arquivo.bin\n")));
        var finding = Assert.Single(results, item => item.Rule == "sup03:unpinned:models/pesos.safetensors");
        Assert.Equal("Failed", finding.State);
        Assert.Contains("sem o nome do artefato", finding.Summary);
    }

    [Fact]
    public async Task Arquivo_bin_com_assinatura_pickle_e_reconhecido_pelo_conteudo()
    {
        var zip = ZipBytes(("models/pesos.bin", [0x80, 0x04, 0x95, 0x01, 0x00, 0x00, 0x00, 0x2E]));
        var results = Sup03(await RunZipAsync(zip));
        Assert.Contains(results, item => item.Rule == "sup03:unsafe-format:models/pesos.bin" && item.State == "Failed");
    }

    [Fact]
    public async Task Codigo_que_carrega_modelo_de_forma_insegura_reprova_por_regra_e_linha()
    {
        const string code = "import torch\nimport joblib\nfrom transformers import AutoModel\n\nmodelo = torch.load('m.pt')\nseguro = torch.load('s.pt', weights_only=True)\nclf = joblib.load('c.joblib')\nm = AutoModel.from_pretrained('org/modelo', trust_remote_code=True)\n";
        var results = Sup03(await RunSourceAuditAsync(("src/carga.py", code)));
        var rules = results.Where(item => item.State == "Failed").Select(item => item.Rule).ToArray();
        Assert.Contains("sup03:torch-load:src/carga.py:5", rules);          // sem weights_only
        Assert.DoesNotContain(rules, rule => rule.StartsWith("sup03:torch-load:src/carga.py:6")); // com weights_only=True
        Assert.Contains("sup03:joblib-load:src/carga.py:7", rules);
        Assert.Contains("sup03:trust-remote-code:src/carga.py:8", rules);
        Assert.Contains(results, item => item.Rule == "sup03:trust-remote-code:src/carga.py:8" && item.Severity == "High");
        Assert.Contains("sup03:hub-unpinned:src/carga.py:8", rules);
        Assert.DoesNotContain("conteudo", string.Join(" ", results.Select(item => item.Summary)));
    }

    [Fact]
    public async Task Download_de_pesos_sem_checksum_reprova_e_com_sha256sum_no_mesmo_arquivo_nao()
    {
        var bare = Sup03(await RunSourceAuditAsync(("Dockerfile", "FROM python:3.12\nRUN wget https://exemplo.invalid/modelo.safetensors -O /m/modelo.safetensors\n")));
        Assert.Contains(bare, item => item.Rule == "sup03:download-no-checksum:Dockerfile:2" && item.State == "Failed");
        var verified = Sup03(await RunSourceAuditAsync(("Dockerfile", "FROM python:3.12\nRUN wget https://exemplo.invalid/modelo.safetensors -O /m/modelo.safetensors && echo \"abc  /m/modelo.safetensors\" | sha256sum -c -\n")));
        Assert.DoesNotContain(verified, item => item.Rule.StartsWith("sup03:download-no-checksum"));
    }

    [Fact]
    public async Task Sem_artefatos_de_modelo_e_sem_codigo_inseguro_e_inconclusivo()
    {
        var results = Sup03(await RunSourceAuditAsync(("README.md", "sem modelos aqui")));
        Assert.Equal("Inconclusive", Assert.Single(results).State);
    }

    private static byte[] ZipBytes(params (string Path, byte[] Data)[] files)
    {
        using var bytes = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(bytes, System.IO.Compression.ZipArchiveMode.Create, true))
            foreach (var (path, data) in files) { var entry = zip.CreateEntry(path); using var stream = entry.Open(); stream.Write(data); }
        return bytes.ToArray();
    }

    private static Task<Audit> RunSourceAuditAsync(params (string Path, string Text)[] files) => RunZipAsync(SourceSnapshotTests.Zip(files));

    private static async Task<Audit> RunZipAsync(byte[] zipBytes)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("ModelInt " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        using var zip = new ByteArrayContent(zipBytes);
        zip.Headers.ContentType = new("application/zip");
        var sourceUrl = $"/api/v1/projects/{project.Id}/source-snapshots";
        var upload = await client.PostAsync(sourceUrl + "?sourceKey=model-int&revision=" + Guid.NewGuid().ToString("N"), zip);
        upload.EnsureSuccessStatusCode();
        using var snapshot = JsonDocument.Parse(await upload.Content.ReadAsStringAsync());

        var queued = await client.PostAsJsonAsync(sourceUrl + $"/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
        queued.EnsureSuccessStatusCode();
        var audit = (await queued.Content.ReadFromJsonAsync<Audit>(Json))!;

        var deadline = DateTimeOffset.UtcNow.AddMinutes(2);
        while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(250);
            audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.True(audit.State == AuditState.Completed, audit.PolicyReason);
        host.PurgeSnapshots(project.Id);
        return audit;
    }
}
