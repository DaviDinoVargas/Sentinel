using Sentinel.Contracts;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class GatewayHeaderExporterTests
{
    private static readonly PluginManifestGateway Policy = new() { HeaderCount = 32, HeaderBytes = 8000, HeaderValueLength = 512, CookieAttributes = true };
    private static KeyValuePair<string, IEnumerable<string>> Header(string name, params string[] values) => new(name, values);

    [Fact]
    public void Nono_cookie_inseguro_nao_desaparece_e_nenhum_valor_de_cookie_e_exportado()
    {
        var cookies = Enumerable.Range(1, 8).Select(index => $"safe{index}=synthetic-secret; Secure; HttpOnly").Append("ninth=synthetic-secret; Path=/").ToArray();
        var result = GatewayHeaderExporter.Export([Header("Set-Cookie", cookies)], Policy, false, null);
        Assert.False(result.Incomplete); Assert.Equal(9, result.Headers["Set-Cookie"].Length);
        Assert.Contains("ninth=<redacted>; Path=/", result.Headers["Set-Cookie"]);
        Assert.DoesNotContain("synthetic-secret", string.Join(";", result.Headers["Set-Cookie"]));
    }
    [Fact]
    public void Atributos_de_seguranca_apos_valor_de_cookie_longo_nao_sao_cortados()
    {
        var result = GatewayHeaderExporter.Export([Header("Set-Cookie", "session=" + new string('s', 2048) + "; Secure; HttpOnly")], Policy, false, null);
        Assert.False(result.Incomplete);
        Assert.Equal("session=<redacted>; Secure; HttpOnly", Assert.Single(result.Headers["Set-Cookie"]));
    }
    [Fact]
    public void Terceiro_valor_e_campos_repetidos_preservam_todos_os_valores_permitidos()
    {
        var result = GatewayHeaderExporter.Export([Header("X-Policy", "first", "second", "third"), Header("x-policy", "fourth")], Policy, false, null);
        Assert.False(result.Incomplete); Assert.Single(result.Headers);
        Assert.Equal(new[] { "first", "second", "third", "fourth" }, result.Headers["X-Policy"]);
    }
    [Theory]
    [InlineData("bytes")]
    [InlineData("fields")]
    [InlineData("value")]
    public void Orcamento_atingido_sinaliza_omissao_sem_transformar_prefixo_em_cabecalho_valido(string variant)
    {
        var policy = new PluginManifestGateway { HeaderCount = variant == "fields" ? 1 : 32,
            HeaderBytes = variant == "bytes" ? 12 : 8000, HeaderValueLength = variant == "value" ? 10 : 512 };
        var result = GatewayHeaderExporter.Export([Header("X-First", "ok"), Header("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")], policy, false, null);
        Assert.True(result.Incomplete); Assert.Equal(2, result.EligibleValues); Assert.Equal(1, result.DeliveredValues);
        Assert.False(result.Headers.ContainsKey("Content-Security-Policy"));
    }
    [Fact]
    public void Orcamento_de_bytes_considera_utf8_em_vez_de_apenas_contar_caracteres()
    {
        var policy = new PluginManifestGateway { HeaderCount = 32, HeaderBytes = 8, HeaderValueLength = 512 };
        var result = GatewayHeaderExporter.Export([Header("X", "áááá")], policy, false, null);
        Assert.True(result.Incomplete); Assert.Empty(result.Headers); Assert.Contains("byte-budget", result.Omissions);
    }
    [Fact]
    public void Credencial_refletida_em_atributos_nao_cruza_o_processo_nem_vira_aprovacao()
    {
        const string secret = "synthetic-bearer-never-export";
        var policy = new PluginManifestGateway { AuthenticatedResponseHeaders = true, CookieAttributes = true };
        var result = GatewayHeaderExporter.Export([Header("Set-Cookie", "session=hidden; Path=/" + secret), Header("X-Echo", secret)], policy, true, secret);
        Assert.True(result.Incomplete); Assert.Empty(result.Headers); Assert.Contains("credential-redaction", result.Omissions);
    }
    [Fact]
    public void Politica_de_resposta_autenticada_preserva_apenas_status_e_tempo_sem_contagens_do_alvo()
    {
        var result = GatewayHeaderExporter.Export([Header("X-Echo", "private")], Policy, true, "synthetic-bearer");
        Assert.True(result.Incomplete); Assert.Empty(result.Headers);
        Assert.Equal(0, result.EligibleValues); Assert.Contains("policy-restricted", result.Omissions);
    }
    [Fact]
    public void Alvo_nao_pode_forjar_metadados_de_completude_e_cookies_nao_autorizados_nao_sao_exportados()
    {
        var result = GatewayHeaderExporter.Export([Header("X-Sentinel-Headers-Incomplete", "false"), Header("Set-Cookie", "secret=value")],
            new PluginManifestGateway(), false, null);
        Assert.False(result.Incomplete); Assert.Empty(result.Headers); Assert.Equal(0, result.EligibleValues);
    }
}
