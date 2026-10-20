using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

public sealed class SourceSecretsCheck : IIsolatedCheck
{
    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        if (request.SourceRoot != "/source" || !Directory.Exists("/source")) return PluginExecutionResult.Failed(request.ContractVersion, "Snapshot somente leitura indisponível.");
        var start = new ProcessStartInfo("/usr/local/bin/gitleaks") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = "/app" };
        start.Environment.Clear(); start.Environment["HOME"] = "/tmp";
        foreach (var arg in new[] { "dir", "/source", "--config", "/app/gitleaks.toml", "--report-format", "json", "--report-path", "-", "--redact=100", "--no-banner", "--no-color", "--log-level", "error", "--exit-code", "42", "--ignore-gitleaks-allow", "--max-target-megabytes", "2", "--max-decode-depth", "0", "--max-archive-depth", "0", "--timeout", "75" }) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Scanner indisponível.");
        async Task<string> ReadBounded(StreamReader reader, int maximum)
        {
            var output = new StringBuilder(); var buffer = new char[4096]; int read;
            while ((read = await reader.ReadAsync(buffer, ct)) != 0) { if (output.Length + read > maximum) { process.Kill(true); throw new InvalidDataException("Saída do scanner excedeu limite."); } output.Append(buffer, 0, read); } return output.ToString();
        }
        var outputTask = ReadBounded(process.StandardOutput, 1_048_576); var errorTask = ReadBounded(process.StandardError, 8192);
        try { await process.WaitForExitAsync(ct); }
        catch { if(!process.HasExited) process.Kill(true); try { await Task.WhenAll(outputTask,errorTask); } catch { } throw; }
        var output = await outputTask; var error = await errorTask;
        // stderr/report raw values are never forwarded, even in failure diagnostics.
        if (process.ExitCode is not (0 or 42) || !string.IsNullOrWhiteSpace(error)) return PluginExecutionResult.Failed(request.ContractVersion, "Gitleaks não concluiu a análise de forma válida; saída bruta descartada.");
        using var report = JsonDocument.Parse(string.IsNullOrWhiteSpace(output) && process.ExitCode == 0 ? "[]" : output, new JsonDocumentOptions { MaxDepth = 16 });
        if (report.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Relatório do scanner inválido.");
        var normalized = new List<SecretCandidate>();
        foreach (var item in report.RootElement.EnumerateArray())
        {
            var file = item.GetProperty("File").GetString() ?? "";
            if (file.StartsWith("/source/", StringComparison.Ordinal)) file = file[8..];
            file = SourceArchivePolicy.SafePath(file);
            var rule = item.GetProperty("RuleID").GetString() ?? "";
            if (!Regex.IsMatch(rule, "^[a-zA-Z0-9._-]{1,100}$")) throw new InvalidDataException("Regra inválida no relatório.");
            var line = item.GetProperty("StartLine").GetInt32(); if (line < 1 || line > SourceArchivePolicy.MaximumFileBytes) throw new InvalidDataException("Localização inválida no relatório.");
            normalized.Add(new(file, rule, line));
        }
        if (process.ExitCode == 42 && normalized.Count == 0 || process.ExitCode == 0 && normalized.Count != 0) throw new InvalidDataException("Estado do scanner divergiu do relatório.");
        var groups = normalized.GroupBy(c => new { c.File, c.Rule }).OrderBy(g => g.Key.File, StringComparer.Ordinal).ThenBy(g => g.Key.Rule).ToArray();
        var selected = groups.Take(16).Select(g => new { file = g.Key.File, rule = g.Key.Rule, lines = g.Select(c => c.Line).Distinct().Order().Take(10).ToArray(), count = g.Count() }).ToArray();
        var checks = selected.Select(g => new PluginCheckResult("SUP-04", "Failed", $"Padrão potencial de segredo: regra {g.rule}, arquivo {g.file[..Math.Min(g.file.Length,120)]}, {g.count} ocorrência(s). Valor omitido; validade/uso da credencial não testados.", "Hypothesis", "High", g.file, g.rule)).ToList();
        if (groups.Length == 0) checks.Add(new("SUP-04", "Informational", "Nenhum padrão de segredo reportado no recorte de arquivos. Não comprova ausência de segredos e não encerra achados anteriores.", "NotAssessed", "Info"));
        if (groups.Length > selected.Length) checks.Add(new("SUP-04", "Inconclusive", "Relatório limitado a 16 grupos de arquivo/regra; existem outros candidatos não exportados.", "NotAssessed", "Info"));
        var details = JsonSerializer.Serialize(new { kind = "source-secrets-v1", tool = "gitleaks", toolVersion = "8.30.1", sourceSha256 = request.SourceSha256,
            candidateCount = normalized.Count, groupCount = groups.Length, exportedGroups = selected, truncated = groups.Length > 16,
            secretValuesStored = false, limitations = new[] { "Padrões e entropia geram hipóteses; sem validação, uso de credenciais ou acesso externo.", "Somente snapshot atual, sem histórico Git, arquivos acima dos limites, arquivos binários ignorados pelo scanner, decodificação ou arquivos compactados aninhados.", "Configuração da plataforma e regras padrão da versão fixada; comentários gitleaks:allow e .gitleaksignore não dispensam achados.", "Ausência de candidatos é Informational, nunca Passed; regressão de segredo exige futura avaliação de cobertura comparável." } });
        return new(request.ContractVersion, groups.Length > 16 ? PluginExecutionOutcome.Partial : PluginExecutionOutcome.Succeeded, checks,
            [new("Candidatos a segredos com regra/localização; valores e trechos descartados.", details)], []);
    }
    private sealed record SecretCandidate(string File, string Rule, int Line);
}
