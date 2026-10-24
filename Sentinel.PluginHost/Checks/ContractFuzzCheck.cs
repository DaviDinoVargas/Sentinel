using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// FUZZ-05 (fuzz de corpo guiado por contrato) e WEB-INJ-07 (strings gigantes sem limite no servidor).
// Usa o inventário OpenAPI v2 do projeto: para até 3 operações POST/PUT/PATCH de corpo JSON, confirma
// que o corpo VÁLIDO sintético é aceito (base) e então envia mutações pensadas a partir dos CAMPOS
// REAIS do contrato: tipos trocados, obrigatórios ausentes, nulos, números extremos, unicode/controle,
// array gigante, aninhamento profundo e strings de 64 KiB. Espera 4xx controlado, nunca 5xx (nem stack
// trace), nunca aceitação de obrigatório ausente/nulo, nunca aceitação de string gigante nem resposta lenta.
//
// Só lab-active, escopo liberando POST/PUT/PATCH, tudo pelo gateway e na trilha de escrita.
public sealed class ContractFuzzCheck : IIsolatedCheck
{
    private const string FuzzControl = "FUZZ-05";
    private const string GiantControl = "WEB-INJ-07";
    private const int GiantChars = 65_536;
    private const int SlowMilliseconds = 4_000;
    private static readonly string[] Methods = ["POST", "PUT", "PATCH"];
    private static readonly string[] StackMarkers = ["   at System.", "   at Microsoft.", ".cs:line ", "StackTrace", "Traceback (most recent call last)", "java.lang.", "NullReferenceException"];
    private static readonly int[] Controlled = [400, 411, 413, 414, 415, 422, 431];

    private sealed record Mutation(string Name, string Body, bool MustReject, bool Giant);
    private sealed record Outcome(string Operation, string Mutation, int Status, double Millis, bool Leaked);

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        var target = new Uri(request.TargetUri);
        if (!request.Action.Equals("lab-active", StringComparison.OrdinalIgnoreCase) || !request.UseHttpRelay || !ScopedHttp.IsLoopback(target))
            return PluginExecutionResult.Failed(request.ContractVersion, "Fuzz de corpo exige perfil de laboratório com gateway.");
        var operations = ContractBodies.Pick(request.OpenApiInventoryJson, Methods, 3);
        if (operations.Count == 0)
            return Single(request, FuzzControl, "Inconclusive", "Sem inventário OpenAPI do projeto com operação POST/PUT/PATCH de corpo JSON, sem parâmetro de caminho e com campos declarados; nada a verificar.");

        using var client = ScopedHttp.CreateLabClient(target);
        var origin = target.GetLeftPart(UriPartial.Authority);
        var outcomes = new List<Outcome>();
        var checks = new List<PluginCheckResult>();
        int baselineFailed = 0, denied = 0, assessedOperations = 0;
        foreach (var operation in operations)
        {
            ct.ThrowIfCancellationRequested();
            var uri = new Uri(origin + operation.Path);
            var label = operation.Method + " " + operation.Path;
            try
            {
                var baseline = await SendAsync(client, operation.Method, uri, ContractBodies.Build(operation.Fields).ToJsonString(), ct);
                if (baseline.Status is < 200 or >= 300) { baselineFailed++; outcomes.Add(new(label, "base", baseline.Status, baseline.Millis, false)); continue; }
                assessedOperations++;
                foreach (var mutation in Mutations(operation.Fields))
                {
                    var result = await SendAsync(client, operation.Method, uri, mutation.Body, ct);
                    outcomes.Add(new(label, mutation.Name, result.Status, result.Millis, result.Leaked));
                    var rule = $"fuzz-body:{mutation.Name}:{operation.Method}:{operation.Path}";
                    rule = rule[..Math.Min(128, rule.Length)];
                    if (result.Status >= 500)
                        checks.Add(new(mutation.Giant ? GiantControl : FuzzControl, "Failed", $"{label} com mutação '{mutation.Name}' produziu HTTP {result.Status}{(result.Leaked ? " com marcadores de stack trace" : "")}: o servidor deveria recusar com 4xx controlado.",
                            "Reproduced", result.Leaked ? "High" : "Medium", operation.Path, rule));
                    else if (mutation.Giant && result.Status is >= 200 and < 300)
                        checks.Add(new(GiantControl, "Failed", $"{label} aceitou strings de {GiantChars} caracteres em campos do contrato (HTTP {result.Status}): não há limite de tamanho no servidor (risco de DoS por hash/regex/armazenamento caro).",
                            "Reproduced", "Medium", operation.Path, rule));
                    else if (mutation.Giant && result.Millis > SlowMilliseconds)
                        checks.Add(new(GiantControl, "Failed", $"{label} levou {result.Millis:0} ms para responder a strings de {GiantChars} caracteres (HTTP {result.Status}): custo algorítmico por entrada grande.",
                            "Reproduced", "Medium", operation.Path, rule));
                    else if (mutation.MustReject && result.Status is >= 200 and < 300)
                        checks.Add(new(FuzzControl, "Failed", $"{label} aceitou '{mutation.Name}' (HTTP {result.Status}): a validação de campos obrigatórios/nulos do contrato não acontece no servidor.",
                            "Reproduced", "Medium", operation.Path, rule));
                }
            }
            catch (HttpRequestException) { denied++; }
        }

        var answered = outcomes.Where(o => o.Mutation != "base" && o.Status > 0).ToArray();
        var controlled = answered.Count(o => Controlled.Contains(o.Status));
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "contract-fuzz-v1", operations = operations.Select(o => o.Method + " " + o.Path), assessedOperations, baselineRejected = baselineFailed, deniedByGateway = denied,
            mutationsAnswered = answered.Length, controlledRejections = controlled,
            results = outcomes.Select(o => new { op = o.Operation, mutation = o.Mutation, status = o.Status, ms = (int)o.Millis, stackTrace = o.Leaked }),
            limitation = "Até 3 operações POST/PUT/PATCH de corpo JSON sem parâmetro de caminho; 9 classes de mutação derivadas dos campos do contrato; não cobre multipart, GraphQL, autenticação por papel nem fluxos encadeados. Corpos sintéticos, não persistidos.",
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        if (evidence.Length > 15_000) evidence = evidence[..evidence.LastIndexOf('}', 14_000)] + "]}";

        if (checks.Count == 0)
        {
            var passed = denied == 0 && baselineFailed == 0 && assessedOperations > 0 && answered.Length >= 6 && controlled >= 2;
            var reason = denied > 0 ? $"{denied} operação(ões) foram recusadas pelo gateway (o escopo precisa liberar o método em laboratório); nenhuma aprovação inferida."
                : baselineFailed > 0 ? $"{baselineFailed} operação(ões) recusaram até o corpo válido sintético (autenticação, regra de negócio ou dados insuficientes); sem prova."
                : $"Só {controlled} recusa(s) 4xx controlada(s) em {answered.Length} mutações respondidas; sem prova suficiente.";
            checks.Add(passed
                ? new(FuzzControl, "Passed", $"{answered.Length} mutações do corpo (tipos trocados, obrigatórios ausentes/nulos, números extremos, unicode, array gigante, aninhamento e strings de {GiantChars} caracteres) em {assessedOperations} operação(ões) não produziram 5xx nem aceitação indevida; {controlled} foram recusadas com 4xx controlado.", "Reproduced", "Info")
                : new(FuzzControl, "Inconclusive", reason, "NotAssessed", "Info"));
            if (passed) checks.Add(new(GiantControl, "Passed", $"Strings de {GiantChars} caracteres em campos do contrato foram recusadas ou tratadas sem lentidão (até {SlowMilliseconds} ms) em {assessedOperations} operação(ões).", "Reproduced", "Info"));
        }
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, checks, [new PluginEvidenceRef(checks[0].Summary, evidence)], []);
    }

    private static List<Mutation> Mutations(JsonElement[] fields)
    {
        var mutations = new List<Mutation>();
        var hasRequired = fields.Any(ContractBodies.Required);
        string Json(JsonObject o) => o.ToJsonString();

        mutations.Add(new("tipo-trocado", Json(ContractBodies.Build(fields, f => (true, ContractBodies.Type(f) switch
        {
            "integer" or "number" => JsonValue.Create("sentinel-texto"),
            "boolean" => JsonValue.Create("sim"),
            var t when t.StartsWith("array<") => JsonValue.Create("nao-e-array"),
            "object" => new JsonArray(),
            _ => JsonValue.Create(123456),
        }))), false, false));
        if (hasRequired)
        {
            mutations.Add(new("obrigatorio-ausente", Json(ContractBodies.Build(fields, omit: ContractBodies.Required)), true, false));
            mutations.Add(new("nulo-em-obrigatorio", Json(ContractBodies.Build(fields, f => ContractBodies.Required(f) ? (true, null) : (false, null))), true, false));
        }
        mutations.Add(new("numero-extremo", Json(ContractBodies.Build(fields, f => ContractBodies.Type(f) is "integer" or "number" ? (true, JsonValue.Create(double.MaxValue)) : (false, null))), false, false));
        mutations.Add(new("unicode-controle", Json(ContractBodies.Build(fields, f => ContractBodies.Type(f) == "string" && ContractBodies.FirstEnum(f) is null ? (true, JsonValue.Create("@@UNI@@")) : (false, null)))
            .Replace("\"@@UNI@@\"", "\"\\u0000\\ud800\\u202e\\u2028\\ufeff\"", StringComparison.Ordinal), false, false));
        if (fields.Any(f => ContractBodies.Type(f).StartsWith("array<", StringComparison.Ordinal)))
            mutations.Add(new("array-gigante", Json(ContractBodies.Build(fields, f => ContractBodies.Type(f).StartsWith("array<", StringComparison.Ordinal) ? (true, new JsonArray(Enumerable.Range(0, 5000).Select(_ => (JsonNode?)JsonValue.Create("x")).ToArray())) : (false, null))), false, false));
        var deep = ContractBodies.Build(fields); deep["sentinel_deep"] = "@@DEEP@@";
        mutations.Add(new("aninhamento-profundo", Json(deep).Replace("\"@@DEEP@@\"", new string('[', 1500) + new string(']', 1500), StringComparison.Ordinal), false, false));
        var giantCount = 0;
        mutations.Add(new("string-gigante", Json(ContractBodies.Build(fields, f => ContractBodies.Type(f) == "string" && ContractBodies.FirstEnum(f) is null && giantCount++ < 3 ? (true, JsonValue.Create(new string('A', GiantChars))) : (false, null))), false, true));
        return mutations;
    }

    private static async Task<(int Status, double Millis, bool Leaked)> SendAsync(HttpClient client, string method, Uri uri, string body, CancellationToken ct)
    {
        using var message = new HttpRequestMessage(new HttpMethod(method), uri) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        var clock = Stopwatch.StartNew();
        using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
        var status = (int)response.StatusCode;
        var text = status >= 500 ? await ScopedHttp.ReadPrefixAsync(response, ct) : "";
        clock.Stop();
        return (status, clock.Elapsed.TotalMilliseconds, StackMarkers.Any(marker => text.Contains(marker, StringComparison.Ordinal)));
    }

    private static PluginExecutionResult Single(PluginExecutionRequest request, string control, string state, string summary) =>
        new(request.ContractVersion, state == "Inconclusive" ? PluginExecutionOutcome.Inconclusive : PluginExecutionOutcome.Succeeded,
            [new PluginCheckResult(control, state, summary, "NotAssessed", "Info")], [new PluginEvidenceRef(summary, "contract-fuzz-unavailable")], []);
}
