using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.Execution;

public sealed partial class ScopedHttpGateway
{
    public sealed partial class Session
    {
        // Resultado interno de UMA tentativa de login. O valor do campo de erro (ErrorField) nunca sai
        // daqui: é comparado no host e só booleanos chegam à observação entregue ao plugin.
        private sealed record EnumAttempt(int Status, string? ErrorField, bool Accepted, bool Stop, string? StopReason);

        // AUTH-ENUM-01 (parcial): o host autentica a referência, intercala três pares de tentativas com
        // senha sintética inválida para o identificador conhecido e para um declarado inexistente pelo
        // operador, e faz um controle final. Compara status e um campo de erro escalar dentro do host e
        // entrega só estatísticas booleanas. Nunca exporta nomes, senhas, tokens, corpos ou mensagens.
        public async Task<EnumerationObservation> EvaluateEnumerationAsync(CancellationToken ct)
        {
            var steps = new List<EnumerationStepObservation>();
            var observation = new EnumerationObservation("NotConfigured", Steps: steps);
            if (!_manifest.Spec.Capabilities.Gateway.EnumerationCheck || _request.Action != "authenticated-lab" ||
                _request.ExpectedAccess != "allow" || _credential?.CredentialType != "JsonLogin") return observation;
            try
            {
                var material = _gateway._credentials!.Material(_request.ProjectId, _request.ScopeId, _credential);
                if (material.Login is not { Configuration.Enumeration: { } contract, ExpectedIdentity: { } identity,
                    ComparisonUsername: { } comparison, SyntheticPassword: { } synthetic } login) return observation;
                observation = observation with { UniformityExpected = contract.UniformityExpected };

                // 1. A referência (já preparada pelo worker, ou autenticada aqui na primeira requisição) tem de
                // mapear para a identidade esperada no recurso protegido. Sem isso, a comparação não tem âncora.
                bool? referenceIdentity = null;
                var referenceGet = await SendCoreAsync(new("http-request", Guid.NewGuid(), "GET", _target.AbsoluteUri, []), ct,
                    (bytes, complete, media) => { if (complete && IsJsonMedia(media)) referenceIdentity = MatchesIdentity(bytes, contract.IdentityPath, identity); });
                steps.Add(new("reference", 0, referenceGet.StatusCode, false));
                if (referenceGet.Error is not null || referenceGet.StatusCode is < 200 or >= 300 || referenceIdentity != true)
                    return observation with { Code = "ReferenceUnverified" };
                observation = observation with { ReferenceVerified = true };

                // 2. Três pares intercalados de tentativas deliberadamente inválidas. Qualquer bloqueio, limite de
                // taxa, revogação, transporte indisponível ou aceitação inesperada interrompe imediatamente.
                var knownStatuses = new List<int>(); var knownErrors = new List<string?>();
                var unknownStatuses = new List<int>(); var unknownErrors = new List<string?>();
                for (var pair = 1; pair <= 3; pair++)
                {
                    var known = await AttemptLoginAsync(login, login.Username, synthetic, contract.ErrorPath, "known", ct);
                    steps.Add(new("known", pair, known.Status, known.ErrorField is not null));
                    knownStatuses.Add(known.Status); knownErrors.Add(known.ErrorField);
                    if (known.Stop) return observation with { Code = "Stopped", KnownAttempts = pair, NonexistentAttempts = pair - 1, Stopped = true, StopReason = known.StopReason };

                    var unknown = await AttemptLoginAsync(login, comparison, synthetic, contract.ErrorPath, "nonexistent", ct);
                    steps.Add(new("nonexistent", pair, unknown.Status, unknown.ErrorField is not null));
                    unknownStatuses.Add(unknown.Status); unknownErrors.Add(unknown.ErrorField);
                    if (unknown.Stop) return observation with { Code = "Stopped", KnownAttempts = pair, NonexistentAttempts = pair, Stopped = true, StopReason = unknown.StopReason };
                }
                observation = observation with { KnownAttempts = 3, NonexistentAttempts = 3 };

                // 3. Controle final: prova que as tentativas inválidas não derrubaram a credencial de referência
                // (o login normal do perfil continua válido). Exige autenticação nova — LoginAsync guarda cache.
                _primaryLogin.Token = null; _primaryLogin.RefreshToken = null; _primaryLogin.Attempted = false;
                if (await LoginAsync(login, ct) is null) return observation with { Code = "ControlUnavailable" };
                bool? controlIdentity = null;
                var controlGet = await SendCoreAsync(new("http-request", Guid.NewGuid(), "GET", _target.AbsoluteUri, []), ct,
                    (bytes, complete, media) => { if (complete && IsJsonMedia(media)) controlIdentity = MatchesIdentity(bytes, contract.IdentityPath, identity); });
                steps.Add(new("control", 0, controlGet.StatusCode, false));
                if (controlGet.Error is not null || controlGet.StatusCode is < 200 or >= 300 || controlIdentity != true)
                    return observation with { Code = "ControlUnavailable" };
                observation = observation with { ControlVerified = true };

                // 4. Comparação só no host: apenas booleanos atravessam para o plugin, nunca os valores de erro.
                static bool StatusConsistent(List<int> s) => s.Count == 3 && s.Distinct().Count() == 1;
                static bool? ErrorConsistent(List<string?> e) => e.Any(v => v is null) ? null : e.Distinct(StringComparer.Ordinal).Count() == 1;
                var knownStatusConsistent = StatusConsistent(knownStatuses);
                var unknownStatusConsistent = StatusConsistent(unknownStatuses);
                var knownErrorConsistent = ErrorConsistent(knownErrors);
                var unknownErrorConsistent = ErrorConsistent(unknownErrors);
                bool? statusDiffers = knownStatusConsistent && unknownStatusConsistent ? knownStatuses[0] != unknownStatuses[0] : null;
                bool? errorDiffers = knownErrorConsistent == true && unknownErrorConsistent == true
                    ? !string.Equals(knownErrors[0], unknownErrors[0], StringComparison.Ordinal) : null;
                return observation with
                {
                    Code = "Evaluated",
                    StatusConsistentWithinKnown = knownStatusConsistent,
                    StatusConsistentWithinNonexistent = unknownStatusConsistent,
                    ErrorFieldConsistentWithinKnown = knownErrorConsistent,
                    ErrorFieldConsistentWithinNonexistent = unknownErrorConsistent,
                    StatusDiffersBetweenGroups = statusDiffers,
                    ErrorFieldDiffersBetweenGroups = errorDiffers,
                };
            }
            catch (Exception error) when (error is InvalidOperationException or ArgumentException or KeyNotFoundException or System.Security.Cryptography.CryptographicException)
            { return observation with { Code = "ConfigurationOrCredentialUnavailable" }; }
        }

        // Uma tentativa de login com usuário/senha informados (referência usa a credencial real; sondas usam a
        // senha sintética inválida). Espelha a governança de LoginAsync (escopo, política POST, orçamento de
        // login, verificação de revogação) sem sobrescrever o diagnóstico de login normal do perfil: registra
        // um evento próprio de sondagem e lê a resposta completa só para extrair o campo de erro escalar no host.
        private async Task<EnumAttempt> AttemptLoginAsync(JsonLoginInput login, string username, string password, string errorPath, string group, CancellationToken ct)
        {
            var binding = _credential!;
            byte[]? body = null;
            try
            {
                var uri = new Uri(login.Configuration.Url);
                if (uri.Scheme != _target.Scheme || uri.IdnHost != _target.IdnHost || uri.Port != _target.Port) return new(0, null, false, true, "OutsideScope");
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var remaining = _request.DeadlineUtc - _gateway._time.GetUtcNow();
                if (remaining <= TimeSpan.Zero) return new(0, null, false, true, "Deadline");
                deadline.CancelAfter(remaining < TimeSpan.FromSeconds(10) ? remaining : TimeSpan.FromSeconds(10));
                var token = deadline.Token;
                while (true)
                {
                    token.ThrowIfCancellationRequested();
                    var scopes = _gateway._store.GetScopes(_request.ProjectId);
                    var scope = scopes.SingleOrDefault(s => s.Id == _request.ScopeId);
                    if (scope is null || !_gateway._policy.Evaluate(scopes, uri, _request.Action, _gateway._time.GetUtcNow(), true, "POST", _request.ScopeId).IsAllowed)
                        return new(0, null, false, true, "OutsideScope");
                    TargetJsonLogin.Validate(login, scope, _gateway._time.GetUtcNow());
                    _gateway._credentials!.Material(_request.ProjectId, _request.ScopeId, binding);
                    var permit = _gateway._coordinator.Permit(_lease, login: true, loginAllowed: true,
                        loginBudget: _manifest.Spec.Capabilities.Gateway.LoginRequests);
                    if (permit.Allowed) break;
                    if (permit.RetryAfterMs == 0) return new(0, null, false, true, "CancelledOrBudgetDenied");
                    await Task.Delay(Math.Min(permit.RetryAfterMs, 200), token);
                }
                var fields = new Dictionary<string, string> { [login.Configuration.UsernameField] = username, [login.Configuration.PasswordField] = password };
                if (login.Configuration.TenantField is { } tenant && login.Tenant is { } tenantValue) fields[tenant] = tenantValue;
                body = JsonSerializer.SerializeToUtf8Bytes(fields);
                using var message = new HttpRequestMessage(HttpMethod.Post, uri) { Content = new ByteArrayContent(body) };
                message.Content.Headers.ContentType = new("application/json");
                using var response = await _client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, token);
                var status = (int)response.StatusCode;
                _gateway._coordinator.Trail(_lease, "EnumerationProbe", $"{_manifest.Metadata.Id} POST {uri.AbsolutePath} grupo={group} -> {status}");
                // Bloqueio, limite de taxa, redirecionamento ou erro de servidor param o fluxo inteiro.
                if (status is 423 or 429 || response.Headers.RetryAfter is not null) return new(status, null, false, true, "RateLimitedOrLocked");
                if (status is >= 500 or (>= 300 and < 400)) return new(status, null, false, true, "TargetUnavailableOrRedirect");
                string? errorField = null; var accepted = false;
                if (response.Content.Headers.ContentType?.MediaType == "application/json")
                {
                    await using var stream = await response.Content.ReadAsStreamAsync(token);
                    var buffer = new byte[32769]; var count = 0;
                    try
                    {
                        while (count < buffer.Length) { var n = await stream.ReadAsync(buffer.AsMemory(count), token); if (n == 0) break; count += n; }
                        if (count == buffer.Length) return new(status, null, false, true, "ResponseTooLarge");
                        // A senha sintética não é dicionário; uma aceitação inesperada interrompe e nunca
                        // reutiliza a sessão obtida (o token extraído aqui é descartado ao zerar o buffer).
                        if (status is >= 200 and < 300) accepted = TargetJsonLogin.Extract(buffer.AsMemory(0, count), login.Configuration.TokenPath) is not null;
                        else errorField = EnumerationErrorField(buffer.AsMemory(0, count), errorPath);
                    }
                    finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer); }
                }
                if (status is >= 200 and < 300) return new(status, null, accepted, true, accepted ? "UnexpectedAccept" : "UnexpectedSuccessNoToken");
                // Falha esperada; se o campo de erro não for escalar/inequívoco, errorField fica null e a
                // consistência do grupo vira ambígua (o plugin não aprova por ausência de sinal).
                return new(status, errorField, false, false, null);
            }
            catch (Exception e) when (e is System.Net.Http.HttpRequestException or IOException or OperationCanceledException or JsonException or ArgumentException or InvalidOperationException or KeyNotFoundException or System.Security.Cryptography.CryptographicException)
            { return new(0, null, false, true, "TransportOrConfigUnavailable"); }
            finally { if (body is not null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(body); }
        }

        private static bool IsJsonMedia(string? media) => media == "application/json" || media?.EndsWith("+json", StringComparison.OrdinalIgnoreCase) == true;

        // Valor escalar do campo de erro, inequívoco (uma única propriedade por segmento). Fica só no host.
        internal static string? EnumerationErrorField(ReadOnlyMemory<byte> bytes, string path)
        {
            try
            {
                using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
                var node = doc.RootElement;
                foreach (var segment in path.Split('.'))
                {
                    if (node.ValueKind != JsonValueKind.Object) return null;
                    var matches = node.EnumerateObject().Where(property => property.Name == segment).ToArray();
                    if (matches.Length != 1) return null;
                    node = matches[0].Value;
                }
                return node.ValueKind switch
                {
                    JsonValueKind.String => node.GetString(),
                    JsonValueKind.Number => node.GetRawText(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    _ => null,
                };
            }
            catch (JsonException) { return null; }
        }
    }
}
