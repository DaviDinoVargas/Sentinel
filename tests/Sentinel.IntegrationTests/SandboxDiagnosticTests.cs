using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class SandboxDiagnosticTests
{
    [Theory]
    [InlineData("client version 1.55 is too new. Maximum supported API version is 1.54", "api-version-mismatch")]
    [InlineData("client version 1.20 is too old", "api-version-mismatch")]
    [InlineData("timed out dialing Hyper-V socket", "daemon-unavailable")]
    [InlineData("Cannot connect to the Docker daemon", "daemon-unavailable")]
    [InlineData("dial tcp: connection refused", "daemon-unavailable")]
    [InlineData("access is denied", "daemon-access-denied")]
    [InlineData("permission denied", "daemon-access-denied")]
    [InlineData("unexpected daemon error", "command-rejected")]
    [InlineData("No such container: sentinel-plugin-fixture", "container-not-found")]
    public void Diagnostico_classifica_falha_de_controle_sem_persistir_stderr_segredos_ou_caminhos(string error, string expected)
    {
        const string canary = "synthetic-secret-never-persist";
        var code = SandboxControlException.Classify(error + "\npassword=" + canary + "\nA:/private/fixture.txt");
        var diagnostic = new SandboxControlException(code, "inspect");
        Assert.Equal(expected, diagnostic.Code);
        Assert.DoesNotContain(canary, diagnostic.ToString());
        Assert.DoesNotContain("fixture.txt", diagnostic.ToString());
        Assert.DoesNotContain(error, diagnostic.Message);
    }
}
