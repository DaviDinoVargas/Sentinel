using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Execution;
using Sentinel.PluginHost.Checks;

namespace Sentinel.IntegrationTests;

// V39: ponte ZAP -> gateway, recursos de container declarados no manifesto e a imagem real com
// o ZAP. O ZAP nunca tem rede própria; a ponte é o único caminho dele até o alvo.
public sealed class ZapBridgeTests
{
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    private sealed class Stub(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) : HttpMessageHandler
    {
        public int Calls;
        public HttpRequestMessage? Last;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { Interlocked.Increment(ref Calls); Last = request; return await handler(request); }
    }

    private static async Task<string> RawAsync(int port, string request)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        var stream = tcp.GetStream();
        await stream.WriteAsync(Encoding.Latin1.GetBytes(request));
        using var reader = new StreamReader(stream, Encoding.Latin1);
        return await reader.ReadToEndAsync();
    }

    [Fact]
    public async Task Get_absoluto_atravessa_o_gateway_com_cabecalhos_filtrados_e_sem_metadados_internos()
    {
        var stub = new Stub(request =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes("<html>ola</html>")) };
            response.Content.Headers.ContentType = new("text/html");
            response.Headers.TryAddWithoutValidation("X-Frame-Options", "DENY");
            response.Headers.TryAddWithoutValidation("X-Sentinel-Body-Truncated", "false");
            return Task.FromResult(response);
        });
        using var bridge = new ZapBridge(new HttpClient(stub));
        bridge.Start();

        var raw = await RawAsync(bridge.Port, "GET http://alvo.local:8080/pagina?x=1 HTTP/1.1\r\nHost: alvo.local:8080\r\nUser-Agent: zap\r\nCookie: sessao=segredo\r\nX-Custom: nao-passa\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 200", raw);
        Assert.Contains("<html>ola</html>", raw);
        Assert.Contains("X-Frame-Options: DENY", raw);
        Assert.Contains("Content-Type: text/html", raw);
        Assert.DoesNotContain("X-Sentinel-", raw);
        Assert.Equal("http://alvo.local:8080/pagina?x=1", stub.Last!.RequestUri!.AbsoluteUri);
        Assert.Equal("zap", Assert.Single(stub.Last.Headers.UserAgent.Select(item => item.Product!.Name)));
        Assert.False(stub.Last.Headers.Contains("Cookie"));
        Assert.False(stub.Last.Headers.Contains("X-Custom"));
        Assert.Equal(1, bridge.Forwarded);
    }

    [Fact]
    public async Task Metodos_de_escrita_e_connect_nunca_chegam_ao_gateway()
    {
        var stub = new Stub(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        using var bridge = new ZapBridge(new HttpClient(stub));
        bridge.Start();

        Assert.StartsWith("HTTP/1.1 405", await RawAsync(bridge.Port, "POST http://alvo.local/x HTTP/1.1\r\nHost: alvo.local\r\nContent-Length: 0\r\n\r\n"));
        Assert.StartsWith("HTTP/1.1 501", await RawAsync(bridge.Port, "CONNECT alvo.local:443 HTTP/1.1\r\nHost: alvo.local:443\r\n\r\n"));
        Assert.Equal(0, stub.Calls);
        Assert.Equal(2, bridge.Unsupported);
    }

    [Fact]
    public async Task Hosts_fora_do_alvo_sao_bloqueados_na_ponte_sem_gastar_orcamento_nem_virar_lacuna()
    {
        var stub = new Stub(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent([1]) }));
        using var bridge = new ZapBridge(new HttpClient(stub), allowedOrigin: new Uri("http://alvo.local:8080/app/"));
        bridge.Start();

        Assert.StartsWith("HTTP/1.1 403", await RawAsync(bridge.Port, "GET http://cfu.zaproxy.org/check HTTP/1.1\r\nHost: cfu.zaproxy.org\r\n\r\n"));
        Assert.StartsWith("HTTP/1.1 403", await RawAsync(bridge.Port, "CONNECT cfu.zaproxy.org:443 HTTP/1.1\r\nHost: cfu.zaproxy.org:443\r\n\r\n"));
        Assert.Equal(0, stub.Calls);
        Assert.Equal(2, bridge.OffTarget);
        Assert.Equal(0, bridge.Refused);
        Assert.Equal(0, bridge.Unsupported);

        Assert.StartsWith("HTTP/1.1 200", await RawAsync(bridge.Port, "GET http://alvo.local:8080/app/p HTTP/1.1\r\nHost: alvo.local:8080\r\n\r\n"));
        Assert.Equal(1, stub.Calls);
    }

    [Fact]
    public async Task Recusa_do_gateway_vira_502_contabilizado_e_nunca_sucesso()
    {
        var stub = new Stub(_ => throw new HttpRequestException("Gateway recusou escopo."));
        using var bridge = new ZapBridge(new HttpClient(stub));
        bridge.Start();

        Assert.StartsWith("HTTP/1.1 502", await RawAsync(bridge.Port, "GET http://fora-do-escopo.invalid/ HTTP/1.1\r\nHost: fora-do-escopo.invalid\r\n\r\n"));
        Assert.Equal(1, bridge.Refused);
        Assert.Equal(0, bridge.Forwarded);
    }

    [Fact]
    public void Recursos_de_container_vem_do_manifesto_e_ficam_limitados_pelo_host()
    {
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Image = "sha256:" + new string('a', 64) }), new Env());
        PluginManifest Manifest(int memory, double cpus, int pids, int tmpfs)
        {
            var manifest = new PluginManifest { Metadata = { Id = "teste.recursos" } };
            manifest.Spec.Resources.MemoryMiB = memory; manifest.Spec.Resources.Cpus = cpus; manifest.Spec.Resources.Pids = pids; manifest.Spec.Resources.TmpfsMiB = tmpfs;
            return manifest;
        }
        string[] Args(PluginManifest manifest) => runtime.Start("unused", manifest, "sentinel-plugin-" + new string('b', 32), DateTimeOffset.UtcNow.AddMinutes(1)).ArgumentList.ToArray();
        string After(string[] args, string flag) => args[Array.IndexOf(args, flag) + 1];

        var granted = Args(Manifest(1536, 1, 512, 256));
        Assert.Equal("1536m", After(granted, "--memory"));
        Assert.Equal("1", After(granted, "--cpus"));
        Assert.Equal("512", After(granted, "--pids-limit"));
        Assert.Equal("/tmp:rw,noexec,nosuid,size=256m", After(granted, "--tmpfs"));
        Assert.Contains("none", After(granted, "--network"));

        var excessive = Args(Manifest(99_999, 64, 99_999, 99_999));
        Assert.Equal("2048m", After(excessive, "--memory"));
        Assert.Equal("2", After(excessive, "--cpus"));
        Assert.Equal("512", After(excessive, "--pids-limit"));
        Assert.Equal("/tmp:rw,noexec,nosuid,size=512m", After(excessive, "--tmpfs"));

        var defaults = Args(new PluginManifest { Metadata = { Id = "teste.padrao" } });
        Assert.Equal("128m", After(defaults, "--memory"));
        Assert.Equal("0.5", After(defaults, "--cpus"));
        Assert.Equal("64", After(defaults, "--pids-limit"));
        Assert.Equal("/tmp:rw,noexec,nosuid,size=16m", After(defaults, "--tmpfs"));
    }

    [Fact]
    public async Task Imagem_da_sandbox_traz_jre_e_zap_fixados_e_roda_sem_rede_como_usuario_sem_privilegio()
    {
        var start = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in new[] { "run", "--rm", "--network", "none", "--read-only", "--user", "65532:65532", "--cap-drop", "ALL", "--entrypoint", "sh", Image, "-c",
            "java -version 2>&1 | head -1 && test -f /zap/zap-2.17.0.jar && echo zap-2.17.0-presente" }) start.ArgumentList.Add(argument);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await process.WaitForExitAsync(timeout.Token);
        var text = await output + await error;
        Assert.True(process.ExitCode == 0, text);
        Assert.Contains("openjdk version \"17", text);
        Assert.Contains("zap-2.17.0-presente", text);
    }

    private sealed class Env : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "Sentinel.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}
