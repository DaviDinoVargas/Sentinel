using System.Text;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class BoundedProtocolReaderTests
{
    [Fact]
    public async Task Mensagens_disponiveis_em_lote_nao_exigem_uma_leitura_por_caractere()
    {
        using var stream = new CountingStream(Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("frame\n", 1000))));
        var reader = new BoundedProtocolReader(stream, 16);
        for (var i = 0; i < 1000; i++) Assert.Equal("frame", await reader.ReadLineAsync(default));
        Assert.Null(await reader.ReadLineAsync(default));
        Assert.True(stream.Reads < 10, $"Leituras para 1000 frames: {stream.Reads}");
    }

    [Fact]
    public async Task Preserva_frames_consecutivos_vazios_crlf_e_ultimo_sem_quebra()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("\uFEFFone\r\n\ntwo\nfinal"));
        var reader = new BoundedProtocolReader(stream, 16);
        Assert.Equal("one", await reader.ReadLineAsync(default));
        Assert.Equal("", await reader.ReadLineAsync(default));
        Assert.Equal("two", await reader.ReadLineAsync(default));
        Assert.Equal("final", await reader.ReadLineAsync(default));
        Assert.Null(await reader.ReadLineAsync(default));
    }

    [Fact]
    public async Task Utf8_fragmentado_nao_corrompe_texto_nem_consume_o_proximo_frame()
    {
        using var stream = new FragmentedStream(Encoding.UTF8.GetBytes("ação🔒\nnext\n"));
        var reader = new BoundedProtocolReader(stream, 16);
        Assert.Equal("ação🔒", await reader.ReadLineAsync(default));
        Assert.Equal("next", await reader.ReadLineAsync(default));
    }

    [Theory]
    [InlineData("12345678\n", false)]
    [InlineData("123456789\n", true)]
    [InlineData("123456789", true)]
    [InlineData("áááááááá\n", false)]
    [InlineData("ááááááááá\n", true)]
    public async Task Limite_e_por_caracteres_e_nao_apenas_bytes(string text, bool rejected)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(text));
        var reader = new BoundedProtocolReader(stream, 8);
        if (rejected) await Assert.ThrowsAsync<InvalidOperationException>(() => reader.ReadLineAsync(default));
        else Assert.Equal(text.TrimEnd('\n'), await reader.ReadLineAsync(default));
    }

    [Fact]
    public async Task Fluxo_sem_quebra_e_limitado_antes_de_ler_conteudo_arbitrario()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(new string('x', 100_000)));
        var reader = new BoundedProtocolReader(stream, 8);
        await Assert.ThrowsAsync<InvalidOperationException>(() => reader.ReadLineAsync(default));
        Assert.True(stream.Position < stream.Length);
    }

    [Fact]
    public async Task Utf8_invalido_e_recusado()
    {
        using var stream = new MemoryStream([0xC3, 0x28, 0x0A]);
        await Assert.ThrowsAsync<DecoderFallbackException>(() => new BoundedProtocolReader(stream, 8).ReadLineAsync(default));
    }

    [Fact]
    public async Task Cancelamento_tambem_interrompe_frames_ja_bufferizados()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("one\ntwo\n"));
        var reader = new BoundedProtocolReader(stream, 8);
        Assert.Equal("one", await reader.ReadLineAsync(default));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reader.ReadLineAsync(cancelled.Token));
    }

    private sealed class FragmentedStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => base.ReadAsync(buffer[..Math.Min(buffer.Length, 1)], cancellationToken);
    }

    private sealed class CountingStream(byte[] bytes) : MemoryStream(bytes)
    {
        public int Reads { get; private set; }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        { Reads++; return base.ReadAsync(buffer, cancellationToken); }
    }
}
