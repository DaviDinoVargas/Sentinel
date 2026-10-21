using System.Text;

namespace Sentinel.Execution;

// Read available pipe bytes in batches without waiting for a full text buffer.
// Keep framing and memory bounded even when a plugin never sends a newline.
internal sealed class BoundedProtocolReader(Stream stream, int maximumChars)
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private readonly byte[] _buffer = new byte[4096];
    private int _position;
    private int _count;
    private bool _firstLine = true;

    public async Task<string?> ReadLineAsync(CancellationToken ct)
    {
        using var line = new MemoryStream();
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            if (_position == _count)
            {
                _count = await stream.ReadAsync(_buffer.AsMemory(), ct);
                _position = 0;
                if (_count == 0) return line.Length == 0 ? null : Decode(line);
            }
            var end = Array.IndexOf(_buffer, (byte)'\n', _position, _count - _position);
            var length = (end < 0 ? _count : end) - _position;
            if (line.Length + length > (long)maximumChars * 4)
                throw new InvalidOperationException("Linha do protocolo excedeu o limite.");
            line.Write(_buffer, _position, length);
            _position += length;
            if (end >= 0) { _position++; return Decode(line); }
        }
    }

    private string Decode(MemoryStream line)
    {
        var value = Utf8.GetString(line.GetBuffer(), 0, checked((int)line.Length));
        if (_firstLine) { if (value.StartsWith('\uFEFF')) value = value[1..]; _firstLine = false; }
        if (value.Length > maximumChars)
            throw new InvalidOperationException("Linha do protocolo excedeu o limite.");
        return value.TrimEnd('\r');
    }
}
