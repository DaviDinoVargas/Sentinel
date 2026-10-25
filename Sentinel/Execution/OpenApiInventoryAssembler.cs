// The caller must verify artifact integrity, project, origin and producer provenance first.
using System.Text;
using System.Text.Json;

namespace Sentinel.Execution;

internal sealed record InventoryAssemblyLimits(int MaximumParts, int MaximumUtf8Bytes, int MaximumOperations);
internal sealed record InventoryAssemblyResult(string? Json, bool Complete, int ExpectedParts, int ReceivedParts,
    int DeclaredOperations, int LoadedOperations, IReadOnlyList<string> Issues);

internal static class OpenApiInventoryAssembler
{
    internal static InventoryAssemblyResult Assemble(IEnumerable<string> verifiedParts, string? expectedSourceHash,
        int declaredOperations, bool producerComplete, InventoryAssemblyLimits limits)
    {
        ArgumentNullException.ThrowIfNull(verifiedParts);
        if (limits.MaximumParts < 1 || limits.MaximumUtf8Bytes < 1 || limits.MaximumOperations < 1 || declaredOperations < 0)
            throw new ArgumentException("Invalid inventory assembly policy.");
        var issues = new HashSet<string>(StringComparer.Ordinal);
        if (!producerComplete) issues.Add("producer-partial");
        if (expectedSourceHash is not { Length: 64 } || !expectedSourceHash.All(Uri.IsHexDigit))
            return new(null, false, 0, 0, declaredOperations, 0, ["source-hash-unavailable"]);
        var parts = new SortedDictionary<int, string>();
        var expectedParts = 0; var operationCount = 0; var inputBytes = 0;
        var fatal = false;
        foreach (var content in verifiedParts)
        {
            var bytes = Encoding.UTF8.GetByteCount(content);
            if (bytes > limits.MaximumUtf8Bytes - inputBytes) { issues.Add("input-budget-exceeded"); break; }
            inputBytes += bytes;
            if (parts.Count >= limits.MaximumParts) { issues.Add("part-budget-exceeded"); break; }
            try
            {
                using var document = JsonDocument.Parse(content);
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object ||
                    !root.TryGetProperty("kind", out var kind) || kind.GetString() != "sentinel-openapi-inventory-v2" ||
                    !root.TryGetProperty("chunk", out var chunk) || !chunk.TryGetInt32(out var number) ||
                    !root.TryGetProperty("chunks", out var chunks) || !chunks.TryGetInt32(out var total) ||
                    number < 1 || total < 1 || number > total ||
                    !root.TryGetProperty("sourceSha256", out var sha) || sha.ValueKind != JsonValueKind.String ||
                    !string.Equals(sha.GetString(), expectedSourceHash, StringComparison.OrdinalIgnoreCase) ||
                    !root.TryGetProperty("operations", out var operations) || operations.ValueKind != JsonValueKind.Array)
                { fatal = true; issues.Add("invalid-part-metadata"); continue; }
                if (total > limits.MaximumParts) { issues.Add("declared-part-budget-exceeded"); break; }
                if (expectedParts != 0 && expectedParts != total) { fatal = true; issues.Add("inconsistent-part-total"); continue; }
                expectedParts = total;
                if (parts.ContainsKey(number)) { fatal = true; issues.Add("duplicate-part-number"); continue; }
                var count = operations.GetArrayLength();
                if (count > limits.MaximumOperations - operationCount) { issues.Add("operation-budget-exceeded"); break; }
                if (operations.EnumerateArray().Any(op => op.ValueKind != JsonValueKind.Object))
                { fatal = true; issues.Add("invalid-operation-shape"); continue; }
                operationCount += count;
                parts.Add(number, operations.GetRawText());
            }
            catch (Exception e) when (e is JsonException or InvalidOperationException or FormatException)
            { fatal = true; issues.Add("malformed-part"); }
        }
        if (expectedParts == 0 || parts.Count != expectedParts) issues.Add("missing-parts");
        if (operationCount != declaredOperations) issues.Add("operation-count-mismatch");
        if (declaredOperations == 0 || operationCount == 0) issues.Add("no-operations");
        string? json = null;
        if (!fatal && parts.Count > 0 && issues.Count == 0)
        {
            try
            {
                using var buffer = new MemoryStream();
                using (var bounded = new BoundedOutputStream(buffer, limits.MaximumUtf8Bytes))
                using (var writer = new Utf8JsonWriter(bounded))
                {
                    writer.WriteStartObject(); writer.WritePropertyName("operations"); writer.WriteStartArray();
                    foreach (var part in parts.Values)
                    {
                        using var array = JsonDocument.Parse(part);
                        foreach (var operation in array.RootElement.EnumerateArray()) operation.WriteTo(writer);
                    }
                    writer.WriteEndArray(); writer.WriteEndObject(); writer.Flush();
                }
                json = Encoding.UTF8.GetString(buffer.GetBuffer(), 0, checked((int)buffer.Length));
            }
            catch (InventoryOutputBudgetException) { issues.Add("output-budget-exceeded"); }
        }
        return new(json, json is not null && issues.Count == 0, expectedParts, parts.Count,
            declaredOperations, operationCount, issues.Order(StringComparer.Ordinal).ToArray());
    }

    private sealed class InventoryOutputBudgetException : IOException { }
    private sealed class BoundedOutputStream(Stream inner, int maximum) : Stream
    {
        private long written;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => written;
        public override long Position { get => written; set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length > maximum - written) throw new InventoryOutputBudgetException();
            inner.Write(buffer); written += buffer.Length;
        }
        // The caller owns inner and reads it after the JSON writer closes.
        protected override void Dispose(bool disposing) { if (disposing) Flush(); base.Dispose(disposing); }
    }
}
