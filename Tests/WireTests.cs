using SecureTransfer.Protocol;
using Xunit;
namespace SecureTransfer.Tests;
public sealed class WireTests
{
    private sealed class Fragmented(byte[] bytes) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => base.ReadAsync(buffer[..Math.Min(3, buffer.Length)], ct);
    }
    [Fact]
    public async Task FragmentationAndCoalescingPreserveFrames()
    {
        using var output = new MemoryStream();
        using (var writer = new Wire(output))
        {
            await writer.SendJsonAsync(MessageType.UploadBegin, 1, new FileMeta("x.bin", 4));
            await writer.SendAsync(MessageType.Data, 1, new byte[] { 0, 1, 2, 255 });
            await writer.SendAsync(MessageType.Ping, 2);
        }
        using var input = new Fragmented(output.ToArray());
        using var reader = new Wire(input);
        Assert.Equal("x.bin", (await reader.ReadAsync()).Json<FileMeta>().Name);
        Assert.Equal(new byte[] { 0, 1, 2, 255 }, (await reader.ReadAsync()).Payload);
        Assert.Equal(MessageType.Ping, (await reader.ReadAsync()).Type);
    }
    [Fact]
    public async Task TruncatedHeaderAndPayloadFail()
    {
        using var output = new MemoryStream();
        using var writer = new Wire(output);
        await writer.SendJsonAsync(MessageType.Login, 1, new Login("a", "b"));
        foreach (int length in new[] { 5, (int)output.Length - 1 })
        {
            using var input = new MemoryStream(output.ToArray()[..length]);
            using var reader = new Wire(input);
            await Assert.ThrowsAsync<EndOfStreamException>(() => reader.ReadAsync());
        }
    }
    [Theory]
    [InlineData(0, 0)]
    [InlineData(4, 2)]
    [InlineData(5, 255)]
    [InlineData(6, 1)]
    [InlineData(11, 0)]
    public async Task InvalidHeaderFieldsFail(int offset, int value)
    {
        using var data = new MemoryStream();
        using (var w = new Wire(data))
            await w.SendAsync(MessageType.Ping, 1);
        var bytes = data.ToArray();
        bytes[offset] = (byte)value;
        using var input = new MemoryStream(bytes);
        using var reader = new Wire(input);
        await Assert.ThrowsAsync<ProtocolException>(() => reader.ReadAsync());
    }
}
