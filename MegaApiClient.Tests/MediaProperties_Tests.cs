namespace CG.Web.MegaApiClient.Tests
{
  using System;
  using System.Collections.Generic;
  using CG.Web.MegaApiClient.Cryptography;
  using CG.Web.MegaApiClient.Serialization;
  using Newtonsoft.Json;
  using Xunit;

  public class MediaProperties_Tests
  {
    private const uint Delta = 0x9E3779B9;

    [Theory]
    [InlineData(1)]
    [InlineData(125)]
    [InlineData(7542)]
    [InlineData(131071)]
    public void GetDuration_ValidMediaAttribute_ReturnsDuration(int seconds)
    {
      var fullKey = CreateFullKey();
      var serializedAttributes = "1:0*thumbnail/0:" + EncodeMediaAttribute((uint)seconds, fullKey) + "/1:1*preview";

      var duration = MediaProperties.GetDuration(serializedAttributes, fullKey);

      Assert.Equal(TimeSpan.FromSeconds(seconds), duration);
    }

    [Fact]
    public void GetDuration_OfficialFormatVector_ReturnsDuration()
    {
      Assert.Equal(TimeSpan.FromSeconds(7542),
        MediaProperties.GetDuration("0:8*2Mx7ovtfjFo", CreateFullKey()));
    }

    [Fact]
    public void GetDuration_LongMediaAttribute_ReturnsMinutePrecisionDuration()
    {
      const uint Seconds = 200000;
      var fullKey = CreateFullKey();

      var duration = MediaProperties.GetDuration(EncodeMediaAttribute(Seconds, fullKey), fullKey);

      Assert.Equal(TimeSpan.FromSeconds(199980), duration);
    }

    [Fact]
    public void Get_ValidMediaAttribute_ReturnsDimensionsAndFrameRate()
    {
      var fullKey = CreateFullKey();

      var properties = MediaProperties.Get(EncodeMediaAttribute(3723, fullKey, 1920, 1080, 60), fullKey);

      Assert.Equal(1920, properties.Width);
      Assert.Equal(1080, properties.Height);
      Assert.Equal(60, properties.FramesPerSecond);
      Assert.Equal(TimeSpan.FromSeconds(3723), properties.Duration);
    }

    [Fact]
    public void Get_LargeDimensionsAndFrameRate_ReturnsCompressedValues()
    {
      var fullKey = CreateFullKey();

      var properties = MediaProperties.Get(EncodeMediaAttribute(60, fullKey, 20000, 20000, 240), fullKey);

      Assert.Equal(20000, properties.Width);
      Assert.Equal(20000, properties.Height);
      Assert.Equal(240, properties.FramesPerSecond);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("1:0*thumbnail")]
    [InlineData("8*invalid")]
    public void GetDuration_MissingOrMalformedMediaAttribute_ReturnsNull(string serializedAttributes)
    {
      Assert.Null(MediaProperties.GetDuration(serializedAttributes, CreateFullKey()));
    }

    [Fact]
    public void NodeDeserialization_MediaAttribute_ExposesDuration()
    {
      var masterKey = new byte[16];
      var fullKey = CreateFullKey();
      Crypto.GetPartsFromDecryptedKey(fullKey, out _, out _, out var fileKey);
      var encryptedKey = Crypto.EncryptKey(fullKey, masterKey).ToBase64();
      var encryptedAttributes = Crypto.EncryptAttributes(new Attributes("video.mp4"), fileKey).ToBase64();
      var mediaAttribute = EncodeMediaAttribute(3723, fullKey, 3840, 2160, 30);
      var json = "{\"h\":\"node\",\"p\":\"parent\",\"t\":0,\"a\":\"" + encryptedAttributes +
        "\",\"k\":\"owner:" + encryptedKey + "\",\"fa\":\"" + mediaAttribute + "\",\"s\":123,\"ts\":1}";
      var sharedKeys = new List<SharedKey>();

      INode node = JsonConvert.DeserializeObject<Node>(json, new NodeConverter(masterKey, ref sharedKeys));

      Assert.Equal(TimeSpan.FromSeconds(3723), node.Duration);
      Assert.Equal(3840, node.Width);
      Assert.Equal(2160, node.Height);
      Assert.Equal(30, node.FramesPerSecond);
    }

    private static byte[] CreateFullKey()
    {
      var key = new byte[32];
      for (var i = 0; i < key.Length; i++)
      {
        key[i] = (byte)(i * 7 + 3);
      }

      return key;
    }

    private static string EncodeMediaAttribute(uint seconds, byte[] fullKey, uint width = 0, uint height = 0,
      uint framesPerSecond = 0)
    {
      var encodedWidth = EncodeCompact(width, 32768, 3, 32767);
      var encodedHeight = EncodeCompact(height, 32768, 3, 32767);
      var encodedFramesPerSecond = EncodeCompact(framesPerSecond, 256, 3, 255);
      var encodedDuration = seconds << 1;
      if (encodedDuration >= 262144)
      {
        encodedDuration = ((encodedDuration - 262200) / 60) | 1;
      }

      if (encodedDuration >= 262144)
      {
        encodedDuration = 262143;
      }

      var bytes = new byte[8];
      bytes[0] = (byte)(encodedWidth & 255);
      bytes[1] = (byte)(((encodedWidth >> 8) & 127) + ((encodedHeight & 1) << 7));
      bytes[2] = (byte)((encodedHeight >> 1) & 255);
      bytes[3] = (byte)(((encodedFramesPerSecond & 3) << 6) + ((encodedHeight >> 9) & 63));
      bytes[4] = (byte)(((encodedDuration & 3) << 6) + (encodedFramesPerSecond >> 2));
      bytes[5] = (byte)((encodedDuration >> 2) & 255);
      bytes[6] = (byte)(encodedDuration >> 10);
      bytes[7] = 1;

      var values = new[] { ReadUInt32LittleEndian(bytes, 0), ReadUInt32LittleEndian(bytes, 4) };
      var key = new[]
      {
        ReadUInt32BigEndian(fullKey, 16),
        ReadUInt32BigEndian(fullKey, 20),
        ReadUInt32BigEndian(fullKey, 24),
        ReadUInt32BigEndian(fullKey, 28)
      };
      Encrypt(values, key);
      WriteUInt32LittleEndian(bytes, 0, values[0]);
      WriteUInt32LittleEndian(bytes, 4, values[1]);
      return "8*" + bytes.ToBase64();
    }

    private static uint EncodeCompact(uint value, uint threshold, int shift, uint maximum)
    {
      value <<= 1;
      if (value >= threshold)
      {
        value = ((value - threshold) >> shift) | 1;
      }

      return value >= threshold ? maximum : value;
    }

    private static void Encrypt(uint[] values, uint[] key)
    {
      var last = values.Length - 1;
      var z = values[last];
      var rounds = 6u + 52u / (uint)values.Length;
      var sum = 0u;
      while (rounds-- > 0)
      {
        sum = unchecked(sum + Delta);
        var e = (sum >> 2) & 3;
        for (var p = 0; p < last; p++)
        {
          var y = values[p + 1];
          z = values[p] = unchecked(values[p] + Mix(sum, y, z, (uint)p, e, key));
        }

        var finalY = values[0];
        z = values[last] = unchecked(values[last] + Mix(sum, finalY, z, (uint)last, e, key));
      }
    }

    private static uint Mix(uint sum, uint y, uint z, uint position, uint e, uint[] key)
    {
      return unchecked((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^
        ((sum ^ y) + (key[(position & 3) ^ e] ^ z)));
    }

    private static uint ReadUInt32LittleEndian(byte[] bytes, int offset)
    {
      return (uint)(bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24);
    }

    private static uint ReadUInt32BigEndian(byte[] bytes, int offset)
    {
      return (uint)(bytes[offset] << 24 | bytes[offset + 1] << 16 | bytes[offset + 2] << 8 | bytes[offset + 3]);
    }

    private static void WriteUInt32LittleEndian(byte[] bytes, int offset, uint value)
    {
      bytes[offset] = (byte)value;
      bytes[offset + 1] = (byte)(value >> 8);
      bytes[offset + 2] = (byte)(value >> 16);
      bytes[offset + 3] = (byte)(value >> 24);
    }
  }
}
