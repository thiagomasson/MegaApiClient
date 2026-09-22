// The media attribute packing and XXTEA algorithm are ported from MEGA's C++ SDK:
// https://github.com/meganz/sdk/blob/master/src/mediafileattribute.cpp
// Copyright (c) 2013, Mega Limited. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted
// provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions
//    and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of
//    conditions and the following disclaimer in the documentation and/or other materials provided
//    with the distribution.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
// IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
// OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

namespace CG.Web.MegaApiClient.Cryptography
{
  using System;
  using System.Text.RegularExpressions;

  internal static class MediaProperties
  {
    private const uint Delta = 0x9E3779B9;
    private static readonly Regex s_mediaAttributeRegex = new Regex(@"(?:^|/)(?:\d+:)?8\*(?<value>[a-zA-Z0-9-_]{11})(?:/|$)");

    public static TimeSpan? GetDuration(string serializedFileAttributes, byte[] fullKey)
    {
      if (string.IsNullOrEmpty(serializedFileAttributes) || fullKey == null || fullKey.Length != 32)
      {
        return null;
      }

      var match = s_mediaAttributeRegex.Match(serializedFileAttributes);
      if (!match.Success)
      {
        return null;
      }

      try
      {
        var bytes = match.Groups["value"].Value.FromBase64();
        if (bytes.Length != 8)
        {
          return null;
        }

        var values = new[] { ReadUInt32LittleEndian(bytes, 0), ReadUInt32LittleEndian(bytes, 4) };
        var key = new[]
        {
          ReadUInt32BigEndian(fullKey, 16),
          ReadUInt32BigEndian(fullKey, 20),
          ReadUInt32BigEndian(fullKey, 24),
          ReadUInt32BigEndian(fullKey, 28)
        };

        Decrypt(values, key);
        WriteUInt32LittleEndian(bytes, 0, values[0]);
        WriteUInt32LittleEndian(bytes, 4, values[1]);

        // 254 and 255 mean unknown or unidentified media formats.
        if (bytes[7] >= 254)
        {
          return null;
        }

        var seconds = (uint)((bytes[4] >> 7) + (bytes[5] << 1) + (bytes[6] << 9));
        if ((bytes[4] & 64) != 0)
        {
          seconds = seconds * 60 + 131100;
        }

        return seconds == 0 ? (TimeSpan?)null : TimeSpan.FromSeconds(seconds);
      }
      catch (FormatException)
      {
        return null;
      }
    }

    private static void Decrypt(uint[] values, uint[] key)
    {
      var last = values.Length - 1;
      var y = values[0];
      var rounds = 6u + 52u / (uint)values.Length;
      var sum = unchecked(rounds * Delta);

      while (sum != 0)
      {
        var e = (sum >> 2) & 3;
        for (var p = last; p > 0; p--)
        {
          var z = values[p - 1];
          y = values[p] = unchecked(values[p] - Mix(sum, y, z, (uint)p, e, key));
        }

        var finalZ = values[last];
        y = values[0] = unchecked(values[0] - Mix(sum, y, finalZ, 0, e, key));
        sum = unchecked(sum - Delta);
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
