using System.Security.Cryptography;
using System.Text;
using SimpleOtp.Core.Model;

namespace SimpleOtp.Core.Totp;

/// <summary>
/// Parses Google Authenticator's bulk export QR (<c>otpauth-migration://offline?data=...</c>). The
/// <c>data</c> parameter is Base64 of a protobuf <c>MigrationPayload</c> holding many accounts. To
/// avoid a protobuf dependency, the small, stable wire format is decoded by hand.
///
/// Only TOTP entries are returned (HOTP and unsupported algorithms are skipped). The migration
/// secret is raw key bytes (NOT Base32), so it maps straight onto <see cref="OtpAuthData.SecretBytes"/>.
/// </summary>
public static class OtpAuthMigration
{
    // MigrationPayload field 1 = repeated OtpParameters.
    // OtpParameters fields: 1=secret(bytes) 2=name 3=issuer 4=algorithm 5=digits 6=type 7=counter.
    private const int FieldOtpParameters = 1;
    private const int FieldSecret = 1, FieldName = 2, FieldIssuer = 3, FieldAlgorithm = 4, FieldDigits = 5, FieldType = 6;

    private const int AlgoSha1 = 1, AlgoSha256 = 2, AlgoSha512 = 3;
    private const int DigitsEight = 2; // 1 = six (default)
    private const int TypeTotp = 2;    // 1 = hotp

    public static bool LooksLikeUri(string? text)
        => text is not null && text.TrimStart().StartsWith("otpauth-migration://", StringComparison.OrdinalIgnoreCase);

    /// <summary>One scanned migration QR: its accounts and its position within a multi-QR export.</summary>
    public sealed record MigrationBatch(int BatchIndex, int BatchSize, int BatchId, IReadOnlyList<OtpAuthData> Accounts);

    /// <summary>
    /// Parses a migration URI into its TOTP accounts. Throws <see cref="FormatException"/> for a
    /// malformed URI / data; returns an empty list if the export contains no usable TOTP entries.
    /// </summary>
    public static IReadOnlyList<OtpAuthData> Parse(string uri) => ParseBatch(uri).Accounts;

    /// <summary>
    /// Parses a migration URI into one batch: its TOTP accounts plus the batch position
    /// (<c>batch_index</c>/<c>batch_size</c>/<c>batch_id</c>) used when an export is split across
    /// several QR codes.
    /// </summary>
    public static MigrationBatch ParseBatch(string uri)
    {
        if (string.IsNullOrWhiteSpace(uri))
            throw new FormatException("Empty migration URI.");

        Uri parsed;
        try { parsed = new Uri(uri.Trim()); }
        catch (UriFormatException ex) { throw new FormatException("Not a valid URI.", ex); }

        if (!parsed.Scheme.Equals("otpauth-migration", StringComparison.OrdinalIgnoreCase))
            throw new FormatException($"Unsupported scheme '{parsed.Scheme}'. Expected 'otpauth-migration'.");

        string? data = GetQueryValue(parsed.Query, "data");
        if (string.IsNullOrWhiteSpace(data))
            throw new FormatException("Migration URI is missing the 'data' parameter.");

        byte[] payload = DecodeBase64(data);
        return ParsePayload(payload);
    }

    private static MigrationBatch ParsePayload(byte[] payload)
    {
        var accounts = new List<OtpAuthData>();
        int batchSize = 1, batchIndex = 0, batchId = 0;
        var reader = new ProtoReader(payload);
        while (reader.HasMore)
        {
            (int field, int wire) = reader.ReadTag();
            if (field == FieldOtpParameters && wire == ProtoReader.LengthDelimited)
            {
                OtpAuthData? account = ParseOtpParameters(reader.ReadLengthDelimited());
                if (account is not null)
                    accounts.Add(account);
            }
            else if (field == 3 && wire == ProtoReader.Varint) batchSize = (int)reader.ReadVarint();   // batch_size
            else if (field == 4 && wire == ProtoReader.Varint) batchIndex = (int)reader.ReadVarint();  // batch_index
            else if (field == 5 && wire == ProtoReader.Varint) batchId = (int)reader.ReadVarint();     // batch_id
            else reader.Skip(wire);
        }
        return new MigrationBatch(batchIndex, batchSize < 1 ? 1 : batchSize, batchId, accounts);
    }

    private static OtpAuthData? ParseOtpParameters(ReadOnlySpan<byte> message)
    {
        byte[] secret = [];
        string name = "", issuer = "";
        int algorithm = 0, digits = 0, type = 0; // protobuf unspecified defaults (don't assume)

        var reader = new ProtoReader(message);
        while (reader.HasMore)
        {
            (int field, int wire) = reader.ReadTag();
            switch (field)
            {
                case FieldSecret when wire == ProtoReader.LengthDelimited: secret = reader.ReadLengthDelimited().ToArray(); break;
                case FieldName when wire == ProtoReader.LengthDelimited: name = Encoding.UTF8.GetString(reader.ReadLengthDelimited()); break;
                case FieldIssuer when wire == ProtoReader.LengthDelimited: issuer = Encoding.UTF8.GetString(reader.ReadLengthDelimited()); break;
                case FieldAlgorithm when wire == ProtoReader.Varint: algorithm = (int)reader.ReadVarint(); break;
                case FieldDigits when wire == ProtoReader.Varint: digits = (int)reader.ReadVarint(); break;
                case FieldType when wire == ProtoReader.Varint: type = (int)reader.ReadVarint(); break;
                default: reader.Skip(wire); break;
            }
        }

        if (type != TypeTotp) return null;   // only TOTP; skip HOTP / unspecified / omitted
        if (secret.Length == 0) return null; // unusable

        // Accept only explicitly supported algorithms; skip unspecified(0)/MD5(4)/unknown rather than
        // guessing (which would generate wrong codes).
        if (algorithm is not (AlgoSha1 or AlgoSha256 or AlgoSha512)) return null;
        OtpAlgorithm algo = algorithm switch
        {
            AlgoSha256 => OtpAlgorithm.Sha256,
            AlgoSha512 => OtpAlgorithm.Sha512,
            _ => OtpAlgorithm.Sha1, // AlgoSha1
        };
        int digitCount = digits == DigitsEight ? 8 : 6;

        SplitIssuer(ref issuer, ref name);
        return new OtpAuthData(issuer, name, secret, algo, digitCount, 30); // Google export period is always 30s
    }

    // The 'name' is often "Issuer:account"; align it with the separate issuer field.
    private static void SplitIssuer(ref string issuer, ref string name)
    {
        if (!string.IsNullOrEmpty(issuer) && name.StartsWith(issuer + ":", StringComparison.Ordinal))
        {
            name = name[(issuer.Length + 1)..].Trim();
        }
        else if (string.IsNullOrEmpty(issuer))
        {
            int colon = name.IndexOf(':');
            if (colon >= 0)
            {
                issuer = name[..colon].Trim();
                name = name[(colon + 1)..].Trim();
            }
        }
    }

    // --- Export (build otpauth-migration:// URIs from accounts) ---------------

    /// <summary>Default per-QR payload budget (bytes, before Base64), chosen to keep each QR scannable.</summary>
    public const int DefaultMaxPayloadBytes = 700;

    /// <summary>
    /// Builds one or more <c>otpauth-migration://</c> export URIs (Google Authenticator format) from
    /// the given accounts, splitting into multiple batches when a single payload would exceed
    /// <paramref name="maxPayloadBytes"/> (so each QR stays scannable). All batches share a random
    /// batch id and carry batch_index/batch_size, matching the format authenticator apps expect.
    ///
    /// Format limitations (inherent to the migration format): period is always 30s and digits are
    /// SIX/EIGHT — accounts with other settings are exported as the nearest supported value.
    /// </summary>
    public static IReadOnlyList<string> BuildExport(IReadOnlyList<OtpAuthData> accounts, int maxPayloadBytes = DefaultMaxPayloadBytes)
    {
        ArgumentNullException.ThrowIfNull(accounts);
        if (accounts.Count == 0) return [];

        // Pre-encode each account, then greedily pack into size-bounded batches.
        var encoded = new List<byte[]>(accounts.Count);
        foreach (OtpAuthData a in accounts)
            encoded.Add(EncodeOtpParameters(a));

        var batches = new List<List<byte[]>>();
        var current = new List<byte[]>();
        int currentSize = 0;
        foreach (byte[] param in encoded)
        {
            int entrySize = param.Length + 2; // + field tag/length overhead (approx)
            if (current.Count > 0 && currentSize + entrySize > maxPayloadBytes)
            {
                batches.Add(current);
                current = [];
                currentSize = 0;
            }
            current.Add(param);
            currentSize += entrySize;
        }
        if (current.Count > 0) batches.Add(current);

        int batchId = RandomNumberGenerator.GetInt32(1, int.MaxValue);
        var uris = new List<string>(batches.Count);
        for (int i = 0; i < batches.Count; i++)
        {
            var payload = new List<byte>();
            foreach (byte[] param in batches[i])
                WriteLengthDelimited(payload, FieldOtpParameters, param);
            WriteVarintField(payload, 2, 1);                 // MigrationPayload.version = 1
            WriteVarintField(payload, 3, batches.Count);     // batch_size
            WriteVarintField(payload, 4, i);                 // batch_index
            WriteVarintField(payload, 5, batchId);           // batch_id (shared across batches)

            string data = Convert.ToBase64String(payload.ToArray());
            uris.Add("otpauth-migration://offline?data=" + Uri.EscapeDataString(data));
        }
        return uris;
    }

    private static byte[] EncodeOtpParameters(OtpAuthData data)
    {
        var b = new List<byte>();
        WriteLengthDelimited(b, FieldSecret, data.SecretBytes);

        string name = string.IsNullOrEmpty(data.Issuer)
            ? data.Label
            : string.IsNullOrEmpty(data.Label) ? data.Issuer : $"{data.Issuer}:{data.Label}";
        WriteString(b, FieldName, name);
        if (!string.IsNullOrEmpty(data.Issuer))
            WriteString(b, FieldIssuer, data.Issuer);

        int algo = data.Algorithm switch
        {
            OtpAlgorithm.Sha256 => AlgoSha256,
            OtpAlgorithm.Sha512 => AlgoSha512,
            _ => AlgoSha1,
        };
        WriteVarintField(b, FieldAlgorithm, algo);
        WriteVarintField(b, FieldDigits, data.Digits == 8 ? DigitsEight : 1); // SIX(1)/EIGHT(2)
        WriteVarintField(b, FieldType, TypeTotp);
        return b.ToArray();
    }

    private static void WriteVarint(List<byte> buf, ulong value)
    {
        while (value >= 0x80)
        {
            buf.Add((byte)(value | 0x80));
            value >>= 7;
        }
        buf.Add((byte)value);
    }

    private static void WriteVarintField(List<byte> buf, int field, int value)
    {
        WriteVarint(buf, (ulong)(field << 3)); // wire type 0 (varint)
        WriteVarint(buf, (ulong)value);
    }

    private static void WriteLengthDelimited(List<byte> buf, int field, byte[] data)
    {
        WriteVarint(buf, (ulong)(field << 3 | 2)); // wire type 2 (length-delimited)
        WriteVarint(buf, (ulong)data.Length);
        buf.AddRange(data);
    }

    private static void WriteString(List<byte> buf, int field, string value)
        => WriteLengthDelimited(buf, field, Encoding.UTF8.GetBytes(value));

    private static string? GetQueryValue(string query, string key)
    {
        foreach (string pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            if (Uri.UnescapeDataString(pair[..eq]).Equals(key, StringComparison.OrdinalIgnoreCase))
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
        }
        return null;
    }

    private static byte[] DecodeBase64(string data)
    {
        string b64 = data.Trim().Replace('-', '+').Replace('_', '/'); // tolerate url-safe Base64
        switch (b64.Length % 4)
        {
            case 2: b64 += "=="; break;
            case 3: b64 += "="; break;
        }
        try { return Convert.FromBase64String(b64); }
        catch (FormatException ex) { throw new FormatException("Migration 'data' is not valid Base64.", ex); }
    }

    /// <summary>Minimal protobuf wire-format reader for the fields used by MigrationPayload.</summary>
    private ref struct ProtoReader(ReadOnlySpan<byte> data)
    {
        public const int Varint = 0;
        public const int LengthDelimited = 2;

        private readonly ReadOnlySpan<byte> _data = data;
        private int _pos = 0;

        public readonly bool HasMore => _pos < _data.Length;

        public ulong ReadVarint()
        {
            ulong value = 0;
            int shift = 0;
            while (true)
            {
                if (_pos >= _data.Length) throw new FormatException("Truncated varint.");
                byte b = _data[_pos++];
                value |= (ulong)(b & 0x7F) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
                if (shift > 63) throw new FormatException("Varint too long.");
            }
            return value;
        }

        public (int field, int wire) ReadTag()
        {
            ulong tag = ReadVarint();
            return ((int)(tag >> 3), (int)(tag & 0x7));
        }

        public ReadOnlySpan<byte> ReadLengthDelimited()
        {
            int len = (int)ReadVarint();
            if (len < 0 || _pos + len > _data.Length) throw new FormatException("Truncated length-delimited field.");
            ReadOnlySpan<byte> slice = _data.Slice(_pos, len);
            _pos += len;
            return slice;
        }

        public void Skip(int wire)
        {
            switch (wire)
            {
                case Varint: ReadVarint(); break;
                case 1: _pos += 8; break;            // 64-bit
                case LengthDelimited: _pos += (int)ReadVarint(); break;
                case 5: _pos += 4; break;            // 32-bit
                default: throw new FormatException($"Unknown protobuf wire type {wire}.");
            }
            if (_pos > _data.Length) throw new FormatException("Truncated protobuf field.");
        }
    }
}
