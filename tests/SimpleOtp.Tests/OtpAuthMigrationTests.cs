using System.Text;
using SimpleOtp.Core.Model;
using SimpleOtp.Core.Totp;
using SimpleOtp.Import;
using SkiaSharp;
using ZXing;
using ZXing.Common;
using FormatException = System.FormatException;

namespace SimpleOtp.Tests;

public class OtpAuthMigrationTests
{
    [Fact]
    public void Decodes_MigrationQrImage_EndToEnd()
    {
        byte[] seed = Encoding.ASCII.GetBytes("12345678901234567890");
        string uri = BuildMigrationUri(
            Param(seed, "octocat", "GitHub", algo: 1, digits: 1, type: 2),
            Param([1, 2, 3, 4, 5], "admin", "ACME", algo: 2, digits: 2, type: 2));

        // Render the migration URI to a QR image, then run the real import pipeline.
        var writer = new ZXing.SkiaSharp.BarcodeWriter
        {
            Format = BarcodeFormat.QR_CODE,
            Options = new EncodingOptions { Width = 600, Height = 600, Margin = 2 },
        };
        using SKBitmap bmp = writer.Write(uri);
        using SKImage img = SKImage.FromBitmap(bmp);
        using SKData png = img.Encode(SKEncodedImageFormat.Png, 100);

        string? decoded = QrDecoder.DecodeFromBytes(png.ToArray());
        Assert.Equal(uri, decoded);

        var accounts = OtpAuthMigration.Parse(decoded!);
        Assert.Equal(2, accounts.Count);
        Assert.Equal("GitHub", accounts[0].Issuer);
        Assert.Equal(seed, accounts[0].SecretBytes);
    }

    [Fact]
    public void Parses_MultipleAccounts_SkipsHotp_AndPreservesRawSecret()
    {
        // RFC 6238 SHA1 seed (raw bytes, as Google export stores them — NOT Base32).
        byte[] rfcSeed = Encoding.ASCII.GetBytes("12345678901234567890");
        byte[] otherSeed = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0];

        string uri = BuildMigrationUri(
            Param(rfcSeed, "octocat", "GitHub", algo: 1, digits: 1, type: 2),   // TOTP SHA1 6-digit
            Param(otherSeed, "admin", "ACME", algo: 2, digits: 2, type: 2),       // TOTP SHA256 8-digit
            Param(otherSeed, "legacy", "Old", algo: 1, digits: 1, type: 1));      // HOTP -> skipped

        var accounts = OtpAuthMigration.Parse(uri);

        Assert.Equal(2, accounts.Count); // HOTP filtered out

        Assert.Equal("GitHub", accounts[0].Issuer);
        Assert.Equal("octocat", accounts[0].Label);
        Assert.Equal(OtpAlgorithm.Sha1, accounts[0].Algorithm);
        Assert.Equal(6, accounts[0].Digits);
        Assert.Equal(30, accounts[0].Period);
        Assert.Equal(rfcSeed, accounts[0].SecretBytes); // raw secret preserved exactly

        // The preserved secret must produce the known RFC 6238 code (low 6 digits of 94287082).
        Assert.Equal("287082",
            TotpGenerator.Compute(accounts[0].SecretBytes, OtpAlgorithm.Sha1, 6, 30, DateTime.UnixEpoch.AddSeconds(59)));

        Assert.Equal("ACME", accounts[1].Issuer);
        Assert.Equal(OtpAlgorithm.Sha256, accounts[1].Algorithm);
        Assert.Equal(8, accounts[1].Digits);
    }

    [Fact]
    public void DerivesIssuer_FromColonName_WhenIssuerFieldEmpty()
    {
        string uri = BuildMigrationUri(Param([1, 2, 3, 4, 5], "Work:bob@x.com", issuer: "", algo: 1, digits: 1, type: 2));
        var account = Assert.Single(OtpAuthMigration.Parse(uri));
        Assert.Equal("Work", account.Issuer);
        Assert.Equal("bob@x.com", account.Label);
    }

    [Fact]
    public void StripsDuplicatedIssuerPrefix_FromName()
    {
        string uri = BuildMigrationUri(Param([1, 2, 3, 4, 5], "GitHub:octocat", issuer: "GitHub", algo: 1, digits: 1, type: 2));
        var account = Assert.Single(OtpAuthMigration.Parse(uri));
        Assert.Equal("GitHub", account.Issuer);
        Assert.Equal("octocat", account.Label);
    }

    [Fact]
    public void Returns_Empty_WhenOnlyHotp()
    {
        string uri = BuildMigrationUri(Param([1, 2, 3, 4, 5], "x", "y", algo: 1, digits: 1, type: 1));
        Assert.Empty(OtpAuthMigration.Parse(uri));
    }

    [Fact]
    public void Skips_WhenTypeOmitted()
    {
        // type field absent (protobuf-unspecified) must NOT be assumed to be TOTP.
        string uri = BuildMigrationUri(ParamPartial([1, 2, 3, 4, 5], "x", "y", algo: 1, digits: 1, type: null));
        Assert.Empty(OtpAuthMigration.Parse(uri));
    }

    [Theory]
    [InlineData(null)] // algorithm omitted (unspecified)
    [InlineData(0)]    // ALGORITHM_UNSPECIFIED
    [InlineData(4)]    // MD5 (unsupported)
    [InlineData(9)]    // unknown
    public void Skips_WhenAlgorithmUnsupported(int? algo)
    {
        string uri = BuildMigrationUri(ParamPartial([1, 2, 3, 4, 5], "x", "y", algo: algo, digits: 1, type: 2));
        Assert.Empty(OtpAuthMigration.Parse(uri));
    }

    [Fact]
    public void Parses_OtpParameters_WithUnknownTrailingFields()
    {
        // Real Google Authenticator exports carry newer, unmodeled fields per account — notably a
        // length-delimited field 8. Those must be skipped, not derail the parse. Regression guard for
        // the Skip(length-delimited) off-by-one that broke multi-account real exports.
        byte[] seed = Encoding.ASCII.GetBytes("12345678901234567890");

        var p = new List<byte>();
        WriteLengthDelimited(p, 1, seed);                       // secret
        WriteString(p, 2, "octocat");                           // name
        WriteString(p, 3, "GitHub");                            // issuer
        WriteVarintField(p, 4, 1);                              // algorithm SHA1
        WriteVarintField(p, 5, 1);                              // digits 6
        WriteVarintField(p, 6, 2);                              // type TOTP
        WriteLengthDelimited(p, 8, [10, 20, 30, 40, 50]);       // UNKNOWN length-delimited field (the trigger)
        WriteString(p, 9, "future-metadata");                   // another unknown length-delimited field

        var payload = new List<byte>();
        WriteLengthDelimited(payload, 1, p.ToArray());          // account 0
        WriteLengthDelimited(payload, 1, p.ToArray());          // account 1 (misalignment would cascade here)
        WriteVarintField(payload, 2, 1);                        // version
        WriteLengthDelimited(payload, 7, [1, 2, 3]);            // unknown top-level length-delimited field
        string uri = "otpauth-migration://offline?data=" + Uri.EscapeDataString(Convert.ToBase64String(payload.ToArray()));

        var accounts = OtpAuthMigration.Parse(uri);
        Assert.Equal(2, accounts.Count);
        Assert.Equal("GitHub", accounts[0].Issuer);
        Assert.Equal("octocat", accounts[0].Label);
        Assert.Equal(seed, accounts[0].SecretBytes);
        Assert.Equal(OtpAlgorithm.Sha1, accounts[0].Algorithm);
        Assert.Equal(seed, accounts[1].SecretBytes);
    }

    [Fact]
    public void LooksLikeUri_Detects() =>
        Assert.True(OtpAuthMigration.LooksLikeUri("otpauth-migration://offline?data=AAAA"));

    [Theory]
    [InlineData("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")] // single, not migration
    [InlineData("otpauth-migration://offline")]               // no data param
    [InlineData("otpauth-migration://offline?data=not!base64")]
    public void Throws_OnInvalidInput(string uri) =>
        Assert.Throws<FormatException>(() => OtpAuthMigration.Parse(uri));

    // --- export (BuildExport) ---

    [Fact]
    public void Export_RoundTrips_SingleBatch()
    {
        OtpAuthData[] accounts =
        [
            new("GitHub", "octocat", Encoding.ASCII.GetBytes("12345678901234567890"), OtpAlgorithm.Sha1, 6, 30),
            new("ACME", "admin", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], OtpAlgorithm.Sha256, 8, 30),
        ];

        var uris = OtpAuthMigration.BuildExport(accounts);
        Assert.Single(uris);

        var parsed = OtpAuthMigration.Parse(uris[0]);
        Assert.Equal(2, parsed.Count);
        Assert.Equal("GitHub", parsed[0].Issuer);
        Assert.Equal("octocat", parsed[0].Label);
        Assert.Equal(Encoding.ASCII.GetBytes("12345678901234567890"), parsed[0].SecretBytes);
        Assert.Equal(OtpAlgorithm.Sha1, parsed[0].Algorithm);
        Assert.Equal(6, parsed[0].Digits);
        Assert.Equal(OtpAlgorithm.Sha256, parsed[1].Algorithm);
        Assert.Equal(8, parsed[1].Digits);
    }

    [Fact]
    public void Export_SplitsIntoBatches_WhenTooLarge_AndReassembles()
    {
        OtpAuthData[] accounts = [.. Enumerable.Range(0, 12).Select(i =>
            new OtpAuthData($"Issuer{i}", $"user{i}@example.com", [(byte)i, 1, 2, 3, 4, 5, 6, 7, 8, 9], OtpAlgorithm.Sha1, 6, 30))];

        var uris = OtpAuthMigration.BuildExport(accounts, maxPayloadBytes: 150); // force multiple batches
        Assert.True(uris.Count > 1);

        var all = new List<OtpAuthData>();
        var indices = new List<int>();
        int? batchId = null;
        foreach (string uri in uris)
        {
            var batch = OtpAuthMigration.ParseBatch(uri);
            Assert.Equal(uris.Count, batch.BatchSize); // every part knows the total
            batchId ??= batch.BatchId;
            Assert.Equal(batchId, batch.BatchId);       // all parts share one batch id
            indices.Add(batch.BatchIndex);
            all.AddRange(batch.Accounts);
        }

        Assert.Equal(Enumerable.Range(0, uris.Count), indices.OrderBy(i => i)); // indices 0..n-1
        Assert.Equal(12, all.Count);
        Assert.Equal(
            accounts.Select(a => a.Label).OrderBy(x => x),
            all.Select(a => a.Label).OrderBy(x => x));
    }

    [Fact]
    public void Export_QrEncodeDecode_EndToEnd()
    {
        OtpAuthData[] accounts =
            [new("GitHub", "octocat", Encoding.ASCII.GetBytes("12345678901234567890"), OtpAlgorithm.Sha1, 6, 30)];
        string uri = OtpAuthMigration.BuildExport(accounts)[0];

        byte[] png = QrEncoder.EncodePng(uri, 600);
        string? decoded = QrDecoder.DecodeFromBytes(png);
        Assert.Equal(uri, decoded);

        var parsed = OtpAuthMigration.Parse(decoded!);
        Assert.Single(parsed);
        Assert.Equal(Encoding.ASCII.GetBytes("12345678901234567890"), parsed[0].SecretBytes);
    }

    [Fact]
    public void Export_Empty_ReturnsNoUris() => Assert.Empty(OtpAuthMigration.BuildExport([]));

    // --- minimal protobuf encoder (mirrors the MigrationPayload wire format) ---

    private static string BuildMigrationUri(params byte[][] otpParameters)
    {
        var payload = new List<byte>();
        foreach (byte[] p in otpParameters)
            WriteLengthDelimited(payload, field: 1, p); // MigrationPayload.otp_parameters
        WriteVarintField(payload, field: 2, 1);          // version = 1
        string data = Convert.ToBase64String(payload.ToArray());
        return "otpauth-migration://offline?data=" + Uri.EscapeDataString(data);
    }

    private static byte[] Param(byte[] secret, string name, string issuer, int algo, int digits, int type)
        => ParamPartial(secret, name, issuer, algo, digits, type);

    // Like Param, but a null enum field is OMITTED entirely (to simulate protobuf-unspecified).
    private static byte[] ParamPartial(byte[] secret, string name, string issuer, int? algo, int? digits, int? type)
    {
        var b = new List<byte>();
        WriteLengthDelimited(b, 1, secret);                 // secret
        WriteString(b, 2, name);                            // name
        if (!string.IsNullOrEmpty(issuer)) WriteString(b, 3, issuer); // issuer
        if (algo.HasValue) WriteVarintField(b, 4, algo.Value);    // algorithm
        if (digits.HasValue) WriteVarintField(b, 5, digits.Value); // digits
        if (type.HasValue) WriteVarintField(b, 6, type.Value);     // type
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

    private static void WriteTag(List<byte> buf, int field, int wire) => WriteVarint(buf, (ulong)(field << 3 | wire));
    private static void WriteVarintField(List<byte> buf, int field, int value) { WriteTag(buf, field, 0); WriteVarint(buf, (ulong)value); }
    private static void WriteLengthDelimited(List<byte> buf, int field, byte[] data)
    {
        WriteTag(buf, field, 2);
        WriteVarint(buf, (ulong)data.Length);
        buf.AddRange(data);
    }
    private static void WriteString(List<byte> buf, int field, string s) => WriteLengthDelimited(buf, field, Encoding.UTF8.GetBytes(s));
}
