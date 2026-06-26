using SkiaSharp;
using ZXing;
using ZXing.Common;
using ZXing.SkiaSharp;

namespace SimpleOtp.Import;

/// <summary>
/// Decodes a QR code from an image using ZXing.Net with the SkiaSharp binding (fully managed and
/// cross-platform / headless). Returns the raw decoded text — for authenticator QR codes that is an
/// <c>otpauth://</c> URI, which the caller parses with <c>OtpAuthUri.Parse</c>.
/// </summary>
public static class QrDecoder
{
    private static BarcodeReader CreateReader() => new()
    {
        AutoRotate = true,
        Options = new DecodingOptions
        {
            PossibleFormats = [BarcodeFormat.QR_CODE],
            TryHarder = true,
            TryInverted = true,
        },
    };

    /// <summary>Decodes the first QR code found in the image file, or null if none is found.</summary>
    public static string? DecodeFromFile(string path)
    {
        using var stream = File.OpenRead(path);
        return DecodeFromStream(stream);
    }

    /// <summary>Decodes the first QR code found in the image bytes, or null if none is found / not an image.</summary>
    public static string? DecodeFromBytes(byte[] imageBytes)
    {
        using var bmp = TryDecodeBitmap(() => SKBitmap.Decode(imageBytes));
        return Decode(bmp);
    }

    /// <summary>Decodes the first QR code found in the image stream (PNG/JPEG/etc), or null.</summary>
    public static string? DecodeFromStream(Stream stream)
    {
        using var bmp = TryDecodeBitmap(() => SKBitmap.Decode(stream));
        return Decode(bmp);
    }

    // SKBitmap.Decode throws (not returns null) when the input isn't a recognized image; treat that
    // as "no QR" so callers get a clean null instead of an exception.
    private static SKBitmap? TryDecodeBitmap(Func<SKBitmap?> decode)
    {
        try { return decode(); }
        catch (Exception) { return null; }
    }

    private static string? Decode(SKBitmap? bitmap)
    {
        if (bitmap is null) return null; // unrecognized / corrupt image
        Result? result = CreateReader().Decode(bitmap);
        return result?.Text;
    }
}
