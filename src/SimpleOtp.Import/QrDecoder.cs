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

    // ZXing sometimes fails to locate a dense, JPEG-compressed QR at the image's native resolution
    // (e.g. a full-screen authenticator-export screenshot) but succeeds once it is resampled. So if the
    // native attempt fails, retry at a few scales and return the first that decodes. Native first keeps
    // the common case fast; the downscales reliably recover the dense exports, the upscales help small
    // or slightly blurry codes.
    private static readonly float[] RetryScales = [1.0f, 0.75f, 0.5f, 1.5f, 2.0f, 0.4f];

    private static string? Decode(SKBitmap? bitmap)
    {
        if (bitmap is null) return null; // unrecognized / corrupt image
        BarcodeReader reader = CreateReader();
        foreach (float scale in RetryScales)
        {
            SKBitmap? scaled = scale == 1.0f ? bitmap : Resize(bitmap, scale);
            if (scaled is null) continue;
            try
            {
                Result? result = reader.Decode(scaled);
                if (result?.Text is { } text) return text;
            }
            finally
            {
                if (!ReferenceEquals(scaled, bitmap)) scaled.Dispose();
            }
        }
        return null;
    }

    private static SKBitmap? Resize(SKBitmap src, float factor)
    {
        int w = (int)(src.Width * factor), h = (int)(src.Height * factor);
        if (w < 1 || h < 1) return null;
        return src.Resize(new SKImageInfo(w, h), SKFilterQuality.High);
    }
}
