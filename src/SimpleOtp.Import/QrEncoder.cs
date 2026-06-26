using SkiaSharp;
using ZXing;
using ZXing.QrCode;
using ZXing.QrCode.Internal;

namespace SimpleOtp.Import;

/// <summary>Renders text (e.g. an otpauth-migration:// export URI) to a QR-code PNG.</summary>
public static class QrEncoder
{
    /// <summary>Encodes <paramref name="text"/> as a QR code and returns PNG bytes.</summary>
    public static byte[] EncodePng(string text, int pixelSize = 600)
    {
        var writer = new ZXing.SkiaSharp.BarcodeWriter
        {
            Format = BarcodeFormat.QR_CODE,
            Options = new QrCodeEncodingOptions
            {
                Width = pixelSize,
                Height = pixelSize,
                Margin = 2,
                ErrorCorrection = ErrorCorrectionLevel.M,
                CharacterSet = "UTF-8",
            },
        };
        using SKBitmap bitmap = writer.Write(text);
        using SKImage image = SKImage.FromBitmap(bitmap);
        using SKData data = image.Encode(SKEncodedImageFormat.Png, 100);
        return data.ToArray();
    }
}
