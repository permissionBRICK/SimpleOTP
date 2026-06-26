using SimpleOtp.Import;
using SkiaSharp;
using ZXing;
using ZXing.Common;

namespace SimpleOtp.Tests;

public class QrDecoderTests
{
    [Fact]
    public void Decodes_GeneratedQrCode_RoundTrip()
    {
        const string uri = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30";

        var writer = new ZXing.SkiaSharp.BarcodeWriter
        {
            Format = BarcodeFormat.QR_CODE,
            Options = new EncodingOptions { Width = 320, Height = 320, Margin = 2 },
        };
        using SKBitmap bitmap = writer.Write(uri);
        byte[] png = EncodePng(bitmap);

        string? decoded = QrDecoder.DecodeFromBytes(png);
        Assert.Equal(uri, decoded);
    }

    [Fact]
    public void ReturnsNull_WhenNoQrPresent()
    {
        using var bitmap = new SKBitmap(64, 64);
        using (var canvas = new SKCanvas(bitmap))
            canvas.Clear(SKColors.White);
        Assert.Null(QrDecoder.DecodeFromBytes(EncodePng(bitmap)));
    }

    [Fact]
    public void ReturnsNull_ForUnrecognizedBytes()
        => Assert.Null(QrDecoder.DecodeFromBytes([1, 2, 3, 4, 5]));

    private static byte[] EncodePng(SKBitmap bitmap)
    {
        using var image = SKImage.FromBitmap(bitmap);
        using var data = image.Encode(SKEncodedImageFormat.Png, 100);
        return data.ToArray();
    }
}
