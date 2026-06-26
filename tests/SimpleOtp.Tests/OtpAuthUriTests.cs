using OtpNet;
using SimpleOtp.Core.Model;
using SimpleOtp.Core.Totp;

namespace SimpleOtp.Tests;

public class OtpAuthUriTests
{
    [Fact]
    public void Parses_FullUri()
    {
        var data = OtpAuthUri.Parse(
            "otpauth://totp/ACME%20Co:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60");

        Assert.Equal("ACME Co", data.Issuer);
        Assert.Equal("alice@example.com", data.Label);
        Assert.Equal(OtpAlgorithm.Sha256, data.Algorithm);
        Assert.Equal(8, data.Digits);
        Assert.Equal(60, data.Period);
        Assert.Equal(Base32Encoding.ToBytes("JBSWY3DPEHPK3PXP"), data.SecretBytes);
    }

    [Fact]
    public void Defaults_WhenParamsOmitted()
    {
        var data = OtpAuthUri.Parse("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP");
        Assert.Equal("", data.Issuer);
        Assert.Equal("Example", data.Label);
        Assert.Equal(OtpAlgorithm.Sha1, data.Algorithm);
        Assert.Equal(6, data.Digits);
        Assert.Equal(30, data.Period);
    }

    [Fact]
    public void IssuerQueryParam_TakesPrecedenceOverLabelPrefix()
    {
        var data = OtpAuthUri.Parse("otpauth://totp/WrongPrefix:bob?secret=JBSWY3DPEHPK3PXP&issuer=RightIssuer");
        Assert.Equal("RightIssuer", data.Issuer);
        Assert.Equal("bob", data.Label);
    }

    [Fact]
    public void Rejects_Hotp() =>
        Assert.Throws<FormatException>(() => OtpAuthUri.Parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=0"));

    [Fact]
    public void Rejects_MissingSecret() =>
        Assert.Throws<FormatException>(() => OtpAuthUri.Parse("otpauth://totp/x?issuer=y"));

    [Fact]
    public void Rejects_NonOtpauthScheme() =>
        Assert.Throws<FormatException>(() => OtpAuthUri.Parse("https://example.com/?secret=abc"));

    // Present-but-invalid parameters must fail rather than silently coerce to a default (which would
    // import a wrong-code account). Absent params still default — see Defaults_WhenParamsOmitted.
    [Theory]
    [InlineData("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5")]
    [InlineData("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=abc")]
    [InlineData("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4")]   // out of 6-8 range
    [InlineData("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=10")]  // out of 6-8 range
    [InlineData("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0")]
    [InlineData("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=xyz")]
    public void Rejects_PresentButInvalidParameters(string uri) =>
        Assert.Throws<FormatException>(() => OtpAuthUri.Parse(uri));

    [Theory]
    [InlineData("jbswy3dpehpk3pxp")]          // lowercase
    [InlineData("JBSW Y3DP EHPK 3PXP")]        // spaced (as some sites display)
    [InlineData("JBSW-Y3DP-EHPK-3PXP")]        // hyphenated
    public void DecodeBase32_Normalizes(string secret)
    {
        byte[] expected = Base32Encoding.ToBytes("JBSWY3DPEHPK3PXP");
        Assert.Equal(expected, OtpAuthUri.DecodeBase32(secret));
    }

    [Fact]
    public void Build_RoundTripsThrough_Parse()
    {
        string uri = OtpAuthUri.Build("GitHub", "octocat", "JBSWY3DPEHPK3PXP", OtpAlgorithm.Sha512, 8, 30);
        var data = OtpAuthUri.Parse(uri);
        Assert.Equal("GitHub", data.Issuer);
        Assert.Equal("octocat", data.Label);
        Assert.Equal(OtpAlgorithm.Sha512, data.Algorithm);
        Assert.Equal(8, data.Digits);
        Assert.Equal(Base32Encoding.ToBytes("JBSWY3DPEHPK3PXP"), data.SecretBytes);
    }

    [Fact]
    public void LooksLikeUri_DetectsScheme()
    {
        Assert.True(OtpAuthUri.LooksLikeUri("  otpauth://totp/x?secret=y"));
        Assert.False(OtpAuthUri.LooksLikeUri("JBSWY3DPEHPK3PXP"));
    }
}
