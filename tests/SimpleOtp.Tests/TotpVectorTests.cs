using System.Text;
using SimpleOtp.Core.Model;
using SimpleOtp.Core.Totp;

namespace SimpleOtp.Tests;

/// <summary>The official RFC 6238 Appendix B test vectors (T0=0, X=30s, 8-digit codes).</summary>
public class TotpVectorTests
{
    // Seeds are ASCII strings repeated to the algorithm's key length, per the RFC.
    private static readonly byte[] Sha1Seed = Encoding.ASCII.GetBytes("12345678901234567890");
    private static readonly byte[] Sha256Seed = Encoding.ASCII.GetBytes("12345678901234567890123456789012");
    private static readonly byte[] Sha512Seed = Encoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234");

    [Theory]
    // unixTime, sha1, sha256, sha512  (all 8-digit)
    [InlineData(59L, "94287082", "46119246", "90693936")]
    [InlineData(1111111109L, "07081804", "68084774", "25091201")]
    [InlineData(1111111111L, "14050471", "67062674", "99943326")]
    [InlineData(1234567890L, "89005924", "91819424", "93441116")]
    [InlineData(2000000000L, "69279037", "90698825", "38618901")]
    [InlineData(20000000000L, "65353130", "77737706", "47863826")]
    public void MatchesRfc6238Vectors(long unixTime, string sha1, string sha256, string sha512)
    {
        DateTime utc = DateTime.UnixEpoch.AddSeconds(unixTime);
        Assert.Equal(sha1, TotpGenerator.Compute(Sha1Seed, OtpAlgorithm.Sha1, 8, 30, utc));
        Assert.Equal(sha256, TotpGenerator.Compute(Sha256Seed, OtpAlgorithm.Sha256, 8, 30, utc));
        Assert.Equal(sha512, TotpGenerator.Compute(Sha512Seed, OtpAlgorithm.Sha512, 8, 30, utc));
    }

    [Fact]
    public void RemainingFraction_IsFullAtWindowStart_AndSmallNearEnd()
    {
        DateTime start = DateTime.UnixEpoch; // counter boundary
        Assert.Equal(1.0, TotpGenerator.RemainingFraction(30, start), 3);

        DateTime nearEnd = DateTime.UnixEpoch.AddSeconds(29);
        Assert.True(TotpGenerator.RemainingFraction(30, nearEnd) is > 0 and < 0.05);

        Assert.Equal(30, TotpGenerator.RemainingSeconds(30, start));
        Assert.Equal(1, TotpGenerator.RemainingSeconds(30, nearEnd));
    }

    [Fact]
    public void DefaultSixDigitCode_HasSixDigits()
    {
        string code = TotpGenerator.Compute(Sha1Seed, OtpAlgorithm.Sha1, 6, 30, DateTime.UtcNow);
        Assert.Equal(6, code.Length);
        Assert.All(code, c => Assert.True(char.IsDigit(c)));
    }
}
