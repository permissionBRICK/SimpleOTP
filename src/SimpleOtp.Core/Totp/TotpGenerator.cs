using OtpNet;
using SimpleOtp.Core.Model;

namespace SimpleOtp.Core.Totp;

/// <summary>RFC 6238 TOTP computation, wrapping Otp.NET. Pure function of (secret, params, time).</summary>
public static class TotpGenerator
{
    /// <summary>Computes the current code for the given secret and parameters at <paramref name="utc"/>.</summary>
    public static string Compute(byte[] secret, OtpAlgorithm algorithm, int digits, int period, DateTime utc)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length == 0) throw new ArgumentException("Secret is empty.", nameof(secret));
        if (digits is < 6 or > 8) throw new ArgumentOutOfRangeException(nameof(digits), digits, "Digits must be 6-8.");
        if (period <= 0) throw new ArgumentOutOfRangeException(nameof(period), period, "Period must be positive.");

        var totp = new OtpNet.Totp(secret, step: period, mode: ToHashMode(algorithm), totpSize: digits);
        return totp.ComputeTotp(utc.ToUniversalTime());
    }

    /// <summary>Fraction (1.0 → 0.0) of the current period remaining at <paramref name="utc"/>.</summary>
    public static double RemainingFraction(int period, DateTime utc)
    {
        double seconds = (utc.ToUniversalTime() - DateTime.UnixEpoch).TotalSeconds;
        double inWindow = seconds % period;
        return (period - inWindow) / period;
    }

    /// <summary>Whole seconds remaining (rounded up) in the current period at <paramref name="utc"/>.</summary>
    public static int RemainingSeconds(int period, DateTime utc)
        => (int)Math.Ceiling(RemainingFraction(period, utc) * period);

    private static OtpHashMode ToHashMode(OtpAlgorithm algorithm) => algorithm switch
    {
        OtpAlgorithm.Sha256 => OtpHashMode.Sha256,
        OtpAlgorithm.Sha512 => OtpHashMode.Sha512,
        _ => OtpHashMode.Sha1,
    };
}
