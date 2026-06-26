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

    /// <summary>
    /// The TOTP time counter at <paramref name="utc"/> as the 8-byte big-endian HMAC message (RFC 6238).
    /// Used by Advanced mode, where the HMAC itself is computed inside the TPM.
    /// </summary>
    public static byte[] CounterBytes(int period, DateTime utc)
    {
        if (period <= 0) throw new ArgumentOutOfRangeException(nameof(period), period, "Period must be positive.");
        long counter = (long)((utc.ToUniversalTime() - DateTime.UnixEpoch).TotalSeconds / period);
        byte[] bytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return bytes;
    }

    /// <summary>
    /// RFC 4226 dynamic truncation of a finished HMAC into a zero-padded decimal code. Lets Advanced
    /// mode reuse the standard truncation over a MAC produced by the TPM.
    /// </summary>
    public static string Truncate(ReadOnlySpan<byte> hmac, int digits)
    {
        if (digits is < 6 or > 8) throw new ArgumentOutOfRangeException(nameof(digits), digits, "Digits must be 6-8.");
        if (hmac.Length < 20) throw new ArgumentException("HMAC is too short for truncation.", nameof(hmac));
        int offset = hmac[^1] & 0x0F;
        int binary = ((hmac[offset] & 0x7F) << 24)
                   | ((hmac[offset + 1] & 0xFF) << 16)
                   | ((hmac[offset + 2] & 0xFF) << 8)
                   | (hmac[offset + 3] & 0xFF);
        int code = binary % (int)Math.Pow(10, digits);
        return code.ToString().PadLeft(digits, '0');
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
