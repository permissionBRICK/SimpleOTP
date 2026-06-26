namespace SimpleOtp.Core.Model;

/// <summary>Hash algorithm used by the HMAC inside the TOTP/HOTP computation.</summary>
public enum OtpAlgorithm
{
    Sha1,
    Sha256,
    Sha512,
}
