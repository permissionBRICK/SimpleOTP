namespace SimpleOtp.Core.Model;

/// <summary>
/// One TOTP account. All metadata is stored in cleartext so the list can render without unlocking;
/// only <see cref="Secret"/> (the shared seed) is encrypted.
/// </summary>
public sealed class Account
{
    public string Id { get; init; } = Guid.NewGuid().ToString("n");

    /// <summary>Service / provider name, e.g. "GitHub". May be empty.</summary>
    public string Issuer { get; set; } = "";

    /// <summary>Account identifier within the issuer, e.g. "alice@example.com".</summary>
    public string Label { get; set; } = "";

    public OtpAlgorithm Algorithm { get; set; } = OtpAlgorithm.Sha1;

    /// <summary>Number of digits in the generated code (commonly 6, sometimes 8).</summary>
    public int Digits { get; set; } = 6;

    /// <summary>Time step in seconds (commonly 30).</summary>
    public int Period { get; set; } = 30;

    /// <summary>The AES-GCM encrypted shared secret.</summary>
    public EncryptedSecret Secret { get; set; } = new([], [], []);

    /// <summary>A friendly one-line title for display.</summary>
    public string DisplayName =>
        string.IsNullOrWhiteSpace(Issuer) ? (string.IsNullOrWhiteSpace(Label) ? "(unnamed)" : Label)
        : string.IsNullOrWhiteSpace(Label) ? Issuer
        : $"{Issuer} ({Label})";
}
