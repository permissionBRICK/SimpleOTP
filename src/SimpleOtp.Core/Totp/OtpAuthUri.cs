using System.Text;
using OtpNet;
using SimpleOtp.Core.Model;

namespace SimpleOtp.Core.Totp;

/// <summary>A fully parsed otpauth descriptor, with the secret decoded to raw bytes.</summary>
public sealed record OtpAuthData(
    string Issuer,
    string Label,
    byte[] SecretBytes,
    OtpAlgorithm Algorithm,
    int Digits,
    int Period);

/// <summary>
/// Parser and builder for <c>otpauth://totp/...</c> URIs (the format encoded in authenticator QR
/// codes). Otp.NET only ships a URI <i>builder</i>, so the parsing here is hand-rolled per the
/// Key-Uri-Format spec. HOTP is intentionally not supported (this app is TOTP-only).
/// </summary>
public static class OtpAuthUri
{
    /// <summary>
    /// Parses an <c>otpauth://totp/...</c> URI. Throws <see cref="FormatException"/> for anything
    /// that isn't a valid TOTP URI with a decodable secret.
    /// </summary>
    public static OtpAuthData Parse(string uri)
    {
        if (string.IsNullOrWhiteSpace(uri))
            throw new FormatException("Empty otpauth URI.");

        Uri parsed;
        try { parsed = new Uri(uri.Trim()); }
        catch (UriFormatException ex) { throw new FormatException("Not a valid URI.", ex); }

        if (!parsed.Scheme.Equals("otpauth", StringComparison.OrdinalIgnoreCase))
            throw new FormatException($"Unsupported scheme '{parsed.Scheme}'. Expected 'otpauth'.");

        string type = parsed.Host;
        if (type.Equals("hotp", StringComparison.OrdinalIgnoreCase))
            throw new FormatException("HOTP (counter-based) tokens are not supported; only TOTP.");
        if (!type.Equals("totp", StringComparison.OrdinalIgnoreCase))
            throw new FormatException($"Unsupported otpauth type '{type}'. Expected 'totp'.");

        var query = ParseQuery(parsed.Query);

        if (!query.TryGetValue("secret", out string? secret) || string.IsNullOrWhiteSpace(secret))
            throw new FormatException("otpauth URI is missing the required 'secret' parameter.");

        byte[] secretBytes = DecodeBase32(secret);

        // Label = the path, "Issuer:Account" (issuer prefix optional). The 'issuer' query param,
        // when present, takes precedence over the label prefix.
        string label = Uri.UnescapeDataString(parsed.AbsolutePath.TrimStart('/'));
        string issuerFromLabel = "";
        string account = label;
        int colon = label.IndexOf(':');
        if (colon >= 0)
        {
            issuerFromLabel = label[..colon].Trim();
            account = label[(colon + 1)..].Trim();
        }

        string issuer = query.TryGetValue("issuer", out string? iss) && !string.IsNullOrWhiteSpace(iss)
            ? iss.Trim()
            : issuerFromLabel;

        OtpAlgorithm algorithm = ParseAlgorithm(query.GetValueOrDefault("algorithm"));
        int digits = ParseInt(query.GetValueOrDefault("digits"), fallback: 6, min: 6, max: 8, name: "digits");
        int period = ParseInt(query.GetValueOrDefault("period"), fallback: 30, min: 1, max: 3600, name: "period");

        return new OtpAuthData(issuer, account, secretBytes, algorithm, digits, period);
    }

    /// <summary>True if the string looks like an otpauth URI (cheap prefix check for routing input).</summary>
    public static bool LooksLikeUri(string text)
        => text is not null && text.TrimStart().StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Decodes a Base32 secret as found in otpauth URIs / manual entry. Tolerant of lowercase,
    /// spaces, and missing padding.
    /// </summary>
    public static byte[] DecodeBase32(string secret)
    {
        string normalized = new string(secret.Where(c => !char.IsWhiteSpace(c) && c != '-').ToArray())
            .ToUpperInvariant();
        if (normalized.Length == 0)
            throw new FormatException("Secret is empty.");
        try
        {
            byte[] bytes = Base32Encoding.ToBytes(normalized);
            if (bytes.Length == 0)
                throw new FormatException("Secret decoded to zero bytes.");
            return bytes;
        }
        catch (Exception ex) when (ex is not FormatException)
        {
            throw new FormatException("Secret is not valid Base32.", ex);
        }
    }

    /// <summary>Re-encodes raw secret bytes to an (unpadded, uppercase) Base32 string for display.</summary>
    public static string EncodeBase32(byte[] secretBytes)
        => Base32Encoding.ToString(secretBytes).TrimEnd('=').ToUpperInvariant();

    /// <summary>Builds a canonical <c>otpauth://totp/...</c> URI (used for export and tests).</summary>
    public static string Build(string issuer, string label, string base32Secret,
        OtpAlgorithm algorithm, int digits, int period)
    {
        string normalizedSecret = new string(base32Secret.Where(c => !char.IsWhiteSpace(c)).ToArray())
            .ToUpperInvariant();
        var sb = new StringBuilder("otpauth://totp/");
        string fullLabel = string.IsNullOrWhiteSpace(issuer) ? label : $"{issuer}:{label}";
        sb.Append(Uri.EscapeDataString(fullLabel));
        sb.Append("?secret=").Append(Uri.EscapeDataString(normalizedSecret));
        if (!string.IsNullOrWhiteSpace(issuer))
            sb.Append("&issuer=").Append(Uri.EscapeDataString(issuer));
        sb.Append("&algorithm=").Append(algorithm.ToString().ToUpperInvariant());
        sb.Append("&digits=").Append(digits);
        sb.Append("&period=").Append(period);
        return sb.ToString();
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query)) return result;
        foreach (string pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            if (eq < 0) { result[Uri.UnescapeDataString(pair)] = ""; continue; }
            string key = Uri.UnescapeDataString(pair[..eq]);
            string value = Uri.UnescapeDataString(pair[(eq + 1)..]);
            result[key] = value;
        }
        return result;
    }

    // Absent/blank parameters fall back to the spec defaults; a parameter that IS present but
    // unsupported/invalid throws, so a malformed link can't be imported as a wrong-code account.
    private static OtpAlgorithm ParseAlgorithm(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return OtpAlgorithm.Sha1; // default when omitted
        return value.Trim().ToUpperInvariant() switch
        {
            "SHA1" => OtpAlgorithm.Sha1,
            "SHA256" => OtpAlgorithm.Sha256,
            "SHA512" => OtpAlgorithm.Sha512,
            _ => throw new FormatException($"Unsupported algorithm '{value}'. Expected SHA1, SHA256, or SHA512."),
        };
    }

    private static int ParseInt(string? value, int fallback, int min, int max, string name)
    {
        if (string.IsNullOrWhiteSpace(value)) return fallback; // default when omitted
        if (!int.TryParse(value.Trim(), out int n))
            throw new FormatException($"Invalid {name} '{value}': not a number.");
        if (n < min || n > max)
            throw new FormatException($"{name} '{value}' is out of range ({min}-{max}).");
        return n;
    }
}
