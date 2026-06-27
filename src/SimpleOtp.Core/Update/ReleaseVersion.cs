using System.Globalization;

namespace SimpleOtp.Core.Update;

/// <summary>
/// A minimal three-part version (major.minor.patch) used for update comparisons. Tolerant of a
/// leading 'v' and of pre-release/build suffixes (e.g. "v1.2.3-beta+abc") — only the numeric
/// major/minor/patch are compared and any missing component is treated as 0. This avoids
/// <see cref="System.Version"/>'s surprising treatment of "1.2" (Build = -1) when comparing against
/// "1.2.0".
/// </summary>
public readonly struct ReleaseVersion : IComparable<ReleaseVersion>, IEquatable<ReleaseVersion>
{
    public int Major { get; }
    public int Minor { get; }
    public int Patch { get; }

    public ReleaseVersion(int major, int minor, int patch)
    {
        Major = major;
        Minor = minor;
        Patch = patch;
    }

    /// <summary>True for the 0.0.0 sentinel used by unstamped local/dev builds.</summary>
    public bool IsZero => Major == 0 && Minor == 0 && Patch == 0;

    /// <summary>Parses "1.2.3", "v1.2.3", "1.2", "v1.2.3-beta+meta". Returns false if there is no leading number.</summary>
    public static bool TryParse(string? text, out ReleaseVersion version)
    {
        version = default;
        if (string.IsNullOrWhiteSpace(text)) return false;

        string s = text.Trim();
        if (s.Length > 0 && (s[0] is 'v' or 'V')) s = s[1..];

        int cut = s.IndexOfAny(['-', '+']); // drop pre-release / build metadata
        if (cut >= 0) s = s[..cut];
        if (s.Length == 0) return false;

        string[] parts = s.Split('.');
        int[] nums = [0, 0, 0];
        for (int i = 0; i < parts.Length && i < 3; i++)
        {
            if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out int value))
                return false;
            nums[i] = value;
        }
        version = new ReleaseVersion(nums[0], nums[1], nums[2]);
        return true;
    }

    public static ReleaseVersion Parse(string text)
        => TryParse(text, out ReleaseVersion v) ? v : throw new FormatException($"Invalid version string: '{text}'.");

    public int CompareTo(ReleaseVersion other)
    {
        int c = Major.CompareTo(other.Major);
        if (c != 0) return c;
        c = Minor.CompareTo(other.Minor);
        if (c != 0) return c;
        return Patch.CompareTo(other.Patch);
    }

    public bool Equals(ReleaseVersion other) => Major == other.Major && Minor == other.Minor && Patch == other.Patch;
    public override bool Equals(object? obj) => obj is ReleaseVersion v && Equals(v);
    public override int GetHashCode() => HashCode.Combine(Major, Minor, Patch);
    public override string ToString() => $"{Major}.{Minor}.{Patch}";

    public static bool operator >(ReleaseVersion a, ReleaseVersion b) => a.CompareTo(b) > 0;
    public static bool operator <(ReleaseVersion a, ReleaseVersion b) => a.CompareTo(b) < 0;
    public static bool operator >=(ReleaseVersion a, ReleaseVersion b) => a.CompareTo(b) >= 0;
    public static bool operator <=(ReleaseVersion a, ReleaseVersion b) => a.CompareTo(b) <= 0;
    public static bool operator ==(ReleaseVersion a, ReleaseVersion b) => a.Equals(b);
    public static bool operator !=(ReleaseVersion a, ReleaseVersion b) => !a.Equals(b);
}
