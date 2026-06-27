using System.Text.Json;
using System.Text.Json.Serialization;

namespace SimpleOtp.Core.Update;

/// <summary>
/// Describes how the running app was installed, read from a <c>simpleotp.install.json</c> marker file
/// that each installer/package drops next to the executable. When the marker is missing (e.g. a raw
/// portable run, or a dev build) the channel falls back to a per-OS default so updates still work
/// best-effort.
/// </summary>
public sealed class InstallInfo
{
    public const string MarkerFileName = "simpleotp.install.json";

    [JsonConverter(typeof(JsonStringEnumConverter<InstallChannel>))]
    public InstallChannel Channel { get; init; }

    /// <summary>"user" or "machine" — informational; "machine" means an update needs elevation (Program Files / /opt).</summary>
    public string Scope { get; init; } = "user";

    /// <summary>Directory the app is installed in (where files are replaced for portable/tarball updates).</summary>
    public string InstallDir { get; init; } = "";

    /// <summary>
    /// Whether the app should automatically check GitHub for updates on startup. Set by the installer's
    /// "check for updates automatically" choice (default true). A user-set override in
    /// <see cref="UpdatePreferences"/> takes precedence over this initial value.
    /// </summary>
    public bool AutoUpdate { get; init; } = true;

    /// <summary>True when applying an update requires elevation (all-users / system install).</summary>
    [JsonIgnore]
    public bool RequiresElevation => string.Equals(Scope, "machine", StringComparison.OrdinalIgnoreCase);

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>Loads the marker beside the running executable (<see cref="AppContext.BaseDirectory"/>).</summary>
    public static InstallInfo Load() => Load(AppContext.BaseDirectory);

    /// <summary>Loads the marker from <paramref name="baseDir"/>, or a per-OS default if it is absent/unreadable.</summary>
    public static InstallInfo Load(string baseDir)
    {
        string markerPath = Path.Combine(baseDir, MarkerFileName);
        try
        {
            if (File.Exists(markerPath))
            {
                InstallInfo? info = JsonSerializer.Deserialize<InstallInfo>(File.ReadAllText(markerPath), Options);
                if (info is not null)
                    return new InstallInfo
                    {
                        Channel = info.Channel,
                        Scope = string.IsNullOrWhiteSpace(info.Scope) ? "user" : info.Scope,
                        InstallDir = string.IsNullOrWhiteSpace(info.InstallDir) ? baseDir : info.InstallDir,
                        AutoUpdate = info.AutoUpdate, // defaults to true when the marker omits the field
                    };
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // Unreadable marker — fall through to the default.
        }
        return new InstallInfo
        {
            Channel = OperatingSystem.IsWindows() ? InstallChannel.Portable : InstallChannel.Tarball,
            Scope = "user",
            InstallDir = baseDir,
        };
    }
}
