using System.Text.Json;
using SimpleOtp.Core.Storage;

namespace SimpleOtp.Core.Update;

/// <summary>
/// Persists update-related user choices — the version the user chose to ignore, and an optional
/// auto-update on/off override — to <c>update.json</c> in the app config directory (beside the vault,
/// NOT inside it: this is non-secret and must be readable without unlocking the TPM). Used to decide
/// whether to check at all, and whether a found update prompts again or only shows the top-bar
/// indicator.
/// </summary>
public sealed class UpdatePreferences
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    private readonly string _path;

    /// <param name="path">Override the storage path (tests); defaults to <c>update.json</c> beside the vault.</param>
    public UpdatePreferences(string? path = null)
        => _path = path ?? Path.Combine(Path.GetDirectoryName(VaultStore.DefaultPath)!, "update.json");

    /// <summary>The version the user dismissed, or null if none.</summary>
    public ReleaseVersion? GetIgnoredVersion()
    {
        string? s = Load().IgnoredVersion;
        return s is not null && ReleaseVersion.TryParse(s, out ReleaseVersion v) ? v : null;
    }

    /// <summary>Records <paramref name="version"/> as ignored, so it stops prompting (the indicator still shows).</summary>
    public void Ignore(ReleaseVersion version)
    {
        Model m = Load();
        m.IgnoredVersion = version.ToString();
        Save(m);
    }

    /// <summary>
    /// The user's explicit auto-update on/off choice, or null if they never changed it (so the
    /// installer's initial choice from <see cref="InstallInfo.AutoUpdate"/> applies).
    /// </summary>
    public bool? GetAutoUpdateOverride() => Load().AutoUpdate;

    /// <summary>Sets the user's auto-update on/off choice (overrides the installer's initial value).</summary>
    public void SetAutoUpdate(bool enabled)
    {
        Model m = Load();
        m.AutoUpdate = enabled;
        Save(m);
    }

    /// <summary>
    /// Whether an available update at <paramref name="latest"/> should pop up (vs. only showing the
    /// indicator). True unless the user already dismissed that version or a newer one — i.e. a strictly
    /// newer release than the one they ignored will prompt once more.
    /// </summary>
    public bool ShouldPrompt(ReleaseVersion latest)
    {
        ReleaseVersion? ignored = GetIgnoredVersion();
        return ignored is null || latest > ignored.Value;
    }

    private Model Load()
    {
        try
        {
            if (File.Exists(_path))
                return JsonSerializer.Deserialize<Model>(File.ReadAllText(_path)) ?? new Model();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // Treat an unreadable preferences file as empty.
        }
        return new Model();
    }

    private void Save(Model m)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(_path, JsonSerializer.Serialize(m, Options));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort: failing to persist the choice just means we may prompt again next launch.
        }
    }

    private sealed class Model
    {
        public string? IgnoredVersion { get; set; }
        public bool? AutoUpdate { get; set; }
    }
}
