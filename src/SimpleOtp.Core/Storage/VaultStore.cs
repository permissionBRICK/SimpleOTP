using System.Text.Json;
using System.Text.Json.Serialization;

namespace SimpleOtp.Core.Storage;

/// <summary>Loads and saves the <see cref="VaultFile"/> JSON to disk with restrictive permissions.</summary>
public static class VaultStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>
    /// Default vault location: <c>%AppData%\SimpleOtp\vault.json</c> on Windows,
    /// <c>~/.config/SimpleOtp/vault.json</c> on Linux/macOS.
    /// </summary>
    public static string DefaultPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.Create),
        "SimpleOtp", "vault.json");

    public static bool Exists(string path) => File.Exists(path);

    public static VaultFile? Load(string path)
    {
        if (!File.Exists(path)) return null;
        string json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<VaultFile>(json, Options)
               ?? throw new InvalidDataException($"Vault file '{path}' could not be parsed.");
    }

    public static void Save(string path, VaultFile file)
    {
        string dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        if (!OperatingSystem.IsWindows())
            TrySetUnixMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        string json = JsonSerializer.Serialize(file, Options);
        string tmp = path + ".tmp";
        File.WriteAllText(tmp, json);
        if (!OperatingSystem.IsWindows())
            TrySetUnixMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.Move(tmp, path, overwrite: true);
    }

    private static void TrySetUnixMode(string path, UnixFileMode mode)
    {
        if (OperatingSystem.IsWindows()) return;
        try { File.SetUnixFileMode(path, mode); }
        catch (IOException) { /* best effort */ }
        catch (UnauthorizedAccessException) { /* best effort */ }
    }
}
