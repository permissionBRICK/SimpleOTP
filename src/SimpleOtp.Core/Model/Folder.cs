namespace SimpleOtp.Core.Model;

/// <summary>
/// A named group the user can sort accounts into. Purely an organizational/UX construct: it has no
/// effect on how a secret is protected. Folders matter for performance, though — the UI only generates
/// codes for the folder that is currently open, so a vault with far more accounts than the TPM could
/// refresh at once stays responsive instead of stalling on a backlog of code generation.
/// </summary>
public sealed class Folder
{
    public string Id { get; init; } = Guid.NewGuid().ToString("n");

    /// <summary>User-chosen display name. May be empty (shown as "(unnamed folder)").</summary>
    public string Name { get; set; } = "";
}
