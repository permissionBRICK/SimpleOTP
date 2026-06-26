using SimpleOtp.Core.Crypto;
using SimpleOtp.Core.Model;

namespace SimpleOtp.Core.Storage;

/// <summary>
/// On-disk representation of the vault. Serialized as JSON. Contains only the TPM-sealed DEK and
/// per-account AES-GCM ciphertext plus cleartext metadata — never a plaintext secret.
/// </summary>
public sealed class VaultFile
{
    /// <summary>The schema version this build writes. v1 = Simple-only; v2 added Advanced Security.</summary>
    public const int CurrentSchemaVersion = 2;

    /// <summary>
    /// Schema version of this file, for forward migration. New files use
    /// <see cref="CurrentSchemaVersion"/>; an older file keeps its on-disk value until it is next
    /// saved (<see cref="VaultService"/> restamps it to the current version on every write).
    /// </summary>
    public int Version { get; set; } = CurrentSchemaVersion;

    /// <summary>Sealer backend id that created this vault (e.g. "tpm2"). Used to detect mismatch.</summary>
    public string Backend { get; set; } = "";

    /// <summary>Which security model protects the secrets (see <see cref="SecurityMode"/>).</summary>
    public SecurityMode Mode { get; set; } = SecurityMode.Simple;

    /// <summary>Whether unlocking requires a non-empty PIN. Simple mode only.</summary>
    public bool PinProtected { get; set; }

    /// <summary>
    /// Simple mode: the TPM-sealed data-encryption key (sealed under the PIN, empty auth when no PIN).
    /// Empty in Advanced mode, which has no DEK.
    /// </summary>
    public SealedBlob Dek { get; set; } = new([], []);

    /// <summary>
    /// Optional second sealing of the same DEK under the network auto-unlock secret. Present only
    /// when auto-unlock is configured (Simple mode only).
    /// </summary>
    public SealedBlob? DekAuto { get; set; }

    /// <summary>Network auto-unlock configuration (null/disabled when not used). Simple mode only.</summary>
    public AutoUnlockConfig? AutoUnlock { get; set; }

    /// <summary>
    /// Advanced mode + master password: the ECIES export private scalar, TPM-sealed under the master
    /// password. Recovering it (password + this device) lets the export copies be decrypted.
    /// </summary>
    public SealedBlob? ExportKeySealed { get; set; }

    /// <summary>
    /// Advanced mode + master password: the export public key (clear, DER) used to encrypt new export
    /// copies without needing the password. Present iff <see cref="ExportKeySealed"/> is.
    /// </summary>
    public byte[]? ExportPublicKey { get; set; }

    public List<Account> Accounts { get; set; } = [];

    /// <summary>Advanced mode: true if a master password was set, so exporting secrets is possible.</summary>
    public bool ExportProtected => ExportPublicKey is not null;

    /// <summary>
    /// True once a vault exists on disk. Simple vaults are initialized once their DEK is sealed;
    /// an Advanced vault is initialized by virtue of its mode (it has no DEK and may have no accounts).
    /// </summary>
    public bool IsInitialized => Mode == SecurityMode.Advanced || Dek.Public.Length > 0 || Dek.Private.Length > 0;
}
