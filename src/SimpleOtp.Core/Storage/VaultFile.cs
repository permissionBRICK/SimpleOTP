using SimpleOtp.Core.Crypto;
using SimpleOtp.Core.Model;

namespace SimpleOtp.Core.Storage;

/// <summary>
/// On-disk representation of the vault. Serialized as JSON. Contains only the TPM-sealed DEK and
/// per-account AES-GCM ciphertext plus cleartext metadata — never a plaintext secret.
/// </summary>
public sealed class VaultFile
{
    /// <summary>Schema version, for forward migration.</summary>
    public int Version { get; set; } = 1;

    /// <summary>Sealer backend id that created this vault (e.g. "tpm2"). Used to detect mismatch.</summary>
    public string Backend { get; set; } = "";

    /// <summary>Whether unlocking requires a non-empty PIN.</summary>
    public bool PinProtected { get; set; }

    /// <summary>The TPM-sealed data-encryption key (sealed under the PIN, empty auth when no PIN).</summary>
    public SealedBlob Dek { get; set; } = new([], []);

    /// <summary>
    /// Optional second sealing of the same DEK under the network auto-unlock secret. Present only
    /// when auto-unlock is configured.
    /// </summary>
    public SealedBlob? DekAuto { get; set; }

    /// <summary>Network auto-unlock configuration (null/disabled when not used).</summary>
    public AutoUnlockConfig? AutoUnlock { get; set; }

    public List<Account> Accounts { get; set; } = [];

    public bool IsInitialized => Dek.Public.Length > 0 || Dek.Private.Length > 0;
}
