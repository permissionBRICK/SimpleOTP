using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SimpleOtp.Core.AutoUnlock;
using SimpleOtp.Core.Crypto;
using SimpleOtp.Core.Model;
using SimpleOtp.Core.Storage;
using SimpleOtp.Core.Totp;

namespace SimpleOtp.Core;

/// <summary>
/// Top-level orchestration used by the UI: ties together the sealer (TPM), the in-memory
/// <see cref="Vault"/>, the persisted <see cref="VaultFile"/>, and TOTP generation. UI-agnostic.
/// </summary>
public sealed class VaultService : IDisposable
{
    private readonly ISecretSealer _sealer;
    private readonly string _path;
    private VaultFile _file;
    private Vault? _vault;

    public VaultService(ISecretSealer sealer, string? path = null)
    {
        _sealer = sealer;
        _path = path ?? VaultStore.DefaultPath;
        _file = VaultStore.Load(_path) ?? new VaultFile { Backend = sealer.BackendId };
    }

    /// <summary>Path of the vault file on disk.</summary>
    public string StorePath => _path;

    /// <summary>True once a vault (sealed DEK) exists on disk.</summary>
    public bool IsInitialized => _file.IsInitialized;

    /// <summary>True if unlocking requires a PIN.</summary>
    public bool PinProtected => _file.PinProtected;

    public bool IsUnlocked => _vault?.IsUnlocked == true;

    public IReadOnlyList<Account> Accounts => _file.Accounts;

    /// <summary>
    /// Creates a brand-new vault (first run). Generates and seals the DEK behind <paramref name="pin"/>
    /// (empty = no PIN). Leaves the vault unlocked.
    /// </summary>
    public void CreateNew(ReadOnlySpan<byte> pin)
    {
        _vault?.Dispose();
        _vault = Vault.Create(_sealer, pin);
        _file = new VaultFile
        {
            Backend = _sealer.BackendId,
            PinProtected = _vault.PinProtected,
            Dek = _vault.SealedDek,
            Accounts = [],
        };
        Save();
    }

    /// <summary>
    /// Unlocks an existing vault with <paramref name="pin"/> (empty when no PIN). Opens the vault
    /// against the sealer on first call.
    /// </summary>
    /// <exception cref="WrongDeviceException">Vault was created by a different backend/TPM.</exception>
    /// <exception cref="WrongPinException">PIN was wrong.</exception>
    public void Unlock(ReadOnlySpan<byte> pin)
    {
        EnsureOpened();
        _vault!.Unlock(pin);
    }

    private void EnsureOpened()
    {
        if (_vault is not null) return;
        if (!IsInitialized)
            throw new InvalidOperationException("No vault exists yet; call CreateNew first.");
        if (!string.Equals(_file.Backend, _sealer.BackendId, StringComparison.Ordinal))
            throw new WrongDeviceException(
                $"This vault was created with backend '{_file.Backend}', but the current device uses '{_sealer.BackendId}'. " +
                "It cannot be unlocked here.");
        _vault = Vault.Open(_sealer, _file.Dek, _file.PinProtected);
    }

    /// <summary>Convenience overload: unlock with a string PIN (UTF-8), or null/empty for no PIN.</summary>
    public void Unlock(string? pin) => Unlock(PinBytes(pin));

    public void Lock() => _vault?.Lock();

    /// <summary>Adds an account from parsed otpauth data. Zeroes the supplied secret bytes after use.</summary>
    public Account AddAccount(OtpAuthData data)
    {
        EnsureUnlocked();
        var account = new Account
        {
            Issuer = data.Issuer,
            Label = data.Label,
            Algorithm = data.Algorithm,
            Digits = data.Digits,
            Period = data.Period,
            Secret = _vault!.Encrypt(data.SecretBytes),
        };
        CryptographicOperations.ZeroMemory(data.SecretBytes);
        _file.Accounts.Add(account);
        Save();
        return account;
    }

    public void RemoveAccount(string id)
    {
        _file.Accounts.RemoveAll(a => a.Id == id);
        Save();
    }

    /// <summary>
    /// Generates the current TOTP code for an account. Decrypts the secret transiently and zeroes it
    /// immediately afterward.
    /// </summary>
    public string GenerateCode(Account account, DateTime? utc = null)
    {
        EnsureUnlocked();
        byte[] secret = _vault!.Decrypt(account.Secret);
        try
        {
            return TotpGenerator.Compute(secret, account.Algorithm, account.Digits, account.Period,
                utc ?? DateTime.UtcNow);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>Sets, changes, or removes the PIN (empty/null removes it). Re-seals the existing DEK.</summary>
    public void ChangePin(string? newPin)
    {
        EnsureUnlocked();
        _vault!.ChangePin(PinBytes(newPin));
        _file.PinProtected = _vault.PinProtected;
        _file.Dek = _vault.SealedDek;
        Save();
    }

    // --- Network auto-unlock --------------------------------------------------

    public AutoUnlockConfig? AutoUnlock => _file.AutoUnlock;

    /// <summary>True if auto-unlock is configured and a second sealed copy of the DEK exists.</summary>
    public bool AutoUnlockEnabled => _file.AutoUnlock?.Enabled == true && _file.DekAuto is not null;

    /// <summary>
    /// Enables network auto-unlock: seals a second copy of the DEK under an auto-unlock secret and
    /// stores <paramref name="config"/>. Requires the vault to be unlocked. Returns the auto-unlock
    /// secret to display once so the user can configure their webservice to return it. The secret is
    /// not persisted on disk.
    /// </summary>
    public string EnableAutoUnlock(AutoUnlockConfig config, string? autoUnlockKey = null)
    {
        EnsureUnlocked();
        string keyString = string.IsNullOrEmpty(autoUnlockKey)
            ? Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            : autoUnlockKey;

        byte[] keyBytes = Encoding.UTF8.GetBytes(keyString);
        try
        {
            _file.DekAuto = _vault!.SealCurrentUnder(keyBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }

        config.Enabled = true;
        _file.AutoUnlock = config;
        Save();
        return keyString;
    }

    public void DisableAutoUnlock()
    {
        _file.DekAuto = null;
        _file.AutoUnlock = null;
        Save();
    }

    /// <summary>
    /// Attempts to unlock by fetching the auto-unlock secret from the configured webservice. Returns
    /// false (leaving the vault locked) on any failure, so the caller can fall back to the PIN.
    /// </summary>
    public async Task<bool> TryAutoUnlockAsync(HttpMessageHandler? handler = null, CancellationToken cancellationToken = default)
    {
        if (!AutoUnlockEnabled) return false;
        try
        {
            EnsureOpened();
            byte[] key = await AutoUnlockClient.FetchKeyAsync(_file.AutoUnlock!, handler, cancellationToken).ConfigureAwait(false);
            try
            {
                _vault!.UnlockFrom(_file.DekAuto!, key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void Save() => VaultStore.Save(_path, _file);

    private void EnsureUnlocked()
    {
        if (_vault?.IsUnlocked != true)
            throw new InvalidOperationException("Vault is locked.");
    }

    private static byte[] PinBytes(string? pin)
        => string.IsNullOrEmpty(pin) ? [] : Encoding.UTF8.GetBytes(pin);

    public void Dispose() => _vault?.Dispose();
}
