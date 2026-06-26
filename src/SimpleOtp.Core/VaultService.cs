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

    /// <summary>True once a vault exists on disk.</summary>
    public bool IsInitialized => _file.IsInitialized;

    /// <summary>Which security model this vault uses.</summary>
    public SecurityMode Mode => _file.Mode;

    /// <summary>True if unlocking requires a PIN (Simple mode only).</summary>
    public bool PinProtected => _file.PinProtected;

    /// <summary>Advanced mode: true if a master password was set, so secrets can be exported.</summary>
    public bool ExportProtected => _file.ExportProtected;

    /// <summary>
    /// True when the vault can generate codes. Advanced mode is always usable (codes come straight
    /// from the TPM, no unlock step); Simple mode requires the DEK to be unsealed.
    /// </summary>
    public bool IsUnlocked => _file.Mode == SecurityMode.Advanced || _vault?.IsUnlocked == true;

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
        ValidateDevice();
        _vault = Vault.Open(_sealer, _file.Dek, _file.PinProtected);
    }

    /// <summary>
    /// Verifies the vault was created by the current sealer backend, throwing
    /// <see cref="WrongDeviceException"/> otherwise. Cheap early guard before any TPM operation;
    /// device binding is ultimately enforced by the TPM itself.
    /// </summary>
    public void ValidateDevice()
    {
        if (!string.Equals(_file.Backend, _sealer.BackendId, StringComparison.Ordinal))
            throw new WrongDeviceException(
                $"This vault was created with backend '{_file.Backend}', but the current device uses '{_sealer.BackendId}'. " +
                "It cannot be opened here.");
    }

    /// <summary>Convenience overload: unlock with a string PIN (UTF-8), or null/empty for no PIN.</summary>
    public void Unlock(string? pin) => Unlock(PinBytes(pin));

    public void Lock() => _vault?.Lock();

    /// <summary>
    /// Adds an account from parsed otpauth data. In Advanced mode the secret is imported into the TPM
    /// as a non-exportable HMAC key (plus a recoverable export copy when a master password is set);
    /// in Simple mode it is AES-GCM encrypted under the DEK. Zeroes the supplied secret bytes after use.
    /// </summary>
    public Account AddAccount(OtpAuthData data)
    {
        var account = new Account
        {
            Issuer = data.Issuer,
            Label = data.Label,
            Algorithm = data.Algorithm,
            Digits = data.Digits,
            Period = data.Period,
        };
        try
        {
            if (_file.Mode == SecurityMode.Advanced)
            {
                ValidateDevice();
                account.HmacKey = _sealer.ImportHmacKey(data.SecretBytes, data.Algorithm);
                if (_file.ExportProtected)
                    account.ExportCopy = ExportProtection.Encrypt(_file.ExportPublicKey!, data.SecretBytes);
            }
            else
            {
                EnsureUnlocked();
                account.Secret = _vault!.Encrypt(data.SecretBytes);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data.SecretBytes);
        }
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
    /// Generates the current TOTP code for an account. In Advanced mode the HMAC is computed inside
    /// the TPM (the seed never leaves the chip); in Simple mode the secret is decrypted transiently
    /// and zeroed immediately afterward.
    /// </summary>
    public string GenerateCode(Account account, DateTime? utc = null)
    {
        DateTime when = (utc ?? DateTime.UtcNow);
        if (_file.Mode == SecurityMode.Advanced)
        {
            if (account.HmacKey is null)
                throw new InvalidOperationException("Account has no TPM HMAC key.");
            byte[] counter = TotpGenerator.CounterBytes(account.Period, when);
            byte[] mac = _sealer.ComputeHmac(account.HmacKey, counter, account.Algorithm);
            return TotpGenerator.Truncate(mac, account.Digits);
        }

        EnsureUnlocked();
        byte[] secret = _vault!.Decrypt(account.Secret!);
        try
        {
            return TotpGenerator.Compute(secret, account.Algorithm, account.Digits, account.Period, when);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>
    /// Exports all accounts as one or more <c>otpauth-migration://</c> URIs (Google Authenticator
    /// format), split into batches so each fits in a scannable QR. Each secret is recovered
    /// transiently and zeroed afterward.
    ///
    /// Simple mode decrypts under the DEK (requires the vault unlocked; <paramref name="masterPassword"/>
    /// is ignored). Advanced mode requires the master password to recover the export private key, and
    /// is only possible if a master password was set when entering Advanced mode.
    /// </summary>
    /// <exception cref="InvalidOperationException">Advanced mode without a master password (export disabled).</exception>
    /// <exception cref="WrongPinException">Advanced mode with a wrong master password.</exception>
    public IReadOnlyList<string> ExportToMigrationUris(string? masterPassword = null)
    {
        if (_file.Mode == SecurityMode.Simple)
        {
            EnsureUnlocked();
            var simpleData = new List<OtpAuthData>(_file.Accounts.Count);
            try
            {
                foreach (Account account in _file.Accounts)
                {
                    byte[] secret = _vault!.Decrypt(account.Secret!);
                    simpleData.Add(new OtpAuthData(account.Issuer, account.Label, secret, account.Algorithm, account.Digits, account.Period));
                }
                return OtpAuthMigration.BuildExport(simpleData);
            }
            finally
            {
                foreach (OtpAuthData d in simpleData)
                    CryptographicOperations.ZeroMemory(d.SecretBytes);
            }
        }

        // Advanced mode.
        if (!_file.ExportProtected)
            throw new InvalidOperationException(
                "Exporting is disabled: this vault uses Advanced Security without a master password, " +
                "so the secrets cannot be recovered from the device.");
        ValidateDevice();

        byte[] pwBytes = PinBytes(masterPassword);
        byte[]? priv = null;
        var data = new List<OtpAuthData>(_file.Accounts.Count);
        try
        {
            priv = _sealer.Unseal(_file.ExportKeySealed!, pwBytes); // WrongPinException on bad password
            foreach (Account account in _file.Accounts)
            {
                if (account.ExportCopy is null)
                    throw new SealerException($"Account '{account.DisplayName}' has no recoverable export copy.");
                byte[] secret = ExportProtection.Decrypt(priv, _file.ExportPublicKey!, account.ExportCopy);
                data.Add(new OtpAuthData(account.Issuer, account.Label, secret, account.Algorithm, account.Digits, account.Period));
            }
            return OtpAuthMigration.BuildExport(data);
        }
        finally
        {
            foreach (OtpAuthData d in data)
                CryptographicOperations.ZeroMemory(d.SecretBytes);
            if (priv is not null) CryptographicOperations.ZeroMemory(priv);
            CryptographicOperations.ZeroMemory(pwBytes);
        }
    }

    // --- Security-mode conversion --------------------------------------------

    /// <summary>
    /// Converts a Simple vault to Advanced Security: each secret is re-homed into the TPM as a
    /// non-exportable HMAC key. If <paramref name="masterPassword"/> is non-empty, a recoverable
    /// export copy of each secret is also kept (encrypted to a fresh key sealed under the password),
    /// so the vault can still be exported or converted back later. With no password, the seeds become
    /// permanently non-exportable. Requires the (Simple) vault to be unlocked.
    /// </summary>
    public void ConvertToAdvanced(string? masterPassword)
    {
        if (_file.Mode == SecurityMode.Advanced)
            throw new InvalidOperationException("Vault is already in Advanced Security mode.");
        EnsureUnlocked(); // need the DEK to read the existing secrets

        byte[] pwBytes = PinBytes(masterPassword);
        ExportProtection.KeyPair? keyPair = null;
        byte[]? publicKey = null;
        SealedBlob? sealedPrivate = null;
        // Build the new per-account state up front; only commit once every import has succeeded, so a
        // failure (e.g. a hash the TPM can't do) leaves the on-disk Simple vault untouched.
        var pending = new List<(Account account, SealedBlob hmacKey, ExportCopy? copy)>(_file.Accounts.Count);
        try
        {
            if (pwBytes.Length > 0)
            {
                keyPair = ExportProtection.GenerateKeyPair();
                publicKey = keyPair.PublicKey;
                sealedPrivate = _sealer.Seal(keyPair.PrivateScalar, pwBytes);
            }

            foreach (Account account in _file.Accounts)
            {
                byte[] secret = _vault!.Decrypt(account.Secret!);
                try
                {
                    SealedBlob hmacKey = _sealer.ImportHmacKey(secret, account.Algorithm);
                    ExportCopy? copy = publicKey is not null ? ExportProtection.Encrypt(publicKey, secret) : null;
                    pending.Add((account, hmacKey, copy));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(secret);
                }
            }

            // Commit.
            foreach ((Account account, SealedBlob hmacKey, ExportCopy? copy) in pending)
            {
                account.HmacKey = hmacKey;
                account.ExportCopy = copy;
                account.Secret = null;
            }
            _file.Mode = SecurityMode.Advanced;
            _file.ExportKeySealed = sealedPrivate;
            _file.ExportPublicKey = publicKey;
            // Tear down Simple-mode state.
            _file.Dek = new SealedBlob([], []);
            _file.DekAuto = null;
            _file.AutoUnlock = null;
            _file.PinProtected = false;
            _vault?.Dispose();
            _vault = null;
            Save();
        }
        finally
        {
            if (keyPair is not null) CryptographicOperations.ZeroMemory(keyPair.PrivateScalar);
            CryptographicOperations.ZeroMemory(pwBytes);
        }
    }

    /// <summary>
    /// Converts an Advanced vault back to Simple Security. Only possible if a master password was set
    /// (otherwise the seeds are unrecoverable). Recovers every secret with the password, then seals a
    /// fresh DEK and re-encrypts the secrets under it. The vault is left unlocked with no PIN.
    /// </summary>
    /// <exception cref="InvalidOperationException">The Advanced vault has no master password.</exception>
    /// <exception cref="WrongPinException">The master password was wrong.</exception>
    public void ConvertToSimple(string masterPassword)
    {
        if (_file.Mode == SecurityMode.Simple)
            throw new InvalidOperationException("Vault is already in Simple Security mode.");
        if (!_file.ExportProtected)
            throw new InvalidOperationException(
                "This Advanced vault has no master password, so its secrets cannot be recovered. " +
                "Converting back to Simple is not possible.");
        ValidateDevice();

        byte[] pwBytes = PinBytes(masterPassword);
        byte[]? priv = null;
        var recovered = new List<(Account account, byte[] secret)>(_file.Accounts.Count);
        try
        {
            priv = _sealer.Unseal(_file.ExportKeySealed!, pwBytes); // WrongPinException on bad password
            foreach (Account account in _file.Accounts)
            {
                if (account.ExportCopy is null)
                    throw new SealerException($"Account '{account.DisplayName}' has no recoverable export copy.");
                recovered.Add((account, ExportProtection.Decrypt(priv, _file.ExportPublicKey!, account.ExportCopy)));
            }

            var vault = Vault.Create(_sealer, ReadOnlySpan<byte>.Empty); // fresh DEK, no PIN
            foreach ((Account account, byte[] secret) in recovered)
            {
                account.Secret = vault.Encrypt(secret);
                account.HmacKey = null;
                account.ExportCopy = null;
            }
            _vault?.Dispose();
            _vault = vault;
            _file.Mode = SecurityMode.Simple;
            _file.Dek = vault.SealedDek;
            _file.PinProtected = false;
            _file.ExportKeySealed = null;
            _file.ExportPublicKey = null;
            Save();
        }
        finally
        {
            foreach ((Account _, byte[] secret) in recovered)
                CryptographicOperations.ZeroMemory(secret);
            if (priv is not null) CryptographicOperations.ZeroMemory(priv);
            CryptographicOperations.ZeroMemory(pwBytes);
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

    private void Save()
    {
        // Any write upgrades the file to the current schema: a loaded v1 vault keeps Version==1 in
        // memory, so without this a conversion would persist v2-format data still labelled v1.
        _file.Version = VaultFile.CurrentSchemaVersion;
        VaultStore.Save(_path, _file);
    }

    private void EnsureUnlocked()
    {
        if (_vault?.IsUnlocked != true)
            throw new InvalidOperationException("Vault is locked.");
    }

    private static byte[] PinBytes(string? pin)
        => string.IsNullOrEmpty(pin) ? [] : Encoding.UTF8.GetBytes(pin);

    public void Dispose() => _vault?.Dispose();
}
