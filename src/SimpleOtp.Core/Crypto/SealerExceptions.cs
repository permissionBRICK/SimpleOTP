namespace SimpleOtp.Core.Crypto;

/// <summary>Base type for all sealer (TPM) errors.</summary>
public class SealerException : Exception
{
    public SealerException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>No usable TPM is present on this machine. The app hard-requires a TPM.</summary>
public sealed class SealerUnavailableException : SealerException
{
    public SealerUnavailableException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>The supplied PIN/auth value was rejected by the TPM.</summary>
public sealed class WrongPinException : SealerException
{
    /// <summary>
    /// Attempts remaining before the TPM trips into dictionary-attack lockout, when the backend can
    /// report it (TPM <c>maxAuthFail - lockoutCounter</c>); null if unknown.
    /// </summary>
    public int? RemainingAttempts { get; }

    public WrongPinException(string message, int? remainingAttempts = null, Exception? inner = null)
        : base(message, inner) => RemainingAttempts = remainingAttempts;
}

/// <summary>
/// The TPM rejected the operation in a way that indicates the sealed blob does not belong to this
/// TPM (e.g. the vault file was copied from another device, or the TPM was cleared/reset).
/// </summary>
public sealed class WrongDeviceException : SealerException
{
    public WrongDeviceException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>The TPM is in dictionary-attack lockout; too many bad auth attempts.</summary>
public sealed class TpmLockedException : SealerException
{
    /// <summary>
    /// Seconds the TPM needs before it will accept another attempt (the chip's lockout recovery
    /// interval), when the backend can report it; null if unknown.
    /// </summary>
    public int? RecoverySeconds { get; }

    public TpmLockedException(string message, int? recoverySeconds = null, Exception? inner = null)
        : base(message, inner) => RecoverySeconds = recoverySeconds;
}

/// <summary>
/// The TPM cannot host an HMAC key for the requested hash algorithm (Advanced mode). Many firmware
/// TPMs support SHA-1/SHA-256 but not SHA-512, so such accounts must stay in Simple mode.
/// </summary>
public sealed class UnsupportedAlgorithmException : SealerException
{
    public UnsupportedAlgorithmException(string message, Exception? inner = null) : base(message, inner) { }
}
