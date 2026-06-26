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
    public WrongPinException(string message, Exception? inner = null) : base(message, inner) { }
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
    public TpmLockedException(string message, Exception? inner = null) : base(message, inner) { }
}
