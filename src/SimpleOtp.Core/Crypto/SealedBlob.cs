namespace SimpleOtp.Core.Crypto;

/// <summary>
/// An opaque blob produced by an <see cref="ISecretSealer"/>. For the TPM backend these are the
/// marshalled public and private portions of a TPM2 sealed object. They are only usable on the
/// exact TPM that created them (device binding); copying them elsewhere is useless.
/// </summary>
public sealed record SealedBlob(byte[] Public, byte[] Private);
