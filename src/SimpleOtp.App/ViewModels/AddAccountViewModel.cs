using System;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SimpleOtp.Core.Model;
using SimpleOtp.Core.Totp;

namespace SimpleOtp.App.ViewModels;

/// <summary>Backs the "Add account" dialog: paste a link/secret, import a QR, or enter fields manually.</summary>
public partial class AddAccountViewModel : ViewModelBase
{
    [ObservableProperty] private string _pasteInput = "";
    [ObservableProperty] private string _issuer = "";
    [ObservableProperty] private string _label = "";
    [ObservableProperty] private string _secret = "";
    [ObservableProperty] private int _selectedAlgorithmIndex; // 0=SHA1,1=SHA256,2=SHA512
    [ObservableProperty] private int _digits = 6;
    [ObservableProperty] private int _period = 30;
    [ObservableProperty] private string _status = "";
    [ObservableProperty] private bool _isError;

    public string[] Algorithms { get; } = ["SHA1", "SHA256", "SHA512"];

    /// <summary>Parses the paste box: an otpauth URI fills all fields; anything else is treated as a Base32 secret.</summary>
    [RelayCommand]
    private void LoadFromPaste()
    {
        string text = PasteInput.Trim();
        if (text.Length == 0)
        {
            SetStatus("Paste an otpauth:// link or a secret first.", error: true);
            return;
        }

        if (OtpAuthUri.LooksLikeUri(text))
            ApplyUri(text);
        else
        {
            Secret = text;
            SetStatus("Treated the input as a Base32 secret. Fill in issuer / label below.");
        }
    }

    /// <summary>Applies text decoded from a QR image (expected to be an otpauth URI).</summary>
    public void ApplyDecoded(string decodedText)
    {
        if (OtpAuthUri.LooksLikeUri(decodedText))
            ApplyUri(decodedText);
        else
            SetStatus("The QR code did not contain an otpauth:// link.", error: true);
    }

    private void ApplyUri(string uri)
    {
        try
        {
            OtpAuthData data = OtpAuthUri.Parse(uri);
            Issuer = data.Issuer;
            Label = data.Label;
            Secret = OtpAuthUri.EncodeBase32(data.SecretBytes);
            SelectedAlgorithmIndex = (int)data.Algorithm;
            Digits = data.Digits;
            Period = data.Period;
            string who = string.IsNullOrWhiteSpace(data.Issuer) ? data.Label : data.Issuer;
            SetStatus($"Loaded “{who}”. Review and click Add.");
        }
        catch (FormatException ex)
        {
            SetStatus("Could not parse: " + ex.Message, error: true);
        }
    }

    /// <summary>Validates and builds the descriptor to add, or returns null and sets an error status.</summary>
    public OtpAuthData? Build()
    {
        string secret = Secret.Trim();
        if (secret.Length == 0)
        {
            SetStatus("A secret is required.", error: true);
            return null;
        }

        byte[] bytes;
        try
        {
            bytes = OtpAuthUri.DecodeBase32(secret);
        }
        catch (FormatException ex)
        {
            SetStatus(ex.Message, error: true);
            return null;
        }

        if (Issuer.Trim().Length == 0 && Label.Trim().Length == 0)
        {
            SetStatus("Enter an issuer or a label so you can recognize this account.", error: true);
            return null;
        }

        if (Digits is < 6 or > 8)
        {
            SetStatus("Digits must be between 6 and 8.", error: true);
            return null;
        }

        if (Period <= 0)
        {
            SetStatus("Period must be a positive number of seconds.", error: true);
            return null;
        }

        var algorithm = (OtpAlgorithm)SelectedAlgorithmIndex;
        return new OtpAuthData(Issuer.Trim(), Label.Trim(), bytes, algorithm, Digits, Period);
    }

    public void SetStatus(string message, bool error = false)
    {
        Status = message;
        IsError = error;
    }
}
