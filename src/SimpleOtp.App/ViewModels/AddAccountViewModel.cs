using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SimpleOtp.Core.Model;
using SimpleOtp.Core.Totp;

namespace SimpleOtp.App.ViewModels;

/// <summary>Backs the "Add account" dialog: paste a link/secret, import a single QR or a Google
/// Authenticator bulk-export QR, or enter fields manually.</summary>
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

    // Bulk import (Google Authenticator export). When IsBulk, the dialog shows the account list
    // instead of the single-account detail fields.
    [ObservableProperty] private bool _isBulk;
    [ObservableProperty] private string _addButtonText = "Add";

    public ObservableCollection<MigrationItemViewModel> BulkItems { get; } = [];

    // Multi-part import bookkeeping: a split export is several QRs sharing a batch id. We accumulate
    // accounts across the parts the user loads, deduping, and track how many parts are still missing.
    private const char KeySeparator = '\u001f'; // unit separator: not present in issuer/label/Base32
    private readonly HashSet<string> _loadedParts = [];   // "batchId:batchIndex"
    private readonly HashSet<string> _accountKeys = [];   // issuer|label|secret, for dedupe
    private int _expectedParts = 1;

    public string[] Algorithms { get; } = ["SHA1", "SHA256", "SHA512"];

    /// <summary>Screen-snip capture is wired to the Windows Snipping Tool, so only offered there.</summary>
    public bool CanSnip { get; } = OperatingSystem.IsWindows();

    partial void OnIsBulkChanged(bool value) => AddButtonText = value ? "Add selected" : "Add";

    /// <summary>Clears the accumulated bulk-import list and returns to single-account mode.</summary>
    [RelayCommand]
    private void ClearBulk()
    {
        BulkItems.Clear();
        _loadedParts.Clear();
        _accountKeys.Clear();
        _expectedParts = 1;
        IsBulk = false;
        SetStatus("");
    }

    /// <summary>Parses the paste box: a migration export → bulk list; an otpauth URI → fills the
    /// fields; anything else → treated as a Base32 secret.</summary>
    [RelayCommand]
    private void LoadFromPaste()
    {
        string text = PasteInput.Trim();
        if (text.Length == 0)
        {
            SetStatus("Paste an otpauth:// link, a migration export, or a secret first.", error: true);
            return;
        }

        if (OtpAuthMigration.LooksLikeUri(text))
            LoadMigration(text);
        else if (OtpAuthUri.LooksLikeUri(text))
            ApplyUri(text);
        else
        {
            Secret = text;
            SetStatus("Treated the input as a Base32 secret. Fill in issuer / label below.");
        }
    }

    /// <summary>Applies text decoded from a QR image (single otpauth URI or a bulk migration export).</summary>
    public void ApplyDecoded(string decodedText)
    {
        if (OtpAuthMigration.LooksLikeUri(decodedText))
            LoadMigration(decodedText);
        else if (OtpAuthUri.LooksLikeUri(decodedText))
            ApplyUri(decodedText);
        else
            SetStatus("The QR code did not contain an otpauth:// link.", error: true);
    }

    private void LoadMigration(string uri)
    {
        try
        {
            OtpAuthMigration.MigrationBatch batch = OtpAuthMigration.ParseBatch(uri);
            if (batch.Accounts.Count == 0)
            {
                SetStatus("That export contained no TOTP accounts (HOTP isn't supported).", error: true);
                return;
            }

            string partKey = $"{batch.BatchId}:{batch.BatchIndex}";
            if (!_loadedParts.Add(partKey))
            {
                SetStatus("That QR was already loaded. Open the other part(s) of the export.", error: true);
                return;
            }
            _expectedParts = Math.Max(_expectedParts, batch.BatchSize);

            int added = 0;
            foreach (OtpAuthData account in batch.Accounts)
            {
                string key = string.Join(KeySeparator, account.Issuer, account.Label, OtpAuthUri.EncodeBase32(account.SecretBytes));
                if (_accountKeys.Add(key))
                {
                    BulkItems.Add(new MigrationItemViewModel(account));
                    added++;
                }
            }

            IsBulk = true;
            if (_loadedParts.Count < _expectedParts)
                SetStatus($"Loaded part {_loadedParts.Count} of {_expectedParts} — {BulkItems.Count} account(s) so far. " +
                          "Open the remaining QR code(s) to load the rest, then Add selected.");
            else
                SetStatus($"Loaded {BulkItems.Count} account(s) from {_expectedParts} QR code(s). Choose which to import, then Add selected.");
        }
        catch (FormatException ex)
        {
            SetStatus("Couldn't read the export: " + ex.Message, error: true);
        }
    }

    /// <summary>The accounts the user ticked in bulk mode.</summary>
    public IReadOnlyList<OtpAuthData> SelectedAccounts()
        => BulkItems.Where(i => i.IsSelected).Select(i => i.Data).ToList();

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
