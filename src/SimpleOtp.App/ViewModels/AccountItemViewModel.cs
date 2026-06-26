using System;
using CommunityToolkit.Mvvm.ComponentModel;
using SimpleOtp.Core;
using SimpleOtp.Core.Model;
using SimpleOtp.Core.Totp;

namespace SimpleOtp.App.ViewModels;

/// <summary>One row/card in the main list: the account, its current code, and the countdown.</summary>
public partial class AccountItemViewModel : ViewModelBase
{
    private readonly Account _account;
    private readonly VaultService _service;
    private long _lastCounter = -1;

    public AccountItemViewModel(Account account, VaultService service)
    {
        _account = account;
        _service = service;
    }

    public string Id => _account.Id;

    /// <summary>Primary line: issuer if present, else the label.</summary>
    public string Title => string.IsNullOrWhiteSpace(_account.Issuer) ? _account.Label : _account.Issuer;

    /// <summary>Secondary line: the account label (blank when it would duplicate the title).</summary>
    public string Subtitle => string.IsNullOrWhiteSpace(_account.Issuer) ? "" : _account.Label;

    /// <summary>The raw (unformatted) current code, used for clipboard copy.</summary>
    public string RawCode { get; private set; } = "";

    [ObservableProperty] private string _code = "------";
    [ObservableProperty] private int _secondsRemaining;
    [ObservableProperty] private double _progress;
    [ObservableProperty] private bool _isExpiring;

    /// <summary>
    /// Recomputes the displayed code (only when the time window rolls over — that's the only time it
    /// changes) and updates the cheap wall-clock-derived countdown every call.
    /// </summary>
    public void Refresh(DateTime utc)
    {
        int period = _account.Period;
        long counter = (long)((utc - DateTime.UnixEpoch).TotalSeconds / period);
        if (counter != _lastCounter)
        {
            _lastCounter = counter;
            try
            {
                RawCode = _service.GenerateCode(_account, utc);
            }
            catch
            {
                RawCode = "";
            }
            Code = Format(RawCode);
        }

        Progress = TotpGenerator.RemainingFraction(period, utc);
        SecondsRemaining = TotpGenerator.RemainingSeconds(period, utc);
        IsExpiring = SecondsRemaining <= 5;
    }

    private static string Format(string code) => code.Length switch
    {
        6 => $"{code[..3]} {code[3..]}",
        8 => $"{code[..4]} {code[4..]}",
        _ => string.IsNullOrEmpty(code) ? "error" : code,
    };
}
