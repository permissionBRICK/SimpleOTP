using CommunityToolkit.Mvvm.ComponentModel;
using SimpleOtp.Core.Totp;

namespace SimpleOtp.App.ViewModels;

/// <summary>One selectable row in the Google Authenticator bulk-import preview.</summary>
public partial class MigrationItemViewModel : ViewModelBase
{
    public OtpAuthData Data { get; }

    [ObservableProperty] private bool _isSelected = true;

    public MigrationItemViewModel(OtpAuthData data)
    {
        Data = data;
        Title = string.IsNullOrWhiteSpace(data.Issuer)
            ? (string.IsNullOrWhiteSpace(data.Label) ? "(unnamed)" : data.Label)
            : data.Issuer;
        Detail = string.IsNullOrWhiteSpace(data.Issuer) ? "" : data.Label;
    }

    public string Title { get; }
    public string Detail { get; }
}
