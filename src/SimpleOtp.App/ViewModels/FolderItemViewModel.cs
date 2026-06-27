using CommunityToolkit.Mvvm.ComponentModel;

namespace SimpleOtp.App.ViewModels;

/// <summary>
/// One folder card on the top-level list. Unlike an account card it never generates a code — it just
/// shows the folder name and how many accounts are filed inside. Clicking it opens the folder, which is
/// where those accounts' codes actually start generating.
/// </summary>
public partial class FolderItemViewModel : ViewModelBase
{
    public string Id { get; }

    [ObservableProperty] private string _name;
    [ObservableProperty] private int _count;

    public FolderItemViewModel(string id, string name, int count)
    {
        Id = id;
        _name = string.IsNullOrWhiteSpace(name) ? "(unnamed folder)" : name;
        _count = count;
    }

    /// <summary>Subtitle line, e.g. "Empty", "1 account", "5 accounts".</summary>
    public string CountText => Count switch
    {
        0 => "Empty",
        1 => "1 account",
        _ => $"{Count} accounts",
    };

    partial void OnCountChanged(int value) => OnPropertyChanged(nameof(CountText));
}
