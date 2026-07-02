using System.Collections.Generic;
using System.IO;
using Avalonia.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SimpleOtp.Import;

namespace SimpleOtp.App.ViewModels;

/// <summary>
/// Backs the Export window: renders each migration URI to a QR code and pages through them. A large
/// account set is split into multiple QRs by the exporter, so this may show more than one.
/// </summary>
public partial class ExportViewModel : ViewModelBase
{
    private readonly List<byte[]> _pngBytes = [];
    private readonly List<Bitmap> _bitmaps = [];

    [ObservableProperty] private int _currentIndex;
    [ObservableProperty] private Bitmap? _currentImage;
    [ObservableProperty] private string _pageLabel = "";
    [ObservableProperty] private bool _canPrev;
    [ObservableProperty] private bool _canNext;

    public int Count => _bitmaps.Count;
    public bool HasMultiple => _bitmaps.Count > 1;
    public int AccountCount { get; }
    public string Heading { get; }
    public string Description { get; }
    public string SaveBaseName { get; }
    public IReadOnlyList<byte[]> PngBytes => _pngBytes;

    /// <summary>Design-time constructor.</summary>
    public ExportViewModel() : this([], 0) { }

    public ExportViewModel(IReadOnlyList<string> uris, int accountCount,
        string heading = "Export accounts",
        string description = "Scan this with Google Authenticator (Add → Scan a QR code) or another authenticator to transfer your accounts. The migration format always uses a 30-second period and 6/8-digit codes.",
        string saveBaseName = "simpleotp-export")
    {
        AccountCount = accountCount;
        Heading = heading;
        Description = description;
        SaveBaseName = saveBaseName;
        foreach (string uri in uris)
        {
            byte[] png = QrEncoder.EncodePng(uri, pixelSize: 520);
            _pngBytes.Add(png);
            using var ms = new MemoryStream(png);
            _bitmaps.Add(new Bitmap(ms));
        }
        UpdateCurrent();
    }

    [RelayCommand]
    private void Next()
    {
        if (CurrentIndex < Count - 1) { CurrentIndex++; UpdateCurrent(); }
    }

    [RelayCommand]
    private void Prev()
    {
        if (CurrentIndex > 0) { CurrentIndex--; UpdateCurrent(); }
    }

    private void UpdateCurrent()
    {
        CurrentImage = Count > 0 ? _bitmaps[CurrentIndex] : null;
        PageLabel = Count > 0 ? $"QR {CurrentIndex + 1} of {Count}" : "Nothing to export";
        CanPrev = CurrentIndex > 0;
        CanNext = CurrentIndex < Count - 1;
    }
}
