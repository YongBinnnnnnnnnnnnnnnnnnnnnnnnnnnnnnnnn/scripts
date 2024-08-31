# Load necessary assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Define Win32 API functions
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class User32 {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

    [DllImport("user32.dll")]
    public static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, int vk);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool UnregisterHotKey(IntPtr hWnd, int id);

    public const int GWL_EXSTYLE = -20; // For getting/setting window styles
    public const int WS_EX_LAYERED = 0x00080000;
    public const int WS_EX_TRANSPARENT = 0x0020;
    public const int WS_EX_TOOLWINDOW = 0x00000080;
    public const int WS_EX_NOACTIVATE = 0x08000000;
    public const int WS_EX_TOPMOST = 0x00000008; // Topmost style
    public const int WM_HOTKEY = 0x0312; // Hotkey message
}
"@

# Check for command-line arguments
if ($args.Count -eq 0) {
    # Default initial opacity if no arguments are provided
    $initialOpacity = 50
} else {
    # Try to parse the first argument as an integer opacity value
    $inputOpacity = [int]$args[0]
    if ($inputOpacity -ge 0 -and $inputOpacity -le 100) {
        $initialOpacity = $inputOpacity
    } else {
        Write-Host "Opacity should be a number between 0 and 100. Defaulting to 50%."
        $initialOpacity = 50
    }
}

# Create a new form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Transparent Overlay"
$form.Size = [System.Windows.Forms.SystemInformation]::VirtualScreen.Size  # Fullscreen size
$form.StartPosition = 'Manual'
$form.Location = [System.Windows.Forms.SystemInformation]::VirtualScreen.Location

# Set form properties for visual display
$form.FormBorderStyle = 'None'
$form.BackColor = [System.Drawing.Color]::Black
$form.Opacity = $initialOpacity / 100 # Convert to a decimal value for Opacity
$form.TopMost = $true
$form.ShowInTaskbar = $false  # Hide from taskbar

# Set extended window styles to allow for clicks to pass through
$hwnd = $form.Handle
$currentStyle = [User32]::GetWindowLong($hwnd, [User32]::GWL_EXSTYLE)
$newStyle = $currentStyle -bor [User32]::WS_EX_LAYERED -bor [User32]::WS_EX_TRANSPARENT -bor [User32]::WS_EX_NOACTIVATE -bor [User32]::WS_EX_TOPMOST
[User32]::SetWindowLong($hwnd, [User32]::GWL_EXSTYLE, $newStyle)

# Register global hotkeys
$hotkeyIds = @{
    IncreaseOpacity = 1
    DecreaseOpacity = 2
    CloseOverlay = 3
}

# Define modifiers and virtual keys
$MOD_CONTROL_WIN = 0x0008 + 0x0002  # Control + Windows
$VK_UP = [System.Windows.Forms.Keys]::Up
$VK_DOWN = [System.Windows.Forms.Keys]::Down
$VK_Q = [System.Windows.Forms.Keys]::Q

# Register the hotkeys
[User32]::RegisterHotKey($hwnd, $hotkeyIds.IncreaseOpacity, $MOD_CONTROL_WIN, [int]$VK_UP)
[User32]::RegisterHotKey($hwnd, $hotkeyIds.DecreaseOpacity, $MOD_CONTROL_WIN, [int]$VK_DOWN)
[User32]::RegisterHotKey($hwnd, $hotkeyIds.CloseOverlay, $MOD_CONTROL_WIN, [int]$VK_Q)

# Prevent the window from being closed in the normal way
$form.Add_FormClosing({
    $_.Cancel = $true
    [User32]::UnregisterHotKey($hwnd, $hotkeyIds.IncreaseOpacity)
    [User32]::UnregisterHotKey($hwnd, $hotkeyIds.DecreaseOpacity)
    [User32]::UnregisterHotKey($hwnd, $hotkeyIds.CloseOverlay)
})

# Start the form
$form.Show()

# Keep the application running
while ($form.Visible) {
    [System.Windows.Forms.Application]::DoEvents()  # Allow other events to process
    Start-Sleep -Milliseconds 100 # Reduce CPU usage
}

# Clean up
$form.Dispose()