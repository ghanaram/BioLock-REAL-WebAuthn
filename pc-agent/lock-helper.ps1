Add-Type @"
using System;
using System.Runtime.InteropServices;

public class WinLock {
    [DllImport("user32.dll")]
    public static extern bool LockWorkStation();
}
"@

[WinLock]::LockWorkStation()