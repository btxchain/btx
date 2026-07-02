' BTX Mining Control - launches the panel with no visible PowerShell console window.
CreateObject("WScript.Shell").Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""D:\BTX\btx-miner-control.ps1""", 0, False
