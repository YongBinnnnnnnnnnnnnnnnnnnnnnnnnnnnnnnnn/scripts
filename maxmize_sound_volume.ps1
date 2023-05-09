Invoke-Expression(([string]::Join([System.Environment]::NewLine, (Get-Content .\sound_volume_control.ps1))))
[Audio]::Volume = 1
[Audio]::Mute = $False