<#
.SYNOPSIS
    Remove/block unwanted apps, restrict Microsoft Store to admins only,
    monitor and block app launches by non-admins with popup,
    auto-run at startup, compatible with Windows 10/11 all editions.

.DESCRIPTION
    - Removes built-in apps (except Calculator).
    - Blocks third-party apps by denying execution permissions.
    - Microsoft Store accessible only to admins.
    - Runs at startup via scheduled task.
    - Monitors and kills blocked apps launched by non-admins with popup.
#>

# --- Configuration ---

# Built-in app package name patterns to remove/block (except Calculator)
$builtInApps = @(
    "3dviewer",
    "windowsalarms",
    "windowscalculator", # Will NOT remove/block, keep accessible
    "windowscommunicationsapps", # Mail, Calendar
    "windowscamera",
    "microsoft.windows.cortana",
    "windowsfeedbackhub",
    "gethelp",
    "getstarted",
    "zunemusic",
    "windowsmaps",
    "windowsmessaging",
    "mixedrealityportal",
    "windowsphone",
    "zunevideo",
    "bingnews",
    "officehub",
    "onenote",
    "mspaint",
    "people",
    "skypeapp",
    "snippingtool",
    "solitairecollection",
    "stickynotes",
    "tips",
    "todo",
    "soundrecorder",
    "windowsalarms",
    "windowsphone",
    "windowsstore", # Microsoft Store handled separately
    "weather",
    "whiteboard",
    "xboxapp",
    "xboxgamemanagement",
    "xboxgameoverlay",
    "xboxidentityprovider",
    "xboxspeechto textoverlay",
    "yourphone"
)

# Third-party apps to block by executable name and common install folder patterns
$thirdPartyApps = @{

    # Remote Access & Control
    "TeamViewer.exe" = "C:\Program Files\TeamViewer"
    "AnyDesk.exe" = "C:\Program Files\AnyDesk"
    "chromeremotedesktop.exe" = "$env:LOCALAPPDATA\Google\Chrome Remote Desktop"
    "LogMeIn.exe" = "C:\Program Files\LogMeIn"
    "vncviewer.exe" = "C:\Program Files\UltraVNC"
    "RemotePC.exe" = "C:\Program Files\RemotePC"
    "tigervnc.exe" = "C:\Program Files\TigerVNC"
    "GoToMyPC.exe" = "C:\Program Files\GoToMyPC"
    "AmmyyAdmin.exe" = "C:\Program Files\Ammyy Admin"

    # File Sharing & P2P
    "bittorrent.exe" = "C:\Program Files\BitTorrent"
    "utorrent.exe" = "C:\Program Files\uTorrent"
    "qbittorrent.exe" = "C:\Program Files\qBittorrent"
    "emule.exe" = "C:\Program Files\eMule"
    "deluge.exe" = "C:\Program Files\Deluge"
    "tixati.exe" = "C:\Program Files\Tixati"
    "frostwire.exe" = "C:\Program Files\FrostWire"
    "MEGAsync.exe" = "C:\Program Files\MEGA"
    "WeTransfer.exe" = "C:\Program Files\WeTransfer"
    "Syncthing.exe" = "C:\Program Files\Syncthing"
    "ResilioSync.exe" = "C:\Program Files\Resilio Sync"

    # Unofficial Communication Tools
    "Telegram.exe" = "C:\Program Files\Telegram Desktop"
    "WhatsApp.exe" = "C:\Program Files\WhatsApp"
    "Signal.exe" = "C:\Program Files\Signal"
    "Discord.exe" = "C:\Program Files\Discord"
    "Viber.exe" = "C:\Program Files\Viber"
    "Skype.exe" = "C:\Program Files\Skype"
    "Slack.exe" = "C:\Program Files\Slack"
    "Zoom.exe" = "C:\Program Files\Zoom"

    # System Tweaking & Riskware
    "RevoUnin.exe" = "C:\Program Files\Revo Uninstaller"
    "IObitUnin.exe" = "C:\Program Files\IObit Uninstaller"
    "PowerToys.exe" = "C:\Program Files\PowerToys"
    "Autoruns.exe" = "C:\Program Files\Autoruns"
    "ProcessHacker.exe" = "C:\Program Files\Process Hacker"
    "CheatEngine.exe" = "C:\Program Files\Cheat Engine"
    "RegistryWorkshop.exe" = "C:\Program Files\Registry Workshop"

    # Gaming Clients & Games
    "Steam.exe" = "C:\Program Files\Steam"
    "EpicGamesLauncher.exe" = "C:\Program Files\Epic Games"
    "Battle.net.exe" = "C:\Program Files\Battle.net"
    "Origin.exe" = "C:\Program Files\Origin"
    "GOGGalaxy.exe" = "C:\Program Files\GOG Galaxy"
    "RiotClient.exe" = "C:\Program Files\Riot Games"
    "MinecraftLauncher.exe" = "C:\Program Files\Minecraft Launcher"
    "RobloxPlayer.exe" = "C:\Program Files\Roblox"

    # Anonymizers & Unapproved Browsers
    "TorBrowser.exe" = "C:\Program Files\Tor Browser"
    "Opera.exe" = "C:\Program Files\Opera"
    "Brave.exe" = "C:\Program Files\BraveSoftware\Brave-Browser"
    "EpicPrivacyBrowser.exe" = "C:\Program Files\Epic Privacy Browser"
    "Psiphon.exe" = "C:\Program Files\Psiphon"
    "HotspotShield.exe" = "C:\Program Files\Hotspot Shield"
    "ProtonVPN.exe" = "C:\Program Files\ProtonVPN"
    "Windscribe.exe" = "C:\Program Files\Windscribe"

    # Hacking & Security Tools
    "Wireshark.exe" = "C:\Program Files\Wireshark"
    "Nmap.exe" = "C:\Program Files\Nmap"
    "Metasploit.exe" = "C:\Program Files\Metasploit"
    "BurpSuite.exe" = "C:\Program Files\Burp Suite"
    "Cain.exe" = "C:\Program Files\Cain and Abel"
    "JohnTheRipper.exe" = "C:\Program Files\John the Ripper"
    "Hashcat.exe" = "C:\Program Files\Hashcat"
    "Netcat.exe" = "C:\Program Files\Netcat"
    "Mimikatz.exe" = "C:\Program Files\Mimikatz"
    "ProcessExplorer.exe" = "C:\Program Files\Process Explorer"

    # Virtualization & Dev Tools
    "VirtualBox.exe" = "C:\Program Files\Oracle\VirtualBox"
    "VMware.exe" = "C:\Program Files\VMware\VMware Workstation"
    "Docker.exe" = "C:\Program Files\Docker"
    "HyperV.exe" = "C:\Windows\System32\Hyper-V"
    "BlueStacks.exe" = "C:\Program Files\BlueStacks"
    "Nox.exe" = "C:\Program Files\Nox"
    "LDPlayer.exe" = "C:\Program Files\LDPlayer"
    "Genymotion.exe" = "C:\Program Files\Genymotion"
    "AndroidStudio.exe" = "C:\Program Files\Android\Android Studio"
    "MEmu.exe" = "C:\Program Files\MEmu"

    # Media & Streaming
    "Netflix.exe" = "C:\Program Files\Netflix"
    "Spotify.exe" = "C:\Program Files\Spotify"
    "VLC.exe" = "C:\Program Files\VideoLAN\VLC"
    "Kodi.exe" = "C:\Program Files\Kodi"
    "Plex.exe" = "C:\Program Files\Plex"

    # Portable App Loaders
    "PortableAppsPlatform.exe" = "C:\PortableApps"
    "LiberKey.exe" = "C:\Program Files\LiberKey"
    "Chocolatey.exe" = "C:\ProgramData\chocolatey\bin"
}

# --- Functions ---

function Remove-BuiltInApps {
    Write-Output "Removing built-in apps (except Calculator and Microsoft Store)..."
    foreach ($pattern in $builtInApps) {
        if ($pattern -eq "windowscalculator" -or $pattern -eq "windowsstore") {
            # Skip Calculator and Store here
            continue
        }
        try {
            $pkgs = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*$pattern*" }
            foreach ($pkg in $pkgs) {
                Write-Output "Removing $($pkg.Name)"
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction SilentlyContinue
            }
            # Remove provisioned packages
            $provPkgs = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*$pattern*" }
            foreach ($prov in $provPkgs) {
                Write-Output "Removing provisioned package $($prov.DisplayName)"
                Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Warning "Failed to remove $pattern: $_"
        }
    }
}

function Deny-ExecutionForNonAdmins {
    param ([string]$path)

    if (-not (Test-Path $path)) {
        Write-Warning "Path not found: $path"
        return
    }

    try {
        $acl = Get-Acl $path
        $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Users",
            "ReadAndExecute",
            "ContainerInherit,ObjectInherit",
            "None",
            "Deny"
        )
        # Check if deny rule exists
        $exists = $false
        foreach ($rule in $acl.Access) {
            if ($rule.IdentityReference -eq "Users" -and
                ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadAndExecute) -and
                $rule.AccessControlType -eq "Deny") {
                $exists = $true
                break
            }
        }
        if (-not $exists) {
            $acl.AddAccessRule($denyRule)
            Set-Acl -Path $path -AclObject $acl
            Write-Output "Denied execution for Users on $path"
        } else {
            Write-Output "Deny rule already exists on $path"
        }
    } catch {
        Write-Warning "Failed to set deny permission on $path: $_"
    }
}

function Allow-ExecutionForAdminsOnly {
    param ([string]$path)

    if (-not (Test-Path $path)) {
        Write-Warning "Path not found: $path"
        return
    }

    try {
        $acl = Get-Acl $path

        # Remove existing deny rules for Users if any
        $acl.Access | Where-Object {
            $_.IdentityReference -eq "Users" -and $_.AccessControlType -eq "Deny"
        } | ForEach-Object {
            $acl.RemoveAccessRule($_)
        }

        # Deny Users read/execute
        $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Users",
            "ReadAndExecute",
            "ContainerInherit,ObjectInherit",
            "None",
            "Deny"
        )
        $acl.AddAccessRule($denyRule)

        # Allow Administrators full control
        $allowRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Administrators",
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($allowRule)

        Set-Acl -Path $path -AclObject $acl
        Write-Output "Set Microsoft Store access to Administrators only on $path"
    } catch {
        Write-Warning "Failed to set permissions on $path: $_"
    }
}

function Monitor-And-BlockApps {
    # List of blocked executables (built-in + third-party)
    $blockedExecutables = @(
        # Built-in apps (except Calculator and Store)
        "3DViewer.exe","Alarms.exe","Calendar.exe","Camera.exe","Cortana.exe","FeedbackHub.exe",
        "GetHelp.exe","Getstarted.exe","GrooveMusic.exe","Maps.exe","Mail.exe","Messaging.exe",
        "MixedRealityPortal.exe","MobilePlans.exe","Movies & TV.exe","News.exe","OfficeHub.exe",
        "OneNote.exe","Paint3D.exe","People.exe","SkypeApp.exe","SnippingTool.exe","SolitaireCollection.exe",
        "StickyNotes.exe","Tips.exe","ToDo.exe","VoiceRecorder.exe","Weather.exe","Whiteboard.exe",
        "XboxGameBar.exe","XboxConsoleCompanion.exe","XboxLive.exe","YourPhone.exe","ZuneMusic.exe",
        "ZuneVideo.exe","MSNWeather.exe","MSNNews.exe","WindowsWebExperiencePack.exe","Widgets.exe",
        "SearchUI.exe", # Web Search (Bing)
        # Third-party apps keys from $thirdPartyApps
    ) + $thirdPartyApps.Keys

    function Show-BlockedPopup {
        param ([string]$AppName)
        Add-Type -AssemblyName PresentationFramework
        [System.Windows.MessageBox]::Show("Access to $AppName is restricted. Please contact your administrator.", "Access Denied", 'OK', 'Warning')
    }

    Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'" -SourceIdentifier "ProcessMonitor" -Action {
        $process = $Event.SourceEventArgs.NewEvent.TargetInstance
        if ($blockedExecutables -contains $process.Name) {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
            $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                try {
                    Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
                } catch {}
                Show-BlockedPopup -AppName $process.Name
            }
        }
    }
    Write-Output "Process monitoring started. Press Ctrl+C to stop."
    while ($true) { Start-Sleep -Seconds 10 }
}

function Create-ScheduledTask {
    $taskName = "EnforceAppRestrictions"
    $taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $taskExists) {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings
        Write-Output "Scheduled task '$taskName' created."
    } else {
        Write-Output "Scheduled task '$taskName' already exists."
    }
}

# --- Main Execution ---

# 1. Remove built-in apps except Calculator and Store
Remove-BuiltInApps

# 2. Deny execution for non-admins on built-in app folders (WindowsApps)
$windowsAppsPath = "$env:ProgramFiles\WindowsApps"
if (Test-Path $windowsAppsPath) {
    $builtInPatterns = $builtInApps | Where-Object { $_ -ne "windowscalculator" -and $_ -ne "windowsstore" }
    foreach ($pattern in $builtInPatterns) {
        $folders = Get-ChildItem -Path "$windowsAppsPath\$pattern*" -Directory -ErrorAction SilentlyContinue
        foreach ($folder in $folders) {
            Deny-ExecutionForNonAdmins -path $folder.FullName
        }
    }
    # Microsoft Store folder - allow only admins
    $storeFolders = Get-ChildItem -Path "$windowsAppsPath\Microsoft.WindowsStore*" -Directory -ErrorAction SilentlyContinue
    foreach ($folder in $storeFolders) {
        Allow-ExecutionForAdminsOnly -path $folder.FullName
    }
}

# 3. Deny execution for non-admins on third-party app folders
foreach ($exe in $thirdPartyApps.Keys) {
    $path = $thirdPartyApps[$exe]
    Deny-ExecutionForNonAdmins -path $path
}

# 4. Create scheduled task to run this script at startup
Create-ScheduledTask

# 5. Start monitoring and blocking apps launched by non-admins
Monitor-And-BlockApps
