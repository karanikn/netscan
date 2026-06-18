#Requires -Version 5.1
<#
.SYNOPSIS   Network Scanner v1 - DHCP Rogue Detector and Port Scanner
.DESCRIPTION
    WinForms GUI (not WPF) for maximum stability on Windows PowerShell 5.1.
    Scanning runs via Start-Job (a separate PowerShell process), polled by a
    Windows.Forms.Timer on the UI thread - this means a crash inside the scan
    logic can NEVER take down the GUI process, unlike thread/runspace based
    approaches where unhandled exceptions on a background thread can kill
    the whole app.

    nmap is NOT checked at startup (this used to slow down opening the app).
    It is only located/offered for download right when a scan starts.
    If nmap is missing, the user is asked whether to download a portable
    copy; if declined, the scan proceeds using built-in PowerShell-only
    ping/TCP/ARP/DNS methods (slower, but fully functional).

    Every significant step is written to a log file in %TEMP% AND to the
    on-screen Scan Log, so problems can always be diagnosed after the fact.
.NOTES
    Version: 1.0   Date: 2026-06-17
    Requires Admin (auto-elevates via UAC)
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\netscan.ps1
#>

$ErrorActionPreference = 'Stop'

# ============================================================
# LOGGING (file + in-memory queue used by the UI)
# ============================================================
$Script:LogDir  = Join-Path $env:TEMP 'NetScanner_Logs'
New-Item -Path $Script:LogDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
$Script:LogFile = Join-Path $Script:LogDir ('NetScanner_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Write-AppLog {
    param([string]$Message, [string]$Level = 'INFO')
    try {
        $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
        Add-Content -Path $Script:LogFile -Value $line -Encoding UTF8
    } catch { }
}

Write-AppLog "=== Application starting ==="
Write-AppLog "PowerShell version: $($PSVersionTable.PSVersion)"
Write-AppLog "Script path: $PSCommandPath"
Write-AppLog "Log file: $Script:LogFile"

# ============================================================
# UAC ELEVATION
# ============================================================
function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

if (-not (Test-IsAdmin)) {
    Write-AppLog "Not running as admin - requesting elevation" "WARN"
    $sp = $PSCommandPath
    if (-not $sp) {
        $sp = Join-Path $env:TEMP 'NetScanner_run.ps1'
        $MyInvocation.MyCommand.ScriptBlock | Out-File $sp -Encoding UTF8
        Write-AppLog "No script path available, wrote temp copy to $sp" "WARN"
    }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName  = 'powershell.exe'
        $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $sp
        $psi.Verb      = 'runas'
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        Write-AppLog "Elevation request sent, exiting non-elevated instance"
    } catch {
        Write-AppLog "Elevation failed or was cancelled: $($_.Exception.Message)" "ERROR"
    }
    exit
}
Write-AppLog "Running elevated: OK"

# ============================================================
# ASSEMBLIES
# ============================================================
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Core
    [System.Windows.Forms.Application]::EnableVisualStyles()
    Write-AppLog "WinForms assemblies loaded OK"
} catch {
    Write-AppLog "FATAL: failed to load assemblies: $($_.Exception.ToString())" "ERROR"
    throw
}

# Catch anything that would otherwise silently kill the process
try {
    [System.Windows.Forms.Application]::add_ThreadException(
        [System.Threading.ThreadExceptionEventHandler]{
            param($sender, $e)
            Write-AppLog "ThreadException: $($e.Exception.ToString())" "ERROR"
            try {
                [System.Windows.Forms.MessageBox]::Show(
                    "An unexpected error occurred:`r`n`r`n$($e.Exception.Message)`r`n`r`nDetails were written to:`r`n$Script:LogFile",
                    "Error", "OK", "Error") | Out-Null
            } catch { }
        })
    [System.AppDomain]::CurrentDomain.add_UnhandledException(
        [System.UnhandledExceptionEventHandler]{
            param($sender, $e)
            Write-AppLog "AppDomain.UnhandledException: $($e.ExceptionObject.ToString())" "ERROR"
        })
    Write-AppLog "Global exception handlers registered OK"
} catch {
    Write-AppLog "Failed to register exception handlers: $($_.Exception.Message)" "WARN"
}

# ============================================================
# GLOBAL STATE
# ============================================================
$Script:Ui          = @{}
$Script:Results     = New-Object System.Collections.ArrayList
$Script:ScanJob      = $null
$Script:ScanTimer    = $null
$Script:ScanStart    = $null
$Script:NmapPath     = $null
# The script's own folder is used for nmap/OUI data so it persists
# alongside the tool itself rather than in a temp folder that gets
# cleaned up. Must be defined before anything that builds a path from it.
$Script:ScriptDir    = if ($PSCommandPath) { Split-Path $PSCommandPath -Parent } else { $env:TEMP }
$Script:NmapDir      = Join-Path $Script:ScriptDir 'nmap'
# As of Nmap 7.93, the Windows distribution dropped the portable .zip
# package in favor of an installer-only release. 7.92 was the last version
# with a portable zip, so we try that first (no install step, no UAC
# elevation prompt beyond what this app already has). If that ever
# disappears too, we fall back to silently installing the current
# installer .exe into a folder next to this script instead of using the
# normal Program Files location.
$Script:NmapZipUrl     = 'https://nmap.org/dist/nmap-7.92-win32.zip'
$Script:NmapInstallUrl = 'https://nmap.org/dist/nmap-7.99-setup.exe'
$Script:DarkMode     = $false
$Script:KnownDhcp    = New-Object 'System.Collections.Generic.HashSet[string]'
$Script:LastReceiveCount = 0

# --- NIC vendor (OUI) lookup ---
$Script:OuiFile       = Join-Path $Script:ScriptDir 'oui.txt'
$Script:OuiUrl        = 'https://standards-oui.ieee.org/oui/oui.txt'
# Fallback mirror, tried if the primary IEEE source fails after several
# retries (e.g. transient rate-limiting/bot-protection errors like the
# HTTP 418 seen in testing). Must serve the same "XX-XX-XX (hex) Vendor"
# text format as the primary source, since that's what Load-OuiDatabase
# parses - a differently formatted source would silently fail to parse.
$Script:OuiMirrorUrls = @(
    'http://linuxnet.ca/ieee/oui.txt'
)
$Script:OuiMap        = $null   # populated lazily by Load-OuiDatabase
$Script:OuiMaxAgeDays = 90      # if the local file is older than this, offer to refresh it

$Script:AllKnownPorts = @(20,21,22,23,25,80,109,110,115,143,161,389,443,445,464,554,587,873,902,993,995,1194,1723,2020,2095,2222,2598,3268,3306,3307,3380,3389,3390,5000,5001,5004,5060,5061,5400,5800,5900,6000,7064,8000,8080,8222,8333,9600,10050,10080,10554,25937)
$Script:PortNames = @{
    20='FTP-Data'; 21='FTP'; 22='SSH'; 23='Telnet'; 25='SMTP'; 80='HTTP'; 109='POP2'; 110='POP3'
    115='SFTP'; 143='IMAP'; 161='SNMP'; 389='LDAP'; 443='HTTPS'; 445='SMB'; 464='Kerberos'; 554='RTSP'
    587='SMTP-TLS'; 873='Rsync'; 902='VMware'; 993='IMAPS'; 995='POP3S'; 1194='OpenVPN'; 1723='PPTP'
    2020='Custom'; 2095='cPanel'; 2222='SSH-Alt'; 2598='Citrix'; 3268='LDAP-GC'; 3306='MySQL'; 3307='MySQL-Alt'
    3380='RDP-Alt2'; 3389='RDP'; 3390='RDP-Alt'; 5000='UPnP'; 5001='Custom'; 5004='RTP'; 5060='SIP'
    5061='SIP-TLS'; 5400='Custom'; 5800='VNC-HTTP'; 5900='VNC'; 6000='X11'; 7064='Custom'; 8000='HTTP-Alt2'
    8080='HTTP-Alt'; 8222='VMware'; 8333='Bitcoin'; 9600='Custom'; 10050='Zabbix'; 10080='Amanda'
    10554='RTSP-Alt'; 25937='Custom'
}
# Ports enabled by default - the basic SoftPerfect-style set (21,22,23,80,443).
# All other known ports exist in the Settings dialog as unchecked checkboxes -
# the user ticks the ones they want scanned.
$Script:EnabledPorts = New-Object 'System.Collections.Generic.HashSet[int]'
foreach ($p in @(21,22,23,80,443)) { [void]$Script:EnabledPorts.Add($p) }

$Script:Settings = [ordered]@{
    MaxThreads      = 50
    PingTimeoutMs   = 300
    TcpTimeoutMs    = 400
    PingMethod      = 'Both'      # ICMP, ARP, Both
    ShowOffline     = $false
    ResolveHostname = $true
    ResolveMac      = $true
    ResolveVendor   = $true
    UdpDhcpCheck    = $true
    DhcpBroadcast   = $true
    CustomPortsText = ''
}

# ============================================================
# THEME
# ============================================================
$Script:ThemeLight = @{
    Back=[Drawing.Color]::FromArgb(248,250,252); Card=[Drawing.Color]::White; Header=[Drawing.Color]::FromArgb(15,23,42)
    HeaderText=[Drawing.Color]::White; Text=[Drawing.Color]::FromArgb(17,24,39); Muted=[Drawing.Color]::FromArgb(100,116,139)
    Border=[Drawing.Color]::FromArgb(203,213,225); Blue=[Drawing.Color]::FromArgb(37,99,235); Green=[Drawing.Color]::FromArgb(22,163,74)
    Red=[Drawing.Color]::FromArgb(220,38,38); Orange=[Drawing.Color]::FromArgb(217,119,6); GridAlt=[Drawing.Color]::FromArgb(248,250,252)
    Select=[Drawing.Color]::FromArgb(219,234,254); Dhcp=[Drawing.Color]::FromArgb(255,237,213); Auth=[Drawing.Color]::FromArgb(220,252,231)
    Menu=[Drawing.Color]::FromArgb(241,245,249); Log=[Drawing.Color]::White
}
$Script:ThemeDark = @{
    Back=[Drawing.Color]::FromArgb(15,23,42); Card=[Drawing.Color]::FromArgb(30,41,59); Header=[Drawing.Color]::FromArgb(2,6,23)
    HeaderText=[Drawing.Color]::White; Text=[Drawing.Color]::FromArgb(241,245,249); Muted=[Drawing.Color]::FromArgb(148,163,184)
    Border=[Drawing.Color]::FromArgb(71,85,105); Blue=[Drawing.Color]::FromArgb(96,165,250); Green=[Drawing.Color]::FromArgb(74,222,128)
    Red=[Drawing.Color]::FromArgb(248,113,113); Orange=[Drawing.Color]::FromArgb(251,191,36); GridAlt=[Drawing.Color]::FromArgb(39,52,73)
    Select=[Drawing.Color]::FromArgb(30,64,175); Dhcp=[Drawing.Color]::FromArgb(92,64,24); Auth=[Drawing.Color]::FromArgb(22,79,48)
    Menu=[Drawing.Color]::FromArgb(30,41,59); Log=[Drawing.Color]::FromArgb(2,6,23)
}
function Get-Theme { if ($Script:DarkMode) { $Script:ThemeDark } else { $Script:ThemeLight } }

# ============================================================
# NETWORK / SYSTEM HELPERS  (run on UI thread - fast, no nmap)
# ============================================================
function Convert-MaskToPrefix {
    param([string]$Mask)
    try {
        $bytes = [System.Net.IPAddress]::Parse($Mask).GetAddressBytes()
        $bits = 0
        foreach ($b in $bytes) { for ($i=7;$i -ge 0;$i--) { if (([int]$b -band (1 -shl $i)) -ne 0) { $bits++ } } }
        return $bits
    } catch { return 24 }
}

function Get-LocalInterfaces {
    # Uses WMI (Win32_NetworkAdapterConfiguration) instead of Get-NetAdapter/
    # Get-NetIPConfiguration - more reliable across PS5.1 / various Windows
    # builds and noticeably faster to enumerate.
    $items = New-Object System.Collections.ArrayList
    try {
        $cfgs = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop
        foreach ($cfg in $cfgs) {
            if (-not $cfg.IPAddress) { continue }
            for ($i=0; $i -lt $cfg.IPAddress.Count; $i++) {
                $ip = [string]$cfg.IPAddress[$i]
                if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { continue }
                if ($ip.StartsWith('169.254.') -or $ip -eq '127.0.0.1') { continue }
                $mask = if ($cfg.IPSubnet -and $cfg.IPSubnet.Count -gt $i) { [string]$cfg.IPSubnet[$i] } else { '255.255.255.0' }
                $prefix = Convert-MaskToPrefix $mask
                $parts = $ip -split '\.'
                $desc = if ($cfg.Description) { [string]$cfg.Description } else { 'Network Adapter' }
                [void]$items.Add([pscustomobject]@{
                    Display = "$desc ($ip)"
                    Name    = $desc
                    Ip      = $ip
                    Prefix  = $prefix
                    From    = "$($parts[0]).$($parts[1]).$($parts[2]).1"
                    To      = "$($parts[0]).$($parts[1]).$($parts[2]).254"
                    Gateway = if ($cfg.DefaultIPGateway) { [string]$cfg.DefaultIPGateway[0] } else { '' }
                    DhcpServer = if ($cfg.DHCPServer) { [string]$cfg.DHCPServer } else { '' }
                })
            }
        }
        Write-AppLog "Found $($items.Count) local interface address(es)"
    } catch {
        Write-AppLog "Get-LocalInterfaces failed: $($_.Exception.Message)" "ERROR"
    }
    return @($items)
}

function Get-NetInfoText {
    $sb = New-Object System.Text.StringBuilder
    foreach ($i in (Get-LocalInterfaces)) {
        [void]$sb.AppendLine($i.Name)
        [void]$sb.AppendLine("  IP  : $($i.Ip)/$($i.Prefix)")
        if ($i.Gateway) { [void]$sb.AppendLine("  GW  : $($i.Gateway)") }
        if ($i.DhcpServer) { [void]$sb.AppendLine("  DHCP: $($i.DhcpServer)") }
        [void]$sb.AppendLine("")
    }
    try {
        $n = (& arp.exe -a 2>$null | Select-String "dynamic").Count
        [void]$sb.AppendLine("ARP cache: $n dynamic entries")
    } catch { }
    return $sb.ToString()
}

function Find-NmapPath {
    # Fast, local-only checks - no process launch, no --version call.
    try {
        $cmd = Get-Command nmap.exe -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    } catch { }
    foreach ($p in @(
        (Join-Path $Script:NmapDir 'nmap.exe'),
        'C:\Program Files\Nmap\nmap.exe',
        'C:\Program Files (x86)\Nmap\nmap.exe'
    )) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

# ============================================================
# NIC VENDOR (OUI) DATABASE
# ============================================================
function Invoke-OuiDownloadAttempt {
    param([string]$Url, [string]$DestPath, [int]$TimeoutSeconds = 90)
    # One single download attempt. Returns $true/$false; throws nothing -
    # all failure modes are captured and logged, caller decides on retry.
    try {
        $wc = New-Object System.Net.WebClient
        # A more complete, browser-like header set. The bare 'Mozilla/5.0'
        # User-Agent we used before was apparently enough to trigger this
        # server's bot/rate-limit protection (HTTP 418). Filling in Accept
        # and Accept-Language like a real browser request reduces that risk.
        $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36')
        $wc.Headers.Add('Accept', 'text/plain,text/html,*/*')
        $wc.Headers.Add('Accept-Language', 'en-US,en;q=0.9')

        $script:ouiDlDone = $false
        $script:ouiDlError = $null
        $wc.Add_DownloadFileCompleted({
            param($s, $e)
            $script:ouiDlDone = $true
            if ($e.Error) { $script:ouiDlError = $e.Error }
        })
        $wc.DownloadFileAsync([Uri]$Url, $DestPath)

        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (-not $script:ouiDlDone -and $sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
            [Windows.Forms.Application]::DoEvents()
            Start-Sleep -Milliseconds 100
        }

        if (-not $script:ouiDlDone) {
            try { $wc.CancelAsync() } catch { }
            Write-AppLog "OUI download attempt timed out after ${TimeoutSeconds}s ($Url)" "WARN"
            return $false
        }
        if ($script:ouiDlError) {
            Write-AppLog "OUI download attempt failed ($Url): $($script:ouiDlError.Message)" "WARN"
            return $false
        }
        if (-not (Test-Path $DestPath) -or (Get-Item $DestPath).Length -lt 1000) {
            Write-AppLog "OUI download attempt produced an empty/too-small file ($Url)" "WARN"
            return $false
        }
        return $true
    } catch {
        Write-AppLog "OUI download attempt exception ($Url): $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Download-OuiDatabase {
    # Downloads the official IEEE OUI registry (MAC address prefix -> vendor
    # name) to oui.txt next to this script. Synchronous with DoEvents()
    # pumping so the UI stays responsive during the download.
    #
    # The IEEE server occasionally returns transient errors (e.g. HTTP 418,
    # likely basic bot/rate-limit protection) that succeed on a simple
    # retry. To handle that without bothering the user, this tries up to
    # 3 times with increasing delay, and falls back to a mirror URL if the
    # primary source keeps failing.
    $tmpFile = "$Script:OuiFile.download"
    Remove-Item $tmpFile -ErrorAction SilentlyContinue

    $urls = @($Script:OuiUrl) + @($Script:OuiMirrorUrls)
    $maxAttemptsPerUrl = 3
    $success = $false

    foreach ($url in $urls) {
        for ($attempt = 1; $attempt -le $maxAttemptsPerUrl; $attempt++) {
            Write-AppLog "Downloading OUI database (attempt $attempt/$maxAttemptsPerUrl) from $url"
            $Script:Ui.StatusLabel.Text = "Downloading NIC vendor database (attempt $attempt)..."
            Ui-Log "Downloading NIC vendor database (attempt $attempt/$maxAttemptsPerUrl)..." "INFO"

            if (Invoke-OuiDownloadAttempt -Url $url -DestPath $tmpFile -TimeoutSeconds 90) {
                $success = $true
                break
            }

            if ($attempt -lt $maxAttemptsPerUrl) {
                $delaySec = $attempt * 3   # 3s, then 6s backoff between retries
                Ui-Log "Download attempt $attempt failed, retrying in ${delaySec}s..." "WARN"
                $waitUntil = (Get-Date).AddSeconds($delaySec)
                while ((Get-Date) -lt $waitUntil) {
                    [Windows.Forms.Application]::DoEvents()
                    Start-Sleep -Milliseconds 100
                }
            }
        }
        if ($success) { break }
        Ui-Log "All attempts for $url failed, trying next source if available..." "WARN"
    }

    $Script:Ui.StatusLabel.Text = "Ready"

    if (-not $success) {
        Write-AppLog "OUI database download failed after all attempts and sources" "ERROR"
        Ui-Log "NIC vendor database download failed after several attempts. You can try again later via Tools > Update NIC Vendor Database." "ERROR"
        Remove-Item $tmpFile -ErrorAction SilentlyContinue
        return $false
    }

    try {
        Move-Item -Path $tmpFile -Destination $Script:OuiFile -Force
        Write-AppLog "OUI database saved to $Script:OuiFile" "OK"
        Ui-Log "NIC vendor database downloaded: $Script:OuiFile" "OK"
        $Script:OuiMap = $null   # force reload on next lookup
        return $true
    } catch {
        Write-AppLog "Failed to move downloaded OUI file into place: $($_.Exception.Message)" "ERROR"
        Ui-Log "Could not save the downloaded NIC vendor database: $($_.Exception.Message)" "ERROR"
        return $false
    } finally {
        $Script:Ui.StatusLabel.Text = "Ready"
    }
}

function Load-OuiDatabase {
    # Parses oui.txt into an in-memory hashtable keyed by the 6 hex digit
    # OUI prefix (e.g. 'A4B1C2') -> vendor name. The IEEE file has lines like:
    #   00-1A-11   (hex)		Google, Inc.
    # We only care about the "(hex)" lines.
    if ($Script:OuiMap) { return $Script:OuiMap }
    if (-not (Test-Path $Script:OuiFile)) { return $null }
    try {
        Write-AppLog "Parsing OUI database: $Script:OuiFile"
        $map = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $reader = [System.IO.StreamReader]::new($Script:OuiFile)
        try {
            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                if ($line -match '^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$') {
                    $prefix = ($Matches[1] -replace '-', '').ToUpper()
                    $vendor = $Matches[2].Trim()
                    if (-not $map.ContainsKey($prefix)) { $map[$prefix] = $vendor }
                }
            }
        } finally { $reader.Close() }
        Write-AppLog "OUI database loaded: $($map.Count) entries"
        $Script:OuiMap = $map
        return $map
    } catch {
        Write-AppLog "Load-OuiDatabase failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-VendorFromMac {
    param([string]$Mac)
    if (-not $Mac) { return '' }
    $map = Load-OuiDatabase
    if (-not $map) { return '' }
    $clean = ($Mac -replace '[:\-\.]', '').ToUpper()
    if ($clean.Length -lt 6) { return '' }
    $prefix = $clean.Substring(0,6)
    if ($map.ContainsKey($prefix)) { return $map[$prefix] }
    return ''
}

function Ensure-OuiDatabase {
    # Called once at startup. Offers to download if missing, or to refresh
    # if the local copy is older than $Script:OuiMaxAgeDays.
    if (-not (Test-Path $Script:OuiFile)) {
        Write-AppLog "OUI database not found, prompting user"
        $answer = [Windows.Forms.MessageBox]::Show(
            "The NIC vendor database (oui.txt) was not found.`r`n`r`n" +
            "This file maps MAC address prefixes to manufacturer names (e.g. 'Routerboard.com', 'HP Inc.') and is used to fill in the VENDOR column during scans.`r`n`r`n" +
            "Download it now from standards-oui.ieee.org? (a few MB, saved next to this script)",
            "NIC Vendor Database", "YesNo", "Question")
        if ($answer -eq 'Yes') { [void](Download-OuiDatabase) }
        return
    }

    try {
        $age = (Get-Date) - (Get-Item $Script:OuiFile).LastWriteTime
        if ($age.TotalDays -gt $Script:OuiMaxAgeDays) {
            Write-AppLog "OUI database is $([int]$age.TotalDays) days old, prompting refresh"
            $answer = [Windows.Forms.MessageBox]::Show(
                "The NIC vendor database (oui.txt) is $([int]$age.TotalDays) days old.`r`n`r`n" +
                "Manufacturers regularly register new MAC prefixes - an outdated file may show blank vendors for newer devices.`r`n`r`n" +
                "Update it now?",
                "NIC Vendor Database", "YesNo", "Question")
            if ($answer -eq 'Yes') { [void](Download-OuiDatabase) }
        }
    } catch { Write-AppLog "Ensure-OuiDatabase age check failed: $($_.Exception.Message)" "WARN" }
}

# ============================================================
# UI BUILDING HELPERS
# ============================================================
function Get-GridContextRow {
    # Returns the currently right-clicked/selected row in the results grid, or $null.
    $g = $Script:Ui.Grid
    if ($g -and $g.SelectedRows.Count -gt 0) { return $g.SelectedRows[0] }
    return $null
}

function Copy-ToClipboardSafe {
    param([string]$Text)
    if ($Text) { try { [Windows.Forms.Clipboard]::SetText($Text) } catch { } }
}

function New-FlatButton {
    param([string]$Text, [Drawing.Color]$Color, [int]$Width = 120, [int]$Height = 36)
    $b = New-Object Windows.Forms.Button
    $b.Text = $Text
    $b.Width = $Width; $b.Height = $Height
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize = 0
    $b.BackColor = $Color
    $b.ForeColor = [Drawing.Color]::White
    $b.Font = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)
    $b.Cursor = [Windows.Forms.Cursors]::Hand
    return $b
}

function Ui-Log {
    param([string]$Message, [string]$Level = 'INFO')
    Write-AppLog $Message $Level
    try {
        $color = switch ($Level) {
            'ERROR' { (Get-Theme).Red }
            'WARN'  { (Get-Theme).Orange }
            'OK'    { (Get-Theme).Green }
            default { (Get-Theme).Text }
        }
        $Script:Ui.LogBox.SelectionStart  = $Script:Ui.LogBox.TextLength
        $Script:Ui.LogBox.SelectionLength = 0
        $Script:Ui.LogBox.SelectionColor  = $color
        $Script:Ui.LogBox.AppendText("[$(Get-Date -Format 'HH:mm:ss')] $Message`r`n")
        $Script:Ui.LogBox.SelectionStart  = $Script:Ui.LogBox.TextLength
        $Script:Ui.LogBox.ScrollToCaret()
    } catch { }
}

function Apply-Theme {
    $t = Get-Theme
    $f = $Script:Ui.Form
    $f.BackColor = $t.Back
    $Script:Ui.Menu.BackColor = $t.Menu
    $Script:Ui.Menu.ForeColor = $t.Text
    $Script:Ui.Header.BackColor = $t.Header
    $Script:Ui.Title.ForeColor = $t.HeaderText
    $Script:Ui.Subtitle.ForeColor = [Drawing.Color]::FromArgb(180,195,220)
    $Script:Ui.NmapLabel.ForeColor = if ($Script:NmapPath) { $t.Green } else { $t.Muted }
    $Script:Ui.ThemeBtn.BackColor = if ($Script:DarkMode) { $t.Blue } else { [Drawing.Color]::FromArgb(30,41,59) }

    $Script:Ui.Toolbar.BackColor = $t.Card
    foreach ($k in @('LblFrom','LblTo','LblIface')) { $Script:Ui[$k].ForeColor = $t.Muted }
    foreach ($k in @('TxtFrom','TxtTo')) {
        $Script:Ui[$k].BackColor = $t.Card; $Script:Ui[$k].ForeColor = $t.Text; $Script:Ui[$k].BorderStyle = 'FixedSingle'
    }
    $Script:Ui.Combo.BackColor = $t.Card; $Script:Ui.Combo.ForeColor = $t.Text

    $Script:Ui.GridHeaderPanel.BackColor = $t.Card
    $Script:Ui.GridHeaderLabel.ForeColor = $t.Text
    $Script:Ui.CountBadge.ForeColor = $t.Muted

    $g = $Script:Ui.Grid
    $g.BackgroundColor = $t.Card
    $g.GridColor = $t.Border
    $g.DefaultCellStyle.BackColor = $t.Card
    $g.DefaultCellStyle.ForeColor = $t.Text
    $g.DefaultCellStyle.SelectionBackColor = $t.Select
    $g.DefaultCellStyle.SelectionForeColor = $t.Text
    $g.AlternatingRowsDefaultCellStyle.BackColor = $t.GridAlt
    $g.ColumnHeadersDefaultCellStyle.BackColor = $t.Menu
    $g.ColumnHeadersDefaultCellStyle.ForeColor = $t.Text
    $g.EnableHeadersVisualStyles = $false

    $Script:Ui.LogHeaderPanel.BackColor = $t.Card
    $Script:Ui.LogHeaderLabel.ForeColor = $t.Text
    $Script:Ui.LogBox.BackColor = $t.Log
    $Script:Ui.LogBox.ForeColor = $t.Text

    $Script:Ui.NetInfoHeaderPanel.BackColor = $t.Card
    $Script:Ui.NetInfoHeaderLabel.ForeColor = $t.Text
    $Script:Ui.NetInfoBox.BackColor = $t.Log
    $Script:Ui.NetInfoBox.ForeColor = $t.Muted

    $Script:Ui.StatusPanel.BackColor = $t.Card
    $Script:Ui.StatusLabel.ForeColor = $t.Muted
}

function Add-ResultToGrid {
    param($r)
    [void]$Script:Results.Add($r)
    $g = $Script:Ui.Grid
    $idx = $g.Rows.Add($r.IP, $r.MAC, $r.Vendor, $r.RespMs, $r.Hostname, $r.OpenPorts, $r.DhcpFlag, $r.Details)
    $row = $g.Rows[$idx]
    $t = Get-Theme
    # Visual hierarchy for the DHCP SERVER column:
    #   "YES (CHECK!)"      -> unexpected/unverified DHCP server = ROGUE candidate.
    #                          Whole row gets a strong red background so it jumps out.
    #   "YES (AUTHORIZED)"  -> a DHCP server that answered the broadcast/UDP probe
    #                          AND is on your whitelist = expected, shown in green.
    #   "Authorized"        -> on the whitelist but not independently confirmed this
    #                          scan = shown in a softer green.
    if ($r.DhcpFlag -match '^YES \(CHECK!\)$') {
        $row.DefaultCellStyle.BackColor = $t.Red
        $row.DefaultCellStyle.ForeColor = [Drawing.Color]::White
        $row.Cells['Dhcp'].Style.Font = New-Object Drawing.Font($g.Font, [Drawing.FontStyle]::Bold)
    } elseif ($r.DhcpFlag -match 'AUTHORIZED') {
        $row.DefaultCellStyle.BackColor = $t.Auth
        $row.Cells['Dhcp'].Style.Font = New-Object Drawing.Font($g.Font, [Drawing.FontStyle]::Bold)
    } elseif ($r.DhcpFlag -eq 'Authorized') {
        $row.DefaultCellStyle.BackColor = $t.Auth
    }
    $Script:Ui.CountBadge.Text = "$($Script:Results.Count) devices"
}

# ============================================================
# MAIN FORM BUILD
# ============================================================
function Build-MainForm {
    Write-AppLog "Building main form..."

    $form = New-Object Windows.Forms.Form
    $form.Text = "Network Scanner"
    $form.Width = 1300; $form.Height = 820
    $form.StartPosition = 'CenterScreen'
    $form.MinimumSize = New-Object Drawing.Size(1000,600)
    $form.Font = New-Object Drawing.Font('Segoe UI', 9)
    $Script:Ui.Form = $form

    # --- Menu bar ---
    $menu = New-Object Windows.Forms.MenuStrip
    $miFile = New-Object Windows.Forms.ToolStripMenuItem('File')
    $miExit = New-Object Windows.Forms.ToolStripMenuItem('Exit')
    $miExit.Add_Click({ $form.Close() })
    [void]$miFile.DropDownItems.Add($miExit)

    $miTools = New-Object Windows.Forms.ToolStripMenuItem('Tools')
    $miSettings = New-Object Windows.Forms.ToolStripMenuItem('Settings...')
    $miSettings.Add_Click({ Show-SettingsDialog })
    $miOpenLog = New-Object Windows.Forms.ToolStripMenuItem('Open Log Folder')
    $miOpenLog.Add_Click({ try { Start-Process explorer.exe $Script:LogDir } catch { } })
    $miUpdateOui = New-Object Windows.Forms.ToolStripMenuItem('Update NIC Vendor Database')
    $miUpdateOui.Add_Click({
        $ageText = if (Test-Path $Script:OuiFile) {
            $age = [int]((Get-Date) - (Get-Item $Script:OuiFile).LastWriteTime).TotalDays
            "Current file is $age day(s) old."
        } else { "No local copy found yet." }
        $answer = [Windows.Forms.MessageBox]::Show(
            "$ageText`r`n`r`nDownload the latest NIC vendor database from standards-oui.ieee.org now?",
            "Update NIC Vendor Database", "YesNo", "Question")
        if ($answer -eq 'Yes') {
            if (Download-OuiDatabase) {
                [Windows.Forms.MessageBox]::Show("NIC vendor database updated.","Update NIC Vendor Database","OK","Information") | Out-Null
            }
        }
    })
    [void]$miTools.DropDownItems.Add($miSettings)
    [void]$miTools.DropDownItems.Add($miOpenLog)
    [void]$miTools.DropDownItems.Add($miUpdateOui)

    $miHelp = New-Object Windows.Forms.ToolStripMenuItem('Help')
    $miAbout = New-Object Windows.Forms.ToolStripMenuItem('About')
    $miAbout.Add_Click({ Show-AboutDialog })
    [void]$miHelp.DropDownItems.Add($miAbout)

    [void]$menu.Items.Add($miFile)
    [void]$menu.Items.Add($miTools)
    [void]$menu.Items.Add($miHelp)
    $form.MainMenuStrip = $menu
    $Script:Ui.Menu = $menu

    # --- Header ---
    $header = New-Object Windows.Forms.Panel
    $header.Dock = 'Top'; $header.Height = 64
    $Script:Ui.Header = $header

    $title = New-Object Windows.Forms.Label
    $title.Text = "Network Scanner"
    $title.Font = New-Object Drawing.Font('Segoe UI', 14, [Drawing.FontStyle]::Bold)
    $title.AutoSize = $true
    $title.Location = New-Object Drawing.Point(18,8)
    $header.Controls.Add($title); $Script:Ui.Title = $title

    $subtitle = New-Object Windows.Forms.Label
    $subtitle.Text = "DHCP Rogue Detector and Port Scanner"
    $subtitle.Font = New-Object Drawing.Font('Segoe UI', 9)
    $subtitle.AutoSize = $true
    $subtitle.Location = New-Object Drawing.Point(20,36)
    $header.Controls.Add($subtitle); $Script:Ui.Subtitle = $subtitle

    $nmapLbl = New-Object Windows.Forms.Label
    $nmapLbl.Text = "nmap: not checked yet"
    $nmapLbl.AutoSize = $true
    $nmapLbl.Font = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)
    $nmapLbl.Location = New-Object Drawing.Point(($form.Width - 420),22)
    $nmapLbl.Anchor = 'Top,Right'
    $header.Controls.Add($nmapLbl); $Script:Ui.NmapLabel = $nmapLbl

    $themeBtn = New-Object Windows.Forms.Button
    $themeBtn.Text = "Dark Mode"
    $themeBtn.Width = 110; $themeBtn.Height = 30
    $themeBtn.FlatStyle = 'Flat'
    $themeBtn.FlatAppearance.BorderSize = 0
    $themeBtn.ForeColor = [Drawing.Color]::White
    $themeBtn.Location = New-Object Drawing.Point(($form.Width - 140),17)
    $themeBtn.Anchor = 'Top,Right'
    $themeBtn.Add_Click({
        $Script:DarkMode = -not $Script:DarkMode
        $Script:Ui.ThemeBtn.Text = if ($Script:DarkMode) { "Light Mode" } else { "Dark Mode" }
        Apply-Theme
    })
    $header.Controls.Add($themeBtn); $Script:Ui.ThemeBtn = $themeBtn

    # --- Toolbar ---
    $toolbar = New-Object Windows.Forms.Panel
    $toolbar.Dock = 'Top'; $toolbar.Height = 76
    $Script:Ui.Toolbar = $toolbar

    $lblFrom = New-Object Windows.Forms.Label
    $lblFrom.Text = "IPv4 From"; $lblFrom.AutoSize = $true
    $lblFrom.Location = New-Object Drawing.Point(18,8)
    $toolbar.Controls.Add($lblFrom); $Script:Ui.LblFrom = $lblFrom

    $txtFrom = New-Object Windows.Forms.TextBox
    $txtFrom.Width = 140; $txtFrom.Location = New-Object Drawing.Point(18,26)
    $txtFrom.Font = New-Object Drawing.Font('Consolas', 10)
    $toolbar.Controls.Add($txtFrom); $Script:Ui.TxtFrom = $txtFrom

    $lblTo = New-Object Windows.Forms.Label
    $lblTo.Text = "To"; $lblTo.AutoSize = $true
    $lblTo.Location = New-Object Drawing.Point(170,8)
    $toolbar.Controls.Add($lblTo); $Script:Ui.LblTo = $lblTo

    $txtTo = New-Object Windows.Forms.TextBox
    $txtTo.Width = 140; $txtTo.Location = New-Object Drawing.Point(170,26)
    $txtTo.Font = New-Object Drawing.Font('Consolas', 10)
    $toolbar.Controls.Add($txtTo); $Script:Ui.TxtTo = $txtTo

    $lblIface = New-Object Windows.Forms.Label
    $lblIface.Text = "Interface"; $lblIface.AutoSize = $true
    $lblIface.Location = New-Object Drawing.Point(330,8)
    $toolbar.Controls.Add($lblIface); $Script:Ui.LblIface = $lblIface

    $combo = New-Object Windows.Forms.ComboBox
    $combo.Width = 240; $combo.Location = New-Object Drawing.Point(330,26)
    $combo.DropDownStyle = 'DropDownList'
    $combo.DisplayMember = 'Display'
    $toolbar.Controls.Add($combo); $Script:Ui.Combo = $combo

    $btnSettings = New-Object Windows.Forms.Button
    $btnSettings.Text = "Settings"
    $btnSettings.Width = 86; $btnSettings.Height = 32
    $btnSettings.FlatStyle = 'Flat'; $btnSettings.FlatAppearance.BorderSize = 1
    $btnSettings.Location = New-Object Drawing.Point(600,26)
    $btnSettings.Add_Click({ Show-SettingsDialog })
    $toolbar.Controls.Add($btnSettings)

    $btnNmap = New-Object Windows.Forms.Button
    $btnNmap.Text = "Get nmap"
    $btnNmap.Width = 96; $btnNmap.Height = 32
    $btnNmap.FlatStyle = 'Flat'; $btnNmap.FlatAppearance.BorderSize = 1
    $btnNmap.Location = New-Object Drawing.Point(692,26)
    $btnNmap.Add_Click({ Get-NmapManually })
    $toolbar.Controls.Add($btnNmap); $Script:Ui.BtnNmap = $btnNmap

    $btnScan = New-FlatButton -Text "Start Scanning" -Color (Get-Theme).Blue -Width 150
    $btnScan.Location = New-Object Drawing.Point(794,24)
    $btnScan.Add_Click({ Start-ScanFlow })
    $toolbar.Controls.Add($btnScan); $Script:Ui.BtnScan = $btnScan

    $btnStop = New-FlatButton -Text "Stop" -Color (Get-Theme).Red -Width 90
    $btnStop.Location = New-Object Drawing.Point(952,24)
    $btnStop.Enabled = $false
    $btnStop.Add_Click({ Stop-Scan })
    $toolbar.Controls.Add($btnStop); $Script:Ui.BtnStop = $btnStop

    $btnExport = New-FlatButton -Text "Export CSV" -Color ([Drawing.Color]::FromArgb(100,116,139)) -Width 110
    $btnExport.Location = New-Object Drawing.Point(1050,24)
    $btnExport.Add_Click({ Export-Results })
    $toolbar.Controls.Add($btnExport)

    # --- Status bar ---
    $statusPanel = New-Object Windows.Forms.Panel
    $statusPanel.Dock = 'Bottom'; $statusPanel.Height = 28
    $Script:Ui.StatusPanel = $statusPanel

    $statusLabel = New-Object Windows.Forms.Label
    $statusLabel.Text = "Ready"
    $statusLabel.AutoSize = $true
    $statusLabel.Location = New-Object Drawing.Point(16,6)
    $statusPanel.Controls.Add($statusLabel); $Script:Ui.StatusLabel = $statusLabel

    $adminBadge = New-Object Windows.Forms.Label
    $adminBadge.Text = "ADMIN"
    $adminBadge.AutoSize = $true
    $adminBadge.ForeColor = [Drawing.Color]::White
    $adminBadge.BackColor = [Drawing.Color]::FromArgb(22,163,74)
    $adminBadge.Padding = New-Object Windows.Forms.Padding(6,2,6,2)
    $adminBadge.Location = New-Object Drawing.Point(($form.Width - 90),3)
    $adminBadge.Anchor = 'Top,Right'
    $statusPanel.Controls.Add($adminBadge)

    # --- Main layout (top to bottom, left to right):
    #     [          Scan Results (full width)            ]
    #     [  Scan Log (left)     |   Network Info (right)  ]
    # outerSplit is Horizontal orientation -> splits TOP/BOTTOM.
    # bottomSplit is Vertical orientation   -> splits LEFT/RIGHT.
    $outerSplit = New-Object Windows.Forms.SplitContainer
    $outerSplit.Dock = 'Fill'
    $outerSplit.Orientation = 'Horizontal'
    $outerSplit.SplitterWidth = 5

    $bottomSplit = New-Object Windows.Forms.SplitContainer
    $bottomSplit.Dock = 'Fill'
    $bottomSplit.Orientation = 'Vertical'
    $bottomSplit.SplitterWidth = 5
    $outerSplit.Panel2.Controls.Add($bottomSplit)

    # --- TOP (full width): results grid ---
    $grid = New-Object Windows.Forms.DataGridView
    $grid.Dock = 'Fill'
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToResizeRows = $false
    $grid.ReadOnly = $true
    $grid.RowHeadersVisible = $false
    $grid.SelectionMode = 'FullRowSelect'
    $grid.AutoSizeColumnsMode = 'None'
    $grid.BorderStyle = 'None'
    $grid.ScrollBars = 'Both'
    $grid.Font = New-Object Drawing.Font('Consolas', 9)
    [void]$grid.Columns.Add('IP','IP')
    [void]$grid.Columns.Add('MAC','MAC')
    [void]$grid.Columns.Add('Vendor','VENDOR')
    [void]$grid.Columns.Add('Resp','RESP.TIME')
    [void]$grid.Columns.Add('Host','HOSTNAME')
    [void]$grid.Columns.Add('Ports','OPEN PORTS')
    [void]$grid.Columns.Add('Dhcp','DHCP SERVER')
    [void]$grid.Columns.Add('Details','DETAILS')
    $grid.Columns['IP'].Width = 130
    $grid.Columns['MAC'].Width = 150
    $grid.Columns['Vendor'].Width = 160
    $grid.Columns['Resp'].Width = 80
    $grid.Columns['Host'].Width = 170
    $grid.Columns['Ports'].Width = 220
    $grid.Columns['Dhcp'].Width = 130
    $grid.Columns['Details'].Width = 200
    $grid.Columns['Details'].MinimumWidth = 150
    $outerSplit.Panel1.Controls.Add($grid); $Script:Ui.Grid = $grid

    # --- Right-click context menu: copy IP / MAC / Hostname / RDP / whole row ---
    $gridMenu = New-Object Windows.Forms.ContextMenuStrip
    $miCopyIp = New-Object Windows.Forms.ToolStripMenuItem('Copy IP')
    $miCopyMac = New-Object Windows.Forms.ToolStripMenuItem('Copy MAC')
    $miCopyHost = New-Object Windows.Forms.ToolStripMenuItem('Copy Hostname')
    $miCopyRdp = New-Object Windows.Forms.ToolStripMenuItem('Connect via RDP')
    $miCopySep = New-Object Windows.Forms.ToolStripSeparator
    $miCopyLine = New-Object Windows.Forms.ToolStripMenuItem('Copy All (line)')
    $miToolsSep = New-Object Windows.Forms.ToolStripSeparator
    $miPingMonitor = New-Object Windows.Forms.ToolStripMenuItem('Ping Monitor...')
    $miTraceroute = New-Object Windows.Forms.ToolStripMenuItem('Traceroute...')
    [void]$gridMenu.Items.Add($miCopyIp)
    [void]$gridMenu.Items.Add($miCopyMac)
    [void]$gridMenu.Items.Add($miCopyHost)
    [void]$gridMenu.Items.Add($miCopyRdp)
    [void]$gridMenu.Items.Add($miCopySep)
    [void]$gridMenu.Items.Add($miCopyLine)
    [void]$gridMenu.Items.Add($miToolsSep)
    [void]$gridMenu.Items.Add($miPingMonitor)
    [void]$gridMenu.Items.Add($miTraceroute)

    $miCopyIp.Add_Click({
        $r = Get-GridContextRow
        if ($r) { Copy-ToClipboardSafe $r.Cells['IP'].Value }
    })
    $miCopyMac.Add_Click({
        $r = Get-GridContextRow
        if ($r) { Copy-ToClipboardSafe $r.Cells['MAC'].Value }
    })
    $miCopyHost.Add_Click({
        $r = Get-GridContextRow
        if ($r) { Copy-ToClipboardSafe $r.Cells['Host'].Value }
    })
    $miCopyRdp.Add_Click({
        $r = Get-GridContextRow
        if ($r) {
            $target = $r.Cells['Host'].Value
            if (-not $target) { $target = $r.Cells['IP'].Value }
            if ($target) {
                Write-AppLog "Connect via RDP: $target"
                try { Start-Process 'mstsc.exe' -ArgumentList "/v:$target" } catch { Write-AppLog "Failed to launch RDP: $($_.Exception.Message)" "ERROR" }
            }
        }
    })
    $miCopyLine.Add_Click({
        $r = Get-GridContextRow
        if ($r) {
            $vals = @()
            foreach ($col in $Script:Ui.Grid.Columns) { $vals += "$($r.Cells[$col.Index].Value)" }
            Copy-ToClipboardSafe ($vals -join "`t")
        }
    })
    $miPingMonitor.Add_Click({
        $r = Get-GridContextRow
        if ($r) {
            $target = $r.Cells['IP'].Value
            if ($target) { Show-PingMonitorWindow -Target $target }
        }
    })
    $miTraceroute.Add_Click({
        $r = Get-GridContextRow
        if ($r) {
            $target = $r.Cells['IP'].Value
            if ($target) { Show-TracerouteWindow -Target $target }
        }
    })

    # Right-clicking a cell should select its row before the menu shows,
    # so Copy IP/MAC/etc always act on the row under the cursor rather
    # than whatever was selected before.
    $grid.Add_CellMouseDown({
        param($s, $e)
        if ($e.Button -eq [Windows.Forms.MouseButtons]::Right -and $e.RowIndex -ge 0) {
            $Script:Ui.Grid.ClearSelection()
            $Script:Ui.Grid.Rows[$e.RowIndex].Selected = $true
        }
    })
    $grid.ContextMenuStrip = $gridMenu

    # Double-click a specific cell to copy just that cell's value.
    $grid.Add_CellDoubleClick({
        param($s, $e)
        if ($e.RowIndex -ge 0 -and $e.ColumnIndex -ge 0) {
            $val = $Script:Ui.Grid.Rows[$e.RowIndex].Cells[$e.ColumnIndex].Value
            if ($val) {
                Copy-ToClipboardSafe $val
                $Script:Ui.StatusLabel.Text = "Copied: $val"
            }
        }
    })

    # Explain the RESP.TIME values that aren't a plain millisecond number:
    # "ARP" means the host didn't answer ping but was found in the ARP
    # cache, and "DHCP" means it only answered a DHCP broadcast/UDP probe.
    $grid.ShowCellToolTips = $true
    $grid.Add_CellToolTipTextNeeded({
        param($s, $e)
        if ($e.RowIndex -ge 0 -and $e.ColumnIndex -eq $Script:Ui.Grid.Columns['Resp'].Index) {
            $val = $Script:Ui.Grid.Rows[$e.RowIndex].Cells[$e.ColumnIndex].Value
            if ($val -eq 'ARP') {
                $e.ToolTipText = "This host did not reply to an ICMP ping (often blocked by a firewall), but was found in the ARP cache, so it is shown online without a round-trip time."
            } elseif ($val -eq 'DHCP') {
                $e.ToolTipText = "This host did not answer ping or show up in the ARP cache, but it did answer a DHCP broadcast/UDP probe, so no round-trip time is available."
            }
        }
    })

    $gridHeaderPanel = New-Object Windows.Forms.Panel
    $gridHeaderPanel.Dock = 'Top'; $gridHeaderPanel.Height = 36
    $outerSplit.Panel1.Controls.Add($gridHeaderPanel); $Script:Ui.GridHeaderPanel = $gridHeaderPanel

    $gridHeaderLabel = New-Object Windows.Forms.Label
    $gridHeaderLabel.Text = "Scan Results"
    $gridHeaderLabel.Font = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold)
    $gridHeaderLabel.AutoSize = $true
    $gridHeaderLabel.Location = New-Object Drawing.Point(10,8)
    $gridHeaderPanel.Controls.Add($gridHeaderLabel); $Script:Ui.GridHeaderLabel = $gridHeaderLabel

    $countBadge = New-Object Windows.Forms.Label
    $countBadge.Text = "0 devices"
    $countBadge.AutoSize = $true
    $countBadge.Location = New-Object Drawing.Point(150,10)
    $gridHeaderPanel.Controls.Add($countBadge); $Script:Ui.CountBadge = $countBadge

    $btnClear = New-Object Windows.Forms.Button
    $btnClear.Text = "Clear"
    $btnClear.Width = 70; $btnClear.Height = 24
    $btnClear.FlatStyle = 'Flat'; $btnClear.FlatAppearance.BorderSize = 1
    $btnClear.Anchor = 'Top,Right'
    $btnClear.Location = New-Object Drawing.Point(10,6)
    $btnClear.Add_Click({
        $Script:Results.Clear()
        $Script:Ui.Grid.Rows.Clear()
        $Script:Ui.CountBadge.Text = "0 devices"
        $Script:Ui.LogBox.Clear()
    })
    $gridHeaderPanel.Controls.Add($btnClear)
    $Script:Ui.BtnClear = $btnClear
    $gridHeaderPanel.Add_SizeChanged({
        $Script:Ui.BtnClear.Location = New-Object Drawing.Point(($Script:Ui.GridHeaderPanel.Width - 90),6)
    })

    # --- BOTTOM-LEFT: scan log (with progress bar above it) ---
    $logBox = New-Object Windows.Forms.RichTextBox
    $logBox.Dock = 'Fill'
    $logBox.ReadOnly = $true
    $logBox.BorderStyle = 'None'
    $logBox.ScrollBars = 'Vertical'
    $logBox.Font = New-Object Drawing.Font('Consolas', 9)
    $bottomSplit.Panel1.Controls.Add($logBox); $Script:Ui.LogBox = $logBox

    $logHeaderPanel = New-Object Windows.Forms.Panel
    $logHeaderPanel.Dock = 'Top'; $logHeaderPanel.Height = 28
    $bottomSplit.Panel1.Controls.Add($logHeaderPanel); $Script:Ui.LogHeaderPanel = $logHeaderPanel
    $logHeaderLabel = New-Object Windows.Forms.Label
    $logHeaderLabel.Text = "Scan Log"
    $logHeaderLabel.Font = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)
    $logHeaderLabel.AutoSize = $true
    $logHeaderLabel.Location = New-Object Drawing.Point(10,6)
    $logHeaderPanel.Controls.Add($logHeaderLabel); $Script:Ui.LogHeaderLabel = $logHeaderLabel

    $progress = New-Object Windows.Forms.ProgressBar
    $progress.Dock = 'Top'; $progress.Height = 8
    $bottomSplit.Panel1.Controls.Add($progress); $Script:Ui.Progress = $progress

    # --- BOTTOM-RIGHT: Network Info ---
    $netInfoBox = New-Object Windows.Forms.RichTextBox
    $netInfoBox.Dock = 'Fill'
    $netInfoBox.ReadOnly = $true
    $netInfoBox.BorderStyle = 'None'
    $netInfoBox.ScrollBars = 'Vertical'
    $netInfoBox.Font = New-Object Drawing.Font('Consolas', 9)
    $bottomSplit.Panel2.Controls.Add($netInfoBox); $Script:Ui.NetInfoBox = $netInfoBox

    $netInfoHeaderPanel = New-Object Windows.Forms.Panel
    $netInfoHeaderPanel.Dock = 'Top'; $netInfoHeaderPanel.Height = 28
    $bottomSplit.Panel2.Controls.Add($netInfoHeaderPanel); $Script:Ui.NetInfoHeaderPanel = $netInfoHeaderPanel
    $netInfoHeaderLabel = New-Object Windows.Forms.Label
    $netInfoHeaderLabel.Text = "Network Info"
    $netInfoHeaderLabel.Font = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)
    $netInfoHeaderLabel.AutoSize = $true
    $netInfoHeaderLabel.Location = New-Object Drawing.Point(10,6)
    $netInfoHeaderPanel.Controls.Add($netInfoHeaderLabel); $Script:Ui.NetInfoHeaderLabel = $netInfoHeaderLabel

    # Interface selection autofill
    $combo.Add_SelectedIndexChanged({
        $sel = $Script:Ui.Combo.SelectedItem
        if ($sel) {
            $Script:Ui.TxtFrom.Text = $sel.From
            $Script:Ui.TxtTo.Text   = $sel.To
        }
    })

    # Add controls to the form in this exact order. WinForms processes
    # Dock='Top'/'Bottom' panels in the order they were added, with each
    # new one taking the space closest to its edge - so adding Fill content
    # first, then Bottom, then Top (toolbar, header, menu added last-to-be-topmost)
    # produces, from top to bottom: Menu, Header, Toolbar, [Fill split], StatusBar.
    $form.Controls.Add($outerSplit)
    $form.Controls.Add($statusPanel)
    $form.Controls.Add($toolbar)
    $form.Controls.Add($header)
    $form.Controls.Add($menu)

    # Sizing - this MUST happen after the split containers are added to the
    # form. Before that, $outerSplit/$bottomSplit still have their default
    # tiny WinForms size (not the form's real size), so SplitterDistance and
    # especially Panel1MinSize/Panel2MinSize calculations would be based on
    # the wrong dimensions and throw "SplitterDistance must be between..."
    try {
        # outerSplit is Horizontal -> splits TOP/BOTTOM, so distance is measured
        # vertically. Panel1 (grid) gets ~60% of the height.
        $sh = if ($outerSplit.Height -gt 300) { $outerSplit.Height } else { $form.ClientSize.Height }
        $outerSplit.SplitterDistance = [int]($sh * 0.6)
        $outerSplit.Panel1MinSize = 200
        $outerSplit.Panel2MinSize = 180
    } catch { Write-AppLog "Could not configure outer split sizing: $($_.Exception.Message)" "WARN" }
    try {
        # bottomSplit is Vertical -> splits LEFT/RIGHT, so distance is measured
        # horizontally. Panel1 (log) gets ~55% of the width, Panel2 (net info) the rest.
        $bw = if ($bottomSplit.Width -gt 400) { $bottomSplit.Width } else { $form.Width }
        $bottomSplit.SplitterDistance = [int]($bw * 0.55)
        $bottomSplit.Panel1MinSize = 250
        $bottomSplit.Panel2MinSize = 250
    } catch { Write-AppLog "Could not configure bottom split sizing: $($_.Exception.Message)" "WARN" }

    # --- Tooltips for the main window controls ---
    $mainTip = New-Object Windows.Forms.ToolTip
    $mainTip.AutoPopDelay = 15000; $mainTip.InitialDelay = 400; $mainTip.ReshowDelay = 100
    $mainTip.SetToolTip($txtFrom, "First IPv4 address of the range to scan (e.g. 192.168.1.1).")
    $mainTip.SetToolTip($txtTo, "Last IPv4 address of the range to scan. Must be in the same /24 subnet as 'From'.")
    $mainTip.SetToolTip($combo, "Pick a network adapter to automatically fill the From/To fields with its subnet range.")
    $mainTip.SetToolTip($btnSettings, "Configure ping/TCP timeouts, thread count, which ports to scan, hostname/MAC resolution, and DHCP detection options.")
    $mainTip.SetToolTip($btnNmap, "Check for or download nmap right now, without starting a scan. nmap enables DHCP broadcast discovery and faster, more accurate port scanning.")
    $mainTip.SetToolTip($btnScan, "Start scanning the selected IP range. The first scan will check whether nmap is installed and offer to download it if missing.")
    $mainTip.SetToolTip($btnStop, "Stop the scan currently in progress.")
    $mainTip.SetToolTip($btnExport, "Save the current scan results to a CSV file.")
    $mainTip.SetToolTip($themeBtn, "Switch between light and dark color themes.")
    $mainTip.SetToolTip($nmapLbl, "Shows whether nmap was found. nmap enables faster scanning, DHCP broadcast discovery, and more accurate port detection. It is only checked when you click Start Scanning.")
    $mainTip.SetToolTip($grid, "Live results of the current/last scan. VENDOR shows the manufacturer identified from the MAC address (OUI lookup). DHCP SERVER column shows YES (CHECK!) for any unexpected DHCP server found - this usually means a rogue DHCP server on the network. Right-click a row to copy its IP, MAC, hostname, connect via RDP, or open a Ping Monitor/Traceroute. Double-click any cell to copy just that value.")
    $mainTip.SetToolTip($btnClear, "Clear the results table and the scan log.")
    $Script:Ui.MainTip = $mainTip

    Write-AppLog "Main form built OK"
    return $form
}

# ============================================================
# SETTINGS DIALOG
# ============================================================
function Show-SettingsDialog {
    Write-AppLog "Opening Settings dialog"
    $f = New-Object Windows.Forms.Form
    $f.Text = "Scan Settings"
    $f.Width = 720; $f.Height = 760
    $f.MinimumSize = New-Object Drawing.Size(620, 560)
    $f.StartPosition = 'CenterParent'
    $f.FormBorderStyle = 'Sizable'
    $f.MaximizeBox = $true; $f.MinimizeBox = $false
    $t = Get-Theme
    $f.BackColor = $t.Card
    $tip = New-Object Windows.Forms.ToolTip
    $tip.AutoPopDelay = 15000; $tip.InitialDelay = 300; $tip.ReshowDelay = 100

    $btnPanel = New-Object Windows.Forms.Panel
    $btnPanel.Dock = 'Bottom'; $btnPanel.Height = 56
    $f.Controls.Add($btnPanel)

    $tabs = New-Object Windows.Forms.TabControl
    $tabs.Dock = 'Fill'
    $f.Controls.Add($tabs)

    # ======================= General =======================
    $tabGen = New-Object Windows.Forms.TabPage; $tabGen.Text = "General"

    $l0 = New-Object Windows.Forms.Label; $l0.Text = "Max. threads"; $l0.AutoSize=$true; $l0.Location = New-Object Drawing.Point(16,18)
    $tabGen.Controls.Add($l0)
    $tbThreads = New-Object Windows.Forms.TextBox; $tbThreads.Text = $Script:Settings.MaxThreads; $tbThreads.Width=100
    $tbThreads.Location = New-Object Drawing.Point(220,15); $tabGen.Controls.Add($tbThreads)
    $tip.SetToolTip($tbThreads, "How many hosts can be checked in parallel during a scan. Higher values scan faster but use more CPU/network resources. 50 is a safe default for most networks.")

    $l1 = New-Object Windows.Forms.Label; $l1.Text = "Ping timeout (ms)"; $l1.AutoSize=$true; $l1.Location = New-Object Drawing.Point(16,54)
    $tabGen.Controls.Add($l1)
    $tbPing = New-Object Windows.Forms.TextBox; $tbPing.Text = $Script:Settings.PingTimeoutMs; $tbPing.Width=100
    $tbPing.Location = New-Object Drawing.Point(220,51); $tabGen.Controls.Add($tbPing)
    $tip.SetToolTip($tbPing, "How long to wait for a ping (ICMP) reply before considering a host offline. Lower values scan faster but may miss slow-responding devices. 100-300 ms works well on local networks.")

    $l2 = New-Object Windows.Forms.Label; $l2.Text = "TCP connect timeout (ms)"; $l2.AutoSize=$true; $l2.Location = New-Object Drawing.Point(16,90)
    $tabGen.Controls.Add($l2)
    $tbTcp = New-Object Windows.Forms.TextBox; $tbTcp.Text = $Script:Settings.TcpTimeoutMs; $tbTcp.Width=100
    $tbTcp.Location = New-Object Drawing.Point(220,87); $tabGen.Controls.Add($tbTcp)
    $tip.SetToolTip($tbTcp, "How long to wait when checking if a TCP port is open. Lower values scan faster but may report open ports as closed on slow links.")

    $l3 = New-Object Windows.Forms.Label; $l3.Text = "Ping method"; $l3.AutoSize=$true; $l3.Location = New-Object Drawing.Point(16,128)
    $tabGen.Controls.Add($l3)
    $cmbPingMethod = New-Object Windows.Forms.ComboBox
    $cmbPingMethod.DropDownStyle = 'DropDownList'; $cmbPingMethod.Width = 200
    [void]$cmbPingMethod.Items.Add('ICMP only')
    [void]$cmbPingMethod.Items.Add('ARP only')
    [void]$cmbPingMethod.Items.Add('Both ICMP and ARP')
    $cmbPingMethod.SelectedIndex = switch ($Script:Settings.PingMethod) { 'ICMP' {0} 'ARP' {1} default {2} }
    $cmbPingMethod.Location = New-Object Drawing.Point(220,124)
    $tabGen.Controls.Add($cmbPingMethod)
    $tip.SetToolTip($cmbPingMethod, "How to detect whether a host is alive. ICMP (ping) is fast but can be blocked by firewalls. ARP also catches hosts that block ping. Both gives the most complete results.")

    $cbShowOffline = New-Object Windows.Forms.CheckBox
    $cbShowOffline.Text = "Show devices that did not respond"
    $cbShowOffline.AutoSize = $true
    $cbShowOffline.Checked = $Script:Settings.ShowOffline
    $cbShowOffline.Location = New-Object Drawing.Point(16,168)
    $tabGen.Controls.Add($cbShowOffline)
    $tip.SetToolTip($cbShowOffline, "When checked, hosts that did not answer ping/ARP are still listed in the results table (marked offline). Useful for seeing the full address range, not just live hosts.")

    [void]$tabs.TabPages.Add($tabGen)

    # ======================= Resolve =======================
    $tabRes = New-Object Windows.Forms.TabPage; $tabRes.Text = "Resolve"
    $cbHost = New-Object Windows.Forms.CheckBox
    $cbHost.Text = "Resolve host names (reverse DNS)"; $cbHost.AutoSize = $true
    $cbHost.Checked = $Script:Settings.ResolveHostname
    $cbHost.Location = New-Object Drawing.Point(16,20)
    $tabRes.Controls.Add($cbHost)
    $tip.SetToolTip($cbHost, "Look up the DNS host name for each live IP address. Adds a small delay per host but makes results much easier to read.")

    $cbMac = New-Object Windows.Forms.CheckBox
    $cbMac.Text = "Resolve MAC addresses (ARP)"; $cbMac.AutoSize = $true
    $cbMac.Checked = $Script:Settings.ResolveMac
    $cbMac.Location = New-Object Drawing.Point(16,52)
    $tabRes.Controls.Add($cbMac)
    $tip.SetToolTip($cbMac, "Look up the hardware (MAC) address of each live host from the ARP cache. Needed to identify the manufacturer/vendor and to track devices that change IP.")

    $cbVendor = New-Object Windows.Forms.CheckBox
    $cbVendor.Text = "Lookup network card vendor (from MAC)"; $cbVendor.AutoSize = $true
    $cbVendor.Checked = $Script:Settings.ResolveVendor
    $cbVendor.Location = New-Object Drawing.Point(16,84)
    $tabRes.Controls.Add($cbVendor)
    $tip.SetToolTip($cbVendor, "Identify the device manufacturer (e.g. 'Routerboard', 'HP Inc.') from the first half of its MAC address (OUI), using the IEEE database stored in oui.txt next to this script. Use Tools > Update NIC Vendor Database to refresh it.")

    [void]$tabs.TabPages.Add($tabRes)

    # ======================= Ports =======================
    $tabPorts = New-Object Windows.Forms.TabPage; $tabPorts.Text = "Ports"
    $portsScroll = New-Object Windows.Forms.Panel
    $portsScroll.Dock = 'Fill'; $portsScroll.AutoScroll = $true
    $tabPorts.Controls.Add($portsScroll)

    $lp = New-Object Windows.Forms.Label
    $lp.Text = "Check for open TCP ports - tick the ones you want scanned:"
    $lp.AutoSize = $true; $lp.Font = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)
    $lp.Location = New-Object Drawing.Point(10,8)
    $portsScroll.Controls.Add($lp)

    $btnAllPorts = New-Object Windows.Forms.Button
    $btnAllPorts.Text = "Select All"; $btnAllPorts.Width = 90; $btnAllPorts.Height = 22
    $btnAllPorts.FlatStyle = 'Flat'; $btnAllPorts.FlatAppearance.BorderSize = 1
    $btnAllPorts.Location = New-Object Drawing.Point(440,4)
    $portsScroll.Controls.Add($btnAllPorts)
    $tip.SetToolTip($btnAllPorts, "Tick every port in the list below.")

    $btnNonePorts = New-Object Windows.Forms.Button
    $btnNonePorts.Text = "Select None"; $btnNonePorts.Width = 90; $btnNonePorts.Height = 22
    $btnNonePorts.FlatStyle = 'Flat'; $btnNonePorts.FlatAppearance.BorderSize = 1
    $btnNonePorts.Location = New-Object Drawing.Point(535,4)
    $portsScroll.Controls.Add($btnNonePorts)
    $tip.SetToolTip($btnNonePorts, "Untick every port in the list below.")

    $portCheckboxes = @{}
    $colCount = 4
    $colWidth = 150
    $rowHeight = 26
    $i = 0
    foreach ($p in ($Script:AllKnownPorts | Sort-Object)) {
        $col = $i % $colCount
        $row = [int]($i / $colCount)
        $cb = New-Object Windows.Forms.CheckBox
        $name = $Script:PortNames[$p]
        $cb.Text = if ($name -and $name -ne 'Custom') { "$p ($name)" } else { "$p" }
        $cb.AutoSize = $true
        $cb.Checked = $Script:EnabledPorts.Contains($p)
        $cb.Location = New-Object Drawing.Point((14 + $col*$colWidth), (40 + $row*$rowHeight))
        $tip.SetToolTip($cb, "Port $p ($name). When ticked, this port is checked on every live host found during the scan.")
        $portsScroll.Controls.Add($cb)
        $portCheckboxes[$p] = $cb
        $i++
    }
    $btnAllPorts.Add_Click({ foreach ($k in $portCheckboxes.Keys) { $portCheckboxes[$k].Checked = $true } })
    $btnNonePorts.Add_Click({ foreach ($k in $portCheckboxes.Keys) { $portCheckboxes[$k].Checked = $false } })

    $lastRow = [int](($Script:AllKnownPorts.Count - 1) / $colCount)
    $customY = 40 + ($lastRow + 1) * $rowHeight + 16

    $lblCustomPorts = New-Object Windows.Forms.Label
    $lblCustomPorts.Text = "Custom ports (comma-separated, e.g. 3,5,2555,6789):"
    $lblCustomPorts.AutoSize = $true
    $lblCustomPorts.Location = New-Object Drawing.Point(10,$customY)
    $portsScroll.Controls.Add($lblCustomPorts)

    $tbCustomPorts = New-Object Windows.Forms.TextBox
    $tbCustomPorts.Width = 400
    $tbCustomPorts.Text = $Script:Settings.CustomPortsText
    $tbCustomPorts.Location = New-Object Drawing.Point(10,($customY+20))
    $portsScroll.Controls.Add($tbCustomPorts)
    $tip.SetToolTip($tbCustomPorts, "Extra TCP ports to scan that aren't in the checklist above. Separate multiple ports with commas, e.g. 3,5,2555,6789. These are checked on every live host in addition to the ticked checkboxes.")

    $udpY = $customY + 56

    $sepLbl = New-Object Windows.Forms.Label
    $sepLbl.Text = "Check for open UDP ports:"
    $sepLbl.AutoSize = $true; $sepLbl.Font = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)
    $sepLbl.Location = New-Object Drawing.Point(10,$udpY)
    $portsScroll.Controls.Add($sepLbl)

    $cbUdpDhcp = New-Object Windows.Forms.CheckBox
    $cbUdpDhcp.Text = "UDP/67 (DHCP) - rogue DHCP server detection"; $cbUdpDhcp.AutoSize = $true
    $cbUdpDhcp.Checked = $Script:Settings.UdpDhcpCheck
    $cbUdpDhcp.Location = New-Object Drawing.Point(10,($udpY+24))
    $portsScroll.Controls.Add($cbUdpDhcp)
    $tip.SetToolTip($cbUdpDhcp, "Probe UDP port 67 on every live host. Any host that has this port open is acting as a DHCP server and will be flagged in the DHCP SERVER column - this is the main rogue DHCP detection check.")

    [void]$tabs.TabPages.Add($tabPorts)

    # ======================= DHCP Detection =======================
    $tabDhcp = New-Object Windows.Forms.TabPage; $tabDhcp.Text = "DHCP Detection"
    $cbBroadcast = New-Object Windows.Forms.CheckBox
    $cbBroadcast.Text = "Send DHCP DISCOVER broadcast (requires nmap)"; $cbBroadcast.AutoSize = $true
    $cbBroadcast.Checked = $Script:Settings.DhcpBroadcast
    $cbBroadcast.Location = New-Object Drawing.Point(16,16)
    $tabDhcp.Controls.Add($cbBroadcast)
    $tip.SetToolTip($cbBroadcast, "Broadcasts a real DHCP DISCOVER packet on the network (like a PC asking for an IP address) and records every DHCP server that answers with an OFFER. The most reliable way to find rogue DHCP servers, but requires nmap.")

    $lk = New-Object Windows.Forms.Label
    $lk.Text = "Authorized DHCP IPs (whitelist, comma separated)"; $lk.AutoSize = $true
    $lk.Location = New-Object Drawing.Point(16,56)
    $tabDhcp.Controls.Add($lk)
    $tbKnown = New-Object Windows.Forms.TextBox
    $tbKnown.Text = ($Script:KnownDhcp -join ', ')
    $tbKnown.Width = 460; $tbKnown.Location = New-Object Drawing.Point(16,80)
    $tabDhcp.Controls.Add($tbKnown)
    $tip.SetToolTip($tbKnown, "IP addresses of your legitimate, expected DHCP servers (e.g. your router or Windows DHCP server). Any other DHCP server found during the scan will be flagged as 'YES (CHECK!)' instead of 'YES (AUTHORIZED)'.")

    $infoLbl = New-Object Windows.Forms.Label
    $infoLbl.Text = "Devices that answer DHCP DISCOVER or have UDP/67 open are flagged in the DHCP SERVER column."
    $infoLbl.AutoSize = $false; $infoLbl.Width = 460; $infoLbl.Height = 50
    $infoLbl.ForeColor = [Drawing.Color]::Gray
    $infoLbl.Location = New-Object Drawing.Point(16,120)
    $tabDhcp.Controls.Add($infoLbl)
    [void]$tabs.TabPages.Add($tabDhcp)

    # ======================= Buttons =======================
    $btnOk = New-Object Windows.Forms.Button
    $btnOk.Text = "OK"; $btnOk.Width = 90; $btnOk.Height = 32
    $btnOk.Location = New-Object Drawing.Point(($f.Width - 220),12)
    $btnOk.Anchor = 'Top,Right'
    $btnOk.Add_Click({
        $Script:Settings.MaxThreads      = [int]($tbThreads.Text -as [int]); if ($Script:Settings.MaxThreads -lt 1) { $Script:Settings.MaxThreads = 50 }
        $Script:Settings.PingTimeoutMs   = [int]($tbPing.Text -as [int]); if ($Script:Settings.PingTimeoutMs -lt 10) { $Script:Settings.PingTimeoutMs = 300 }
        $Script:Settings.TcpTimeoutMs    = [int]($tbTcp.Text -as [int]);  if ($Script:Settings.TcpTimeoutMs -lt 10)  { $Script:Settings.TcpTimeoutMs = 400 }
        $Script:Settings.PingMethod      = switch ($cmbPingMethod.SelectedIndex) { 0 {'ICMP'} 1 {'ARP'} default {'Both'} }
        $Script:Settings.ShowOffline     = $cbShowOffline.Checked
        $Script:Settings.ResolveHostname = $cbHost.Checked
        $Script:Settings.ResolveMac      = $cbMac.Checked
        $Script:Settings.ResolveVendor   = $cbVendor.Checked
        $Script:Settings.UdpDhcpCheck    = $cbUdpDhcp.Checked
        $Script:Settings.DhcpBroadcast   = $cbBroadcast.Checked
        $Script:EnabledPorts.Clear()
        foreach ($k in $portCheckboxes.Keys) { if ($portCheckboxes[$k].Checked) { [void]$Script:EnabledPorts.Add($k) } }
        $Script:Settings.CustomPortsText = $tbCustomPorts.Text
        $tbCustomPorts.Text -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object {
            $cp = $_ -as [int]
            if ($cp -and $cp -gt 0 -and $cp -le 65535) { [void]$Script:EnabledPorts.Add($cp) }
        }
        $Script:KnownDhcp.Clear()
        $tbKnown.Text -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { [void]$Script:KnownDhcp.Add($_.Trim()) }
        Write-AppLog "Settings saved. Enabled ports: $($Script:EnabledPorts -join ',')"
        $f.DialogResult = 'OK'; $f.Close()
    })
    $btnPanel.Controls.Add($btnOk)

    $btnCancel = New-Object Windows.Forms.Button
    $btnCancel.Text = "Cancel"; $btnCancel.Width = 90; $btnCancel.Height = 32
    $btnCancel.Location = New-Object Drawing.Point(($f.Width - 120),12)
    $btnCancel.Anchor = 'Top,Right'
    $btnCancel.Add_Click({ $f.DialogResult = 'Cancel'; $f.Close() })
    $btnPanel.Controls.Add($btnCancel)

    [void]$f.ShowDialog($Script:Ui.Form)
}

# ============================================================
# PING MONITOR (standalone ping tool window)
# ============================================================
function Stop-MonitorProcess {
    param($State, $BtnStart, $BtnStop, $LblStatus)
    if ($null -eq $State) { return }
    if ($State.PollTimer) {
        try { $State.PollTimer.Stop(); $State.PollTimer.Dispose() } catch { }
        $State.PollTimer = $null
    }
    if ($State.Proc -and -not $State.Proc.HasExited) {
        try { $State.Proc.Kill() } catch { }
    }
    if ($State.SubIds) {
        foreach ($sid in $State.SubIds) { try { Unregister-Event -SourceIdentifier $sid -ErrorAction SilentlyContinue } catch { } }
    }
    $State.SubIds = @()
    $State.Running = $false
    if ($State.OutFile) {
        Start-Sleep -Milliseconds 100
        try { Remove-Item $State.OutFile -ErrorAction SilentlyContinue } catch { }
    }
    if ($BtnStart -and $BtnStart.IsHandleCreated) { try { $BtnStart.Enabled = $true } catch { } }
    if ($BtnStop -and $BtnStop.IsHandleCreated) { try { $BtnStop.Enabled = $false } catch { } }
    if ($LblStatus -and $LblStatus.IsHandleCreated) { try { $LblStatus.Invoke([Action]{ $LblStatus.Text = "Stopped" }) } catch { } }
}

function Show-PingMonitorWindow {
    param([string]$Target)

    $t = Get-Theme
    $f = New-Object Windows.Forms.Form
    $f.Text = "Ping Monitor"
    $f.Width = 680; $f.Height = 620
    $f.MinimumSize = New-Object Drawing.Size(560, 420)
    $f.StartPosition = 'CenterParent'
    $f.BackColor = $t.Card
    $f.Font = New-Object Drawing.Font('Segoe UI', 9)

    # Each Ping Monitor window owns its own process handle and a flag the
    # Stop button and the form-close handler both check, so closing the
    # window always cleans up the background ping.exe process rather than
    # leaving it running.
    $state = @{ Proc = $null; Running = $false }

    # --- Target row (above the options box, full width) ---
    $lblTarget = New-Object Windows.Forms.Label
    $lblTarget.Text = "Target"; $lblTarget.AutoSize = $true
    $lblTarget.Location = New-Object Drawing.Point(16,18)
    $f.Controls.Add($lblTarget)
    $tbTarget = New-Object Windows.Forms.TextBox
    $tbTarget.Text = $Target; $tbTarget.Width = 200
    $tbTarget.Location = New-Object Drawing.Point(16,38)
    $f.Controls.Add($tbTarget)

    $btnStart = New-FlatButton -Text "Start" -Color $t.Blue -Width 110 -Height 34
    $btnStart.Location = New-Object Drawing.Point(540,18)
    $btnStart.Anchor = 'Top,Right'
    $f.Controls.Add($btnStart)
    $btnStop = New-FlatButton -Text "Stop" -Color $t.Red -Width 110 -Height 34
    $btnStop.Location = New-Object Drawing.Point(540,56)
    $btnStop.Anchor = 'Top,Right'
    $btnStop.Enabled = $false
    $f.Controls.Add($btnStop)

    # --- Options group box ---
    $grpOptions = New-Object Windows.Forms.GroupBox
    $grpOptions.Text = "Options"
    $grpOptions.Location = New-Object Drawing.Point(16,76)
    $grpOptions.Size = New-Object Drawing.Size(508,108)
    $grpOptions.Anchor = 'Top,Left,Right'
    $f.Controls.Add($grpOptions)

    # Column 1: continuous / count
    $cbContinuous = New-Object Windows.Forms.CheckBox
    $cbContinuous.Text = "Continuous (-t)"; $cbContinuous.AutoSize = $true
    $cbContinuous.Checked = $true
    $cbContinuous.Location = New-Object Drawing.Point(14,24)
    $grpOptions.Controls.Add($cbContinuous)
    $lblCount = New-Object Windows.Forms.Label
    $lblCount.Text = "Count (-n)"; $lblCount.AutoSize = $true
    $lblCount.Location = New-Object Drawing.Point(14,54)
    $grpOptions.Controls.Add($lblCount)
    $tbCount = New-Object Windows.Forms.TextBox
    $tbCount.Text = "4"; $tbCount.Width = 60; $tbCount.Enabled = $false
    $tbCount.Location = New-Object Drawing.Point(96,51)
    $grpOptions.Controls.Add($tbCount)
    $cbContinuous.Add_CheckedChanged({ $tbCount.Enabled = -not $cbContinuous.Checked }.GetNewClosure())

    # Column 2: buffer size / timeout
    $lblSize = New-Object Windows.Forms.Label
    $lblSize.Text = "Buffer size (-l)"; $lblSize.AutoSize = $true
    $lblSize.Location = New-Object Drawing.Point(180,24)
    $grpOptions.Controls.Add($lblSize)
    $tbSize = New-Object Windows.Forms.TextBox
    $tbSize.Text = "32"; $tbSize.Width = 70
    $tbSize.Location = New-Object Drawing.Point(280,21)
    $grpOptions.Controls.Add($tbSize)
    $lblTimeout = New-Object Windows.Forms.Label
    $lblTimeout.Text = "Timeout ms (-w)"; $lblTimeout.AutoSize = $true
    $lblTimeout.Location = New-Object Drawing.Point(180,54)
    $grpOptions.Controls.Add($lblTimeout)
    $tbTimeout = New-Object Windows.Forms.TextBox
    $tbTimeout.Text = "1000"; $tbTimeout.Width = 70
    $tbTimeout.Location = New-Object Drawing.Point(280,51)
    $grpOptions.Controls.Add($tbTimeout)

    # Column 3: flags / IP version
    $cbResolve = New-Object Windows.Forms.CheckBox
    $cbResolve.Text = "Resolve addresses (-a)"; $cbResolve.AutoSize = $true
    $cbResolve.Location = New-Object Drawing.Point(370,24)
    $grpOptions.Controls.Add($cbResolve)
    $cbDontFrag = New-Object Windows.Forms.CheckBox
    $cbDontFrag.Text = "Don't fragment (-f)"; $cbDontFrag.AutoSize = $true
    $cbDontFrag.Location = New-Object Drawing.Point(370,48)
    $grpOptions.Controls.Add($cbDontFrag)

    $lblIpVer = New-Object Windows.Forms.Label
    $lblIpVer.Text = "IP version"; $lblIpVer.AutoSize = $true
    $lblIpVer.Location = New-Object Drawing.Point(14,82)
    $grpOptions.Controls.Add($lblIpVer)
    $cmbIpVer = New-Object Windows.Forms.ComboBox
    $cmbIpVer.DropDownStyle = 'DropDownList'; $cmbIpVer.Width = 150
    [void]$cmbIpVer.Items.Add('Auto')
    [void]$cmbIpVer.Items.Add('Force IPv4 (-4)')
    [void]$cmbIpVer.Items.Add('Force IPv6 (-6)')
    $cmbIpVer.SelectedIndex = 0
    $cmbIpVer.Location = New-Object Drawing.Point(96,79)
    $grpOptions.Controls.Add($cmbIpVer)

    # --- Output area ---
    $lblOutput = New-Object Windows.Forms.Label
    $lblOutput.Text = "Output"
    $lblOutput.Font = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)
    $lblOutput.AutoSize = $true
    $lblOutput.Location = New-Object Drawing.Point(16,192)
    $f.Controls.Add($lblOutput)

    $outBox = New-Object Windows.Forms.RichTextBox
    $outBox.Location = New-Object Drawing.Point(16,214)
    $outBox.Size = New-Object Drawing.Size(634,330)
    $outBox.ReadOnly = $true
    $outBox.ScrollBars = 'Vertical'
    $outBox.BorderStyle = 'FixedSingle'
    $outBox.Font = New-Object Drawing.Font('Consolas', 9)
    $outBox.Anchor = 'Top,Bottom,Left,Right'
    $f.Controls.Add($outBox)

    $lblStatus = New-Object Windows.Forms.Label
    $lblStatus.Text = "Ready"
    $lblStatus.AutoSize = $true
    $lblStatus.Anchor = 'Bottom,Left'
    $lblStatus.Location = New-Object Drawing.Point(16,552)
    $f.Controls.Add($lblStatus)

    $state.SubIds = @()

    $btnStart.Add_Click({
        if ($state.Running) { return }
        $tgt = $tbTarget.Text.Trim()
        if (-not $tgt) { return }

        $argList = New-Object System.Collections.Generic.List[string]
        if ($cbContinuous.Checked) {
            $argList.Add('-t')
        } else {
            $n = [int]($tbCount.Text -as [int]); if ($n -lt 1) { $n = 4 }
            $argList.Add('-n'); $argList.Add("$n")
        }
        if ($cbResolve.Checked) { $argList.Add('-a') }
        if ($cbDontFrag.Checked) { $argList.Add('-f') }
        $size = [int]($tbSize.Text -as [int]); if ($size -gt 0) { $argList.Add('-l'); $argList.Add("$size") }
        $timeout = [int]($tbTimeout.Text -as [int]); if ($timeout -gt 0) { $argList.Add('-w'); $argList.Add("$timeout") }
        switch ($cmbIpVer.SelectedIndex) { 1 { $argList.Add('-4') } 2 { $argList.Add('-6') } }
        $argList.Add($tgt)

        $outBox.Clear()
        $lblStatus.Text = "Running: ping $($argList -join ' ')"
        Write-AppLog "Ping Monitor started: ping $($argList -join ' ')"

        # Redirect output to a temp file via cmd.exe rather than reading
        # the process's redirected streams directly - .NET Process
        # OutputDataReceived/BeginOutputReadLine has a documented
        # PowerShell interop issue that can throw unhandled errors, and
        # StreamReader.Peek()/ReadLine() can block the UI thread if called
        # from a Timer.Tick. Tailing a plain text file from a UI timer
        # avoids both: file reads are quick, never block waiting on a
        # live process, and ConvertFrom never throws on partial writes.
        $outFile = Join-Path $env:TEMP "pingmon_$([guid]::NewGuid().ToString('N')).log"
        Remove-Item $outFile -ErrorAction SilentlyContinue

        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = 'cmd.exe'
        $psi.Arguments = "/c ping $($argList -join ' ') > `"$outFile`" 2>&1"
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true

        $proc = New-Object Diagnostics.Process
        $proc.StartInfo = $psi
        [void]$proc.Start()
        $state.Proc = $proc
        $state.Running = $true
        $state.OutFile = $outFile

        $pollTimer = New-Object Windows.Forms.Timer
        $pollTimer.Interval = 250
        Add-Member -InputObject $pollTimer -NotePropertyName MonProc -NotePropertyValue $proc
        Add-Member -InputObject $pollTimer -NotePropertyName MonFile -NotePropertyValue $outFile
        Add-Member -InputObject $pollTimer -NotePropertyName MonPos -NotePropertyValue 0L
        Add-Member -InputObject $pollTimer -NotePropertyName MonOutBox -NotePropertyValue $outBox
        Add-Member -InputObject $pollTimer -NotePropertyName MonState -NotePropertyValue $state
        Add-Member -InputObject $pollTimer -NotePropertyName MonBtnStart -NotePropertyValue $btnStart
        Add-Member -InputObject $pollTimer -NotePropertyName MonBtnStop -NotePropertyValue $btnStop
        Add-Member -InputObject $pollTimer -NotePropertyName MonLblStatus -NotePropertyValue $lblStatus
        $pollTimer.Add_Tick({
            param($sender, $e)
            $p = $sender.MonProc
            $ob = $sender.MonOutBox
            try {
                if (Test-Path $sender.MonFile) {
                    $fs = [System.IO.File]::Open($sender.MonFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    try {
                        if ($fs.Length -gt $sender.MonPos) {
                            $fs.Seek($sender.MonPos, [System.IO.SeekOrigin]::Begin) | Out-Null
                            $buf = New-Object byte[] ($fs.Length - $sender.MonPos)
                            [void]$fs.Read($buf, 0, $buf.Length)
                            $text = [System.Text.Encoding]::Default.GetString($buf)
                            $sender.MonPos = $fs.Length
                            if ($text) {
                                $ob.AppendText($text)
                                $ob.SelectionStart = $ob.TextLength
                                $ob.ScrollToCaret()
                            }
                        }
                    } finally { $fs.Dispose() }
                }
            } catch { }
            if ($p.HasExited) {
                $sender.Stop()
                $sender.MonState.Running = $false
                $sender.MonBtnStart.Enabled = $true
                $sender.MonBtnStop.Enabled = $false
                $sender.MonLblStatus.Text = "Finished"
            }
        })
        $pollTimer.Start()
        $state.PollTimer = $pollTimer

        $btnStart.Enabled = $false
        $btnStop.Enabled = $true
    }.GetNewClosure())

    $btnStop.Add_Click({ Stop-MonitorProcess -State $state -BtnStart $btnStart -BtnStop $btnStop -LblStatus $lblStatus }.GetNewClosure())
    $f.Add_FormClosing({ Stop-MonitorProcess -State $state -BtnStart $btnStart -BtnStop $btnStop -LblStatus $lblStatus }.GetNewClosure())

    $f.Show($Script:Ui.Form)
}

# ============================================================
# TRACEROUTE (standalone window, nmap or tracert)
# ============================================================
function Show-TracerouteWindow {
    param([string]$Target)

    $t = Get-Theme
    $f = New-Object Windows.Forms.Form
    $f.Text = "Traceroute"
    $f.Width = 680; $f.Height = 560
    $f.MinimumSize = New-Object Drawing.Size(560, 380)
    $f.StartPosition = 'CenterParent'
    $f.BackColor = $t.Card
    $f.Font = New-Object Drawing.Font('Segoe UI', 9)

    $state = @{ Proc = $null; Running = $false }

    # --- Target row (above the options box, full width) ---
    $lblTarget = New-Object Windows.Forms.Label
    $lblTarget.Text = "Target"; $lblTarget.AutoSize = $true
    $lblTarget.Location = New-Object Drawing.Point(16,18)
    $f.Controls.Add($lblTarget)
    $tbTarget = New-Object Windows.Forms.TextBox
    $tbTarget.Text = $Target; $tbTarget.Width = 200
    $tbTarget.Location = New-Object Drawing.Point(16,38)
    $f.Controls.Add($tbTarget)

    $btnStart = New-FlatButton -Text "Start" -Color $t.Blue -Width 110 -Height 34
    $btnStart.Location = New-Object Drawing.Point(540,18)
    $btnStart.Anchor = 'Top,Right'
    $f.Controls.Add($btnStart)
    $btnStop = New-FlatButton -Text "Stop" -Color $t.Red -Width 110 -Height 34
    $btnStop.Location = New-Object Drawing.Point(540,56)
    $btnStop.Anchor = 'Top,Right'
    $btnStop.Enabled = $false
    $f.Controls.Add($btnStop)

    # --- Options group box ---
    $grpOptions = New-Object Windows.Forms.GroupBox
    $grpOptions.Text = "Options"
    $grpOptions.Location = New-Object Drawing.Point(16,76)
    $grpOptions.Size = New-Object Drawing.Size(508,56)
    $grpOptions.Anchor = 'Top,Left,Right'
    $f.Controls.Add($grpOptions)

    $cbUseNmap = New-Object Windows.Forms.CheckBox
    $cbUseNmap.Text = "Use nmap (uncheck for built-in tracert)"
    $cbUseNmap.AutoSize = $true
    $cbUseNmap.Checked = [bool]$Script:NmapPath
    $cbUseNmap.Enabled = [bool](Find-NmapPath)
    $cbUseNmap.Location = New-Object Drawing.Point(14,24)
    $grpOptions.Controls.Add($cbUseNmap)
    if (-not $cbUseNmap.Enabled) {
        $tipNoNmap = New-Object Windows.Forms.ToolTip
        $tipNoNmap.SetToolTip($cbUseNmap, "nmap was not found - using Windows tracert instead. Use the Get nmap button on the main window to install it.")
    }

    # --- Output area ---
    $lblOutput = New-Object Windows.Forms.Label
    $lblOutput.Text = "Output"
    $lblOutput.Font = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)
    $lblOutput.AutoSize = $true
    $lblOutput.Location = New-Object Drawing.Point(16,140)
    $f.Controls.Add($lblOutput)

    $outBox = New-Object Windows.Forms.RichTextBox
    $outBox.Location = New-Object Drawing.Point(16,162)
    $outBox.Size = New-Object Drawing.Size(634,330)
    $outBox.ReadOnly = $true
    $outBox.ScrollBars = 'Vertical'
    $outBox.BorderStyle = 'FixedSingle'
    $outBox.Font = New-Object Drawing.Font('Consolas', 9)
    $outBox.Anchor = 'Top,Bottom,Left,Right'
    $f.Controls.Add($outBox)

    $lblStatus = New-Object Windows.Forms.Label
    $lblStatus.Text = "Ready"
    $lblStatus.AutoSize = $true
    $lblStatus.Anchor = 'Bottom,Left'
    $lblStatus.Location = New-Object Drawing.Point(16,500)
    $f.Controls.Add($lblStatus)

    $state.SubIds = @()

    $btnStart.Add_Click({
        if ($state.Running) { return }
        $tgt = $tbTarget.Text.Trim()
        if (-not $tgt) { return }

        $useNmap = $cbUseNmap.Checked -and (Find-NmapPath)
        $exe = if ($useNmap) { Find-NmapPath } else { 'tracert.exe' }
        $args = if ($useNmap) { "--traceroute -Pn -p 80 $tgt" } else { "$tgt" }

        $outBox.Clear()
        $lblStatus.Text = "Running: $exe $args"
        Write-AppLog "Traceroute started: $exe $args"

        # Redirect output to a temp file via cmd.exe rather than reading
        # the process's redirected streams directly - see Ping Monitor
        # for the reasoning (documented PowerShell/Process interop issue
        # with OutputDataReceived, and Peek()/ReadLine() can block the UI
        # thread). Tailing a plain file from a UI timer avoids both.
        $outFile = Join-Path $env:TEMP "trace_$([guid]::NewGuid().ToString('N')).log"
        Remove-Item $outFile -ErrorAction SilentlyContinue

        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = 'cmd.exe'
        $psi.Arguments = '/c "' + '"' + $exe + '" ' + $args + ' > "' + $outFile + '" 2>&1' + '"'
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true

        $proc = New-Object Diagnostics.Process
        $proc.StartInfo = $psi
        [void]$proc.Start()
        $state.Proc = $proc
        $state.Running = $true
        $state.OutFile = $outFile

        $pollTimer = New-Object Windows.Forms.Timer
        $pollTimer.Interval = 250
        Add-Member -InputObject $pollTimer -NotePropertyName MonProc -NotePropertyValue $proc
        Add-Member -InputObject $pollTimer -NotePropertyName MonFile -NotePropertyValue $outFile
        Add-Member -InputObject $pollTimer -NotePropertyName MonPos -NotePropertyValue 0L
        Add-Member -InputObject $pollTimer -NotePropertyName MonOutBox -NotePropertyValue $outBox
        Add-Member -InputObject $pollTimer -NotePropertyName MonState -NotePropertyValue $state
        Add-Member -InputObject $pollTimer -NotePropertyName MonBtnStart -NotePropertyValue $btnStart
        Add-Member -InputObject $pollTimer -NotePropertyName MonBtnStop -NotePropertyValue $btnStop
        Add-Member -InputObject $pollTimer -NotePropertyName MonLblStatus -NotePropertyValue $lblStatus
        $pollTimer.Add_Tick({
            param($sender, $e)
            $p = $sender.MonProc
            $ob = $sender.MonOutBox
            try {
                if (Test-Path $sender.MonFile) {
                    $fs = [System.IO.File]::Open($sender.MonFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    try {
                        if ($fs.Length -gt $sender.MonPos) {
                            $fs.Seek($sender.MonPos, [System.IO.SeekOrigin]::Begin) | Out-Null
                            $buf = New-Object byte[] ($fs.Length - $sender.MonPos)
                            [void]$fs.Read($buf, 0, $buf.Length)
                            $text = [System.Text.Encoding]::Default.GetString($buf)
                            $sender.MonPos = $fs.Length
                            if ($text) {
                                $ob.AppendText($text)
                                $ob.SelectionStart = $ob.TextLength
                                $ob.ScrollToCaret()
                            }
                        }
                    } finally { $fs.Dispose() }
                }
            } catch { }
            if ($p.HasExited) {
                $sender.Stop()
                $sender.MonState.Running = $false
                $sender.MonBtnStart.Enabled = $true
                $sender.MonBtnStop.Enabled = $false
                $sender.MonLblStatus.Text = "Finished"
            }
        })
        $pollTimer.Start()
        $state.PollTimer = $pollTimer

        $btnStart.Enabled = $false
        $btnStop.Enabled = $true
    }.GetNewClosure())

    $btnStop.Add_Click({ Stop-MonitorProcess -State $state -BtnStart $btnStart -BtnStop $btnStop -LblStatus $lblStatus }.GetNewClosure())
    $f.Add_FormClosing({ Stop-MonitorProcess -State $state -BtnStart $btnStart -BtnStop $btnStop -LblStatus $lblStatus }.GetNewClosure())

    $f.Show($Script:Ui.Form)
}

# ============================================================
# ABOUT DIALOG
# ============================================================
function Show-AboutDialog {
    $f = New-Object Windows.Forms.Form
    $f.Text = "About Network Scanner"
    $f.Width = 600; $f.Height = 460
    $f.StartPosition = 'CenterParent'
    $f.FormBorderStyle = 'FixedDialog'
    $f.MaximizeBox = $false; $f.MinimizeBox = $false

    $title = New-Object Windows.Forms.Label
    $title.Text = "Network Scanner"
    $title.Font = New-Object Drawing.Font('Segoe UI', 18, [Drawing.FontStyle]::Bold)
    $title.AutoSize = $true
    $title.Location = New-Object Drawing.Point(26,22)
    $f.Controls.Add($title)

    $ver = New-Object Windows.Forms.Label
    $ver.Text = "v1.0"
    $ver.ForeColor = [Drawing.Color]::Gray
    $ver.AutoSize = $true
    $ver.Location = New-Object Drawing.Point(28,58)
    $f.Controls.Add($ver)

    $desc = New-Object Windows.Forms.Label
    $desc.Text = "DHCP Rogue Detector and TCP/UDP Port Scanner for Windows."
    $desc.AutoSize = $true
    $desc.Location = New-Object Drawing.Point(28,84)
    $f.Controls.Add($desc)

    $features = New-Object Windows.Forms.Label
    $features.Text = "Features: host discovery (ICMP/ARP), MAC and hostname resolution, TCP/UDP" + [Environment]::NewLine + "port scanning, DHCP broadcast discovery, UDP/67 rogue DHCP detection," + [Environment]::NewLine + "CSV export, dark mode. Scanning runs in a separate background job, so a" + [Environment]::NewLine + "scan error never crashes the application."
    $features.AutoSize = $false; $features.Width = 540; $features.Height = 80
    $features.Location = New-Object Drawing.Point(28,114)
    $f.Controls.Add($features)

    $author = New-Object Windows.Forms.Label
    $author.Text = "Author: Nikolaos Karanikolas"
    $author.AutoSize = $true
    $author.Location = New-Object Drawing.Point(28,210)
    $f.Controls.Add($author)

    $linkSite = New-Object Windows.Forms.LinkLabel
    $linkSite.Text = "https://karanik.gr"
    $linkSite.AutoSize = $true
    $linkSite.Location = New-Object Drawing.Point(28,234)
    $linkSite.Add_LinkClicked({ try { Start-Process "https://karanik.gr" } catch { } })
    $f.Controls.Add($linkSite)

    $linkGithub = New-Object Windows.Forms.LinkLabel
    $linkGithub.Text = "https://github.com/karanikn"
    $linkGithub.AutoSize = $true
    $linkGithub.Location = New-Object Drawing.Point(28,254)
    $linkGithub.Add_LinkClicked({ try { Start-Process "https://github.com/karanikn" } catch { } })
    $f.Controls.Add($linkGithub)

    $req = New-Object Windows.Forms.Label
    $req.Text = "Requires: PowerShell 5.1+, runs elevated (UAC). nmap optional for full functionality -" + [Environment]::NewLine + "you will be prompted to download it the first time you start a scan."
    $req.AutoSize = $false; $req.Width = 540; $req.Height = 50
    $req.ForeColor = [Drawing.Color]::Gray
    $req.Location = New-Object Drawing.Point(28,284)
    $f.Controls.Add($req)

    $btnOk = New-Object Windows.Forms.Button
    $btnOk.Text = "OK"; $btnOk.Width = 90; $btnOk.Height = 32
    $btnOk.Location = New-Object Drawing.Point(480,370)
    $btnOk.Add_Click({ $f.Close() })
    $f.Controls.Add($btnOk)

    [void]$f.ShowDialog($Script:Ui.Form)
}

# ============================================================
# NMAP - on-demand check + portable download (NOT at startup)
# ============================================================
function Get-NmapManually {
    # Triggered by the "Get nmap" toolbar button - same logic as the
    # automatic on-demand check/download, just invoked directly without
    # needing to start a scan first.
    Write-AppLog "Get nmap button clicked"
    $existing = Find-NmapPath
    if ($existing) {
        $Script:NmapPath = $existing
        $Script:Ui.NmapLabel.Text = "nmap: found"
        $Script:Ui.NmapLabel.ForeColor = (Get-Theme).Green
        [Windows.Forms.MessageBox]::Show("nmap is already installed at:`r`n$existing","nmap", "OK", "Information") | Out-Null
        return
    }
    $result = Get-NmapOrPromptDownload
    if (-not $result) {
        Ui-Log "nmap was not installed." "WARN"
    }
}

function Invoke-NmapZipDownloadAttempt {
    param([string]$Url, [string]$DestPath, [int]$TimeoutSeconds = 90)
    # One single attempt at downloading the nmap portable zip. Mirrors the
    # same browser-like header approach used for the OUI database, since
    # generic/incomplete headers can trigger bot-protection style errors.
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36')
        $wc.Headers.Add('Accept', 'application/octet-stream,*/*')
        $wc.Headers.Add('Accept-Language', 'en-US,en;q=0.9')

        $script:nmapDlDone = $false
        $script:nmapDlError = $null
        $wc.Add_DownloadFileCompleted({
            param($s, $e)
            $script:nmapDlDone = $true
            if ($e.Error) { $script:nmapDlError = $e.Error }
        })
        $wc.DownloadFileAsync([Uri]$Url, $DestPath)

        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (-not $script:nmapDlDone -and $sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
            [Windows.Forms.Application]::DoEvents()
            Start-Sleep -Milliseconds 100
        }

        if (-not $script:nmapDlDone) {
            try { $wc.CancelAsync() } catch { }
            Write-AppLog "nmap download attempt timed out after ${TimeoutSeconds}s ($Url)" "WARN"
            return $false
        }
        if ($script:nmapDlError) {
            Write-AppLog "nmap download attempt failed ($Url): $($script:nmapDlError.Message)" "WARN"
            return $false
        }
        if (-not (Test-Path $DestPath) -or (Get-Item $DestPath).Length -lt 100000) {
            Write-AppLog "nmap download attempt produced an empty/too-small file ($Url)" "WARN"
            return $false
        }
        return $true
    } catch {
        Write-AppLog "nmap download attempt exception ($Url): $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Install-NmapFromZip {
    # Tries the last known-good portable zip (7.92) with retry/backoff,
    # extracting it into $Script:NmapDir (next to this script).
    $zipPath = Join-Path $env:TEMP 'nmap_dl.zip'
    Remove-Item $zipPath -ErrorAction SilentlyContinue
    $maxAttempts = 3
    $success = $false

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        Write-AppLog "Downloading nmap portable zip (attempt $attempt/$maxAttempts) from $Script:NmapZipUrl"
        Ui-Log "Downloading nmap (portable, attempt $attempt/$maxAttempts)..." "INFO"
        $Script:Ui.StatusLabel.Text = "Downloading nmap (attempt $attempt)..."

        if (Invoke-NmapZipDownloadAttempt -Url $Script:NmapZipUrl -DestPath $zipPath -TimeoutSeconds 90) {
            $success = $true
            break
        }
        if ($attempt -lt $maxAttempts) {
            $delaySec = $attempt * 3
            Ui-Log "Download attempt $attempt failed, retrying in ${delaySec}s..." "WARN"
            $waitUntil = (Get-Date).AddSeconds($delaySec)
            while ((Get-Date) -lt $waitUntil) {
                [Windows.Forms.Application]::DoEvents()
                Start-Sleep -Milliseconds 100
            }
        }
    }

    if (-not $success) {
        Write-AppLog "nmap portable zip download failed after all attempts" "WARN"
        Remove-Item $zipPath -ErrorAction SilentlyContinue
        return $false
    }

    try {
        Write-AppLog "nmap zip downloaded to $zipPath, extracting to $Script:NmapDir..."
        Ui-Log "Extracting nmap..." "INFO"
        $extractTemp = Join-Path $env:TEMP "nmap_extract_$([guid]::NewGuid().ToString('N'))"
        New-Item -Path $extractTemp -ItemType Directory -Force | Out-Null
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractTemp)
        $extracted = Get-ChildItem $extractTemp -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^nmap-' } | Select-Object -First 1
        if (-not $extracted) {
            Write-AppLog "nmap zip extracted but no nmap-* folder found inside" "ERROR"
            Remove-Item $extractTemp -Recurse -Force -ErrorAction SilentlyContinue
            return $false
        }
        if (Test-Path $Script:NmapDir) { Remove-Item $Script:NmapDir -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -Path (Split-Path $Script:NmapDir -Parent) -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        Move-Item $extracted.FullName $Script:NmapDir
        Remove-Item $extractTemp -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $zipPath -ErrorAction SilentlyContinue
        return (Test-Path (Join-Path $Script:NmapDir 'nmap.exe'))
    } catch {
        Write-AppLog "nmap zip extraction exception: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Install-NmapFromInstaller {
    # Fallback path: the portable zip is no longer published for current
    # nmap releases (dropped after 7.92), so this downloads the official
    # installer .exe and runs it silently (NSIS /S flag) targeting a
    # folder next to this script instead of the default Program Files
    # location, keeping everything self-contained alongside the tool.
    $exePath = Join-Path $env:TEMP 'nmap_setup.exe'
    Remove-Item $exePath -ErrorAction SilentlyContinue
    $maxAttempts = 3
    $success = $false

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        Write-AppLog "Downloading nmap installer (attempt $attempt/$maxAttempts) from $Script:NmapInstallUrl"
        Ui-Log "Downloading nmap installer (attempt $attempt/$maxAttempts)..." "INFO"
        $Script:Ui.StatusLabel.Text = "Downloading nmap installer (attempt $attempt)..."

        if (Invoke-NmapZipDownloadAttempt -Url $Script:NmapInstallUrl -DestPath $exePath -TimeoutSeconds 120) {
            $success = $true
            break
        }
        if ($attempt -lt $maxAttempts) {
            $delaySec = $attempt * 3
            Ui-Log "Download attempt $attempt failed, retrying in ${delaySec}s..." "WARN"
            $waitUntil = (Get-Date).AddSeconds($delaySec)
            while ((Get-Date) -lt $waitUntil) {
                [Windows.Forms.Application]::DoEvents()
                Start-Sleep -Milliseconds 100
            }
        }
    }

    if (-not $success) {
        Write-AppLog "nmap installer download failed after all attempts" "ERROR"
        Remove-Item $exePath -ErrorAction SilentlyContinue
        return $false
    }

    try {
        Write-AppLog "nmap installer downloaded to $exePath, running silently into $Script:NmapDir..."
        Ui-Log "Installing nmap silently (this may take a minute)..." "INFO"
        New-Item -Path $Script:NmapDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $exePath
        # /S = NSIS silent install. /D sets the install directory and must
        # be the last argument with no quotes per NSIS convention.
        $psi.Arguments = "/S /D=$Script:NmapDir"
        $psi.UseShellExecute = $true
        $proc = [Diagnostics.Process]::Start($psi)
        $proc.WaitForExit(180000) | Out-Null
        Remove-Item $exePath -ErrorAction SilentlyContinue
        return (Test-Path (Join-Path $Script:NmapDir 'nmap.exe'))
    } catch {
        Write-AppLog "nmap silent install exception: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-NmapOrPromptDownload {
    Write-AppLog "Checking for nmap (on-demand, scan is starting)..."
    $Script:Ui.StatusLabel.Text = "Checking for nmap..."
    [Windows.Forms.Application]::DoEvents()

    $existing = Find-NmapPath
    if ($existing) {
        $Script:NmapPath = $existing
        Write-AppLog "nmap found at: $existing"
        $Script:Ui.NmapLabel.Text = "nmap: found"
        $Script:Ui.NmapLabel.ForeColor = (Get-Theme).Green
        return $existing
    }

    Write-AppLog "nmap not found" "WARN"
    $Script:Ui.NmapLabel.Text = "nmap: not found"
    $Script:Ui.NmapLabel.ForeColor = (Get-Theme).Orange

    $answer = [Windows.Forms.MessageBox]::Show(
        "nmap was not found on this computer.`r`n`r`n" +
        "nmap enables faster host discovery, port scanning, and DHCP broadcast detection.`r`n`r`n" +
        "Download it now? It will be saved next to this script in a 'nmap' folder.`r`n`r`n" +
        "If you choose No, the scan will continue using built-in PowerShell-only methods (slower, no DHCP broadcast discovery).",
        "nmap not found", "YesNo", "Question")

    if ($answer -ne 'Yes') {
        Write-AppLog "User declined nmap download - continuing without nmap" "WARN"
        Ui-Log "Continuing without nmap (built-in scan methods only)." "WARN"
        $Script:Ui.StatusLabel.Text = "Ready"
        return $null
    }

    Write-AppLog "User accepted nmap download"

    try {
        # Try the portable zip first - it's the last version (7.92) that
        # still ships as a zip, so no install step or UAC prompt needed.
        $ok = Install-NmapFromZip
        if (-not $ok) {
            Ui-Log "Portable nmap zip unavailable, falling back to the official installer..." "WARN"
            $ok = Install-NmapFromInstaller
        }

        if ($ok) {
            $found = Find-NmapPath
            if ($found) {
                $Script:NmapPath = $found
                Write-AppLog "nmap installed and ready: $found" "OK"
                Ui-Log "nmap installed: $found" "OK"
                $Script:Ui.NmapLabel.Text = "nmap: found"
                $Script:Ui.NmapLabel.ForeColor = (Get-Theme).Green
                return $found
            }
        }

        Write-AppLog "nmap setup failed via both zip and installer paths" "ERROR"
        Ui-Log "nmap could not be installed automatically. You can install it manually from nmap.org and this tool will detect it next time." "ERROR"
        return $null
    } catch {
        Write-AppLog "nmap setup exception: $($_.Exception.ToString())" "ERROR"
        Ui-Log "nmap setup failed: $($_.Exception.Message)" "ERROR"
        return $null
    } finally {
        $Script:Ui.StatusLabel.Text = "Ready"
    }
}

# ============================================================
# SCAN ORCHESTRATION  -  Start-Job based (crash-proof for the GUI)
# ============================================================
function Start-ScanFlow {
    if ($Script:ScanJob) { Ui-Log "A scan is already running." "WARN"; return }

    Write-AppLog "Start-ScanFlow invoked"
    $fromIp = $Script:Ui.TxtFrom.Text.Trim()
    $toIp   = $Script:Ui.TxtTo.Text.Trim()

    if ($fromIp -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' -or $toIp -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        [Windows.Forms.MessageBox]::Show("Please enter valid From/To IPv4 addresses.","Invalid range","OK","Warning") | Out-Null
        return
    }

    $nmapPath = Get-NmapOrPromptDownload

    Start-Scan -FromIp $fromIp -ToIp $toIp -NmapPath $nmapPath
}

function Start-Scan {
    param([string]$FromIp, [string]$ToIp, [string]$NmapPath)

    try {
        Write-AppLog "Building IP list from $FromIp to $ToIp"
        $fromParts = $FromIp -split '\.'
        $toOct = ($ToIp -split '\.')[3]
        $base = "$($fromParts[0]).$($fromParts[1]).$($fromParts[2])"
        $startOct = [int]$fromParts[3]
        $endOct   = [int]$toOct
        if ($endOct -lt $startOct) { throw "To address must be >= From address (same /24 assumed)." }
        if (($endOct - $startOct) -gt 1024) { throw "Range too large for this scanner (max 1024 hosts)." }

        $ips = @()
        for ($i=$startOct; $i -le $endOct; $i++) { $ips += "$base.$i" }
        Write-AppLog "IP list built: $($ips.Count) addresses"

        $ports    = @($Script:EnabledPorts)
        $settings = @{}
        foreach ($k in $Script:Settings.Keys) { $settings[$k] = $Script:Settings[$k] }
        $known    = @($Script:KnownDhcp)
        $ouiMapRaw = if ($Script:Settings.ResolveVendor) { Load-OuiDatabase } else { $null }
        $ouiMap = $null
        if ($ouiMapRaw) {
            $ouiMap = @{}
            foreach ($key in $ouiMapRaw.Keys) { $ouiMap[$key] = $ouiMapRaw[$key] }
        }

        $Script:Ui.BtnScan.Enabled = $false
        $Script:Ui.BtnStop.Enabled = $true
        $Script:Ui.Grid.Rows.Clear()
        $Script:Results.Clear()
        $Script:Ui.CountBadge.Text = "0 devices"
        $Script:Ui.LogBox.Clear()
        $Script:Ui.Progress.Value = 0
        $Script:ScanStart = Get-Date

        Ui-Log "=== Scan started: $FromIp - $ToIp ($($ips.Count) hosts) ===" "INFO"
        Ui-Log "nmap: $(if ($NmapPath) { $NmapPath } else { 'not used' })" "INFO"
        if ($known.Count -gt 0) { Ui-Log "Authorized DHCP whitelist: $($known -join ', ')" "INFO" }

        $jobScript = {
            param($Ips, $Ports, $Settings, $KnownList, $NmapPath, $OuiMap)

            function Emit { param($Obj) Write-Output $Obj }

            function Test-PingHostJob {
                param([string]$Ip, [int]$TimeoutMs)
                try {
                    $p = New-Object System.Net.NetworkInformation.Ping
                    $r = $p.Send($Ip, $TimeoutMs)
                    if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                        return [pscustomobject]@{ Online=$true; Ms=[int]$r.RoundtripTime }
                    }
                } catch { }
                return [pscustomobject]@{ Online=$false; Ms=$null }
            }
            function Get-MacFromArpJob {
                param([string]$Ip)
                try {
                    $out = & arp.exe -a $Ip 2>$null
                    foreach ($line in $out) {
                        if ($line -match [regex]::Escape($Ip) -and $line -match '([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}') {
                            return (($Matches[0]).ToUpper() -replace '-',':')
                        }
                    }
                } catch { }
                return ''
            }
            function Resolve-HostJob {
                param([string]$Ip)
                try { return ([System.Net.Dns]::GetHostEntry($Ip)).HostName } catch { return '' }
            }
            function Test-TcpPortJob {
                param([string]$Ip, [int]$Port, [int]$TimeoutMs)
                $c = $null
                try {
                    $c = New-Object System.Net.Sockets.TcpClient
                    $iar = $c.BeginConnect($Ip, $Port, $null, $null)
                    if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $c.Connected) { return $true }
                } catch { } finally { if ($c) { try { $c.Close() } catch { } } }
                return $false
            }
            function Get-VendorFromMacJob {
                param([string]$Mac, $OuiMap)
                if (-not $Mac -or -not $OuiMap) { return '' }
                $clean = ($Mac -replace '[:\-\.]', '').ToUpper()
                if ($clean.Length -lt 6) { return '' }
                $prefix = $clean.Substring(0,6)
                if ($OuiMap.ContainsKey($prefix)) { return $OuiMap[$prefix] }
                return ''
            }
            function Test-UdpDhcpJob {
                param([string]$Ip, [string]$NmapPath)
                if (-not $NmapPath) { return $false }
                try {
                    $psi = New-Object Diagnostics.ProcessStartInfo
                    # Note: deliberately NOT using --open here. With --open, nmap
                    # also reports the ambiguous 'open|filtered' state (its default
                    # guess when a UDP port gets no response at all, which is what
                    # almost every Windows host with a firewall does for ANY UDP
                    # port, DHCP or not). That caused nearly every live host to be
                    # flagged as a rogue DHCP server. We scan without --open and
                    # only treat a host as a DHCP server if nmap reports a
                    # definitive 'open' status (an actual reply was received).
                    $psi.FileName = $NmapPath
                    $psi.Arguments = "-sU -p 67 --host-timeout 8s $Ip"
                    $psi.UseShellExecute = $false
                    $psi.RedirectStandardOutput = $true
                    $psi.CreateNoWindow = $true
                    $proc = [Diagnostics.Process]::Start($psi)
                    if (-not $proc.WaitForExit(10000)) { try { $proc.Kill() } catch { }; return $false }
                    $out = $proc.StandardOutput.ReadToEnd()
                    return ($out -match '67/udp\s+open\s')
                } catch { return $false }
            }
            function Invoke-DhcpBroadcastJob {
                param([string]$NmapPath)
                $found = @()
                if (-not $NmapPath) { return $found }
                try {
                    $psi = New-Object Diagnostics.ProcessStartInfo
                    $psi.FileName = $NmapPath
                    $psi.Arguments = "--script broadcast-dhcp-discover --script-timeout 12s"
                    $psi.UseShellExecute = $false
                    $psi.RedirectStandardOutput = $true
                    $psi.RedirectStandardError = $true
                    $psi.CreateNoWindow = $true
                    $proc = [Diagnostics.Process]::Start($psi)
                    if (-not $proc.WaitForExit(18000)) { try { $proc.Kill() } catch { }; return $found }
                    $text = $proc.StandardOutput.ReadToEnd() + "`r`n" + $proc.StandardError.ReadToEnd()
                    foreach ($line in ($text -split "`r?`n")) {
                        if ($line -match 'Server Identifier:\s+(\d{1,3}(\.\d{1,3}){3})') {
                            if ($found -notcontains $Matches[1]) { $found += $Matches[1] }
                        }
                    }
                } catch { }
                return $found
            }

            Emit ([pscustomobject]@{ Kind='Log'; Level='INFO'; Message='Scan job started.' })

            $knownSet = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($k in @($KnownList)) { if ($k) { [void]$knownSet.Add([string]$k) } }
            $dhcpSet = New-Object 'System.Collections.Generic.HashSet[string]'

            if ($Settings.DhcpBroadcast -and $NmapPath) {
                Emit ([pscustomobject]@{ Kind='Log'; Level='INFO'; Message='Running DHCP broadcast discovery via nmap...' })
                $found = @(Invoke-DhcpBroadcastJob $NmapPath)
                foreach ($d in $found) { [void]$dhcpSet.Add($d) }
                if ($found.Count -gt 0) {
                    Emit ([pscustomobject]@{ Kind='Log'; Level='WARN'; Message="DHCP broadcast response from: $($found -join ', ')" })
                } else {
                    Emit ([pscustomobject]@{ Kind='Log'; Level='INFO'; Message='No response to DHCP broadcast.' })
                }
            }

            # ----------------------------------------------------------
            # Parallel host scan using a runspace pool.
            # This job already runs in its own separate PowerShell process
            # (started via Start-Job), so using runspaces here is safe -
            # nothing here ever touches a UI object. Scanning many hosts
            # one at a time was the main reason scans were slow; running
            # $Settings.MaxThreads hosts concurrently cuts scan time roughly
            # proportionally to the thread count on most home/office LANs.
            # ----------------------------------------------------------
            function Test-OneHostJob {
                param($Ip, $Ports, $Settings, $NmapPath, $KnownDhcpBroadcastSet, $OuiMap)

                $ping = Test-PingHostJob -Ip $Ip -TimeoutMs ([int]$Settings.PingTimeoutMs)
                $online = $ping.Online
                $viaArp = $false

                if ($Settings.PingMethod -ne 'ICMP' -and -not $online) {
                    # ARP fallback: a host can be in the ARP cache (recently
                    # communicated with) even if it silently drops pings.
                    try {
                        $arpOut = & arp.exe -a $Ip 2>$null
                        if ($arpOut -match [regex]::Escape($Ip)) { $online = $true; $viaArp = $true }
                    } catch { }

                    # The host is reachable (found via ARP) but the first
                    # ping attempt failed - this is often just transient
                    # packet loss from many hosts being probed in parallel,
                    # not a real firewall block. Retry ping up to 2 more
                    # times; if any attempt succeeds, use that real
                    # round-trip time instead of just showing "ARP".
                    if ($viaArp) {
                        for ($retry = 1; $retry -le 2; $retry++) {
                            $retryPing = Test-PingHostJob -Ip $Ip -TimeoutMs ([int]$Settings.PingTimeoutMs)
                            if ($retryPing.Online -and $retryPing.Ms) {
                                $ping = $retryPing
                                $viaArp = $false
                                break
                            }
                        }
                    }
                }

                if (-not $online -and -not [bool]$Settings.ShowOffline -and -not $KnownDhcpBroadcastSet.Contains($Ip)) {
                    return $null
                }

                $mac = ''; $hn = ''; $openList = @(); $vendor = ''
                $viaDhcpOnly = (-not $online -and $KnownDhcpBroadcastSet.Contains($Ip))
                if ($viaDhcpOnly) {
                    # The host didn't answer ping or show up in ARP, but it
                    # did answer a DHCP broadcast/UDP probe, so we still
                    # want to try resolving its MAC/hostname/vendor even
                    # though $online is technically false.
                    $mac = Get-MacFromArpJob $Ip
                    if ([bool]$Settings.ResolveHostname) { $hn = Resolve-HostJob $Ip }
                    if ($mac -and [bool]$Settings.ResolveVendor) { $vendor = Get-VendorFromMacJob -Mac $mac -OuiMap $OuiMap }
                }
                if ($online -and [bool]$Settings.ResolveMac)      { $mac = Get-MacFromArpJob $Ip }
                if ($online -and [bool]$Settings.ResolveHostname) { $hn  = Resolve-HostJob $Ip }
                if ($online -and $mac -and [bool]$Settings.ResolveVendor) { $vendor = Get-VendorFromMacJob -Mac $mac -OuiMap $OuiMap }
                if ($online) {
                    foreach ($port in @($Ports)) {
                        if (Test-TcpPortJob -Ip $Ip -Port $port -TimeoutMs ([int]$Settings.TcpTimeoutMs)) { $openList += $port }
                    }
                }
                $isDhcpUdp = $false
                if ($online -and [bool]$Settings.UdpDhcpCheck -and $NmapPath -and -not $KnownDhcpBroadcastSet.Contains($Ip)) {
                    $isDhcpUdp = Test-UdpDhcpJob -Ip $Ip -NmapPath $NmapPath
                }

                return [pscustomobject]@{
                    IP = $Ip; MAC = $mac; Vendor = $vendor; RespMs = $ping.Ms; Hostname = $hn
                    OpenPorts = $openList; Online = $online; IsDhcpUdp = $isDhcpUdp; ViaArp = $viaArp; ViaDhcpOnly = $viaDhcpOnly
                }
            }

            $total = [Math]::Max(1, @($Ips).Count)
            $maxThreads = [Math]::Max(1, [int]$Settings.MaxThreads)

            $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            foreach ($fn in @('Test-PingHostJob','Get-MacFromArpJob','Resolve-HostJob','Test-TcpPortJob','Test-UdpDhcpJob','Get-VendorFromMacJob','Test-OneHostJob')) {
                $def = Get-Item "function:$fn"
                $entry = [System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($fn, $def.Definition)
                $iss.Commands.Add($entry)
            }
            $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $maxThreads, $iss, $Host)
            $pool.Open()

            $jobs = New-Object System.Collections.Generic.List[object]
            foreach ($ip in @($Ips)) {
                $ps = [System.Management.Automation.PowerShell]::Create()
                $ps.RunspacePool = $pool
                [void]$ps.AddCommand('Test-OneHostJob').
                    AddParameter('Ip', $ip).
                    AddParameter('Ports', $Ports).
                    AddParameter('Settings', $Settings).
                    AddParameter('NmapPath', $NmapPath).
                    AddParameter('KnownDhcpBroadcastSet', $dhcpSet).
                    AddParameter('OuiMap', $OuiMap)
                $handle = $ps.BeginInvoke()
                $jobs.Add([pscustomobject]@{ Ps=$ps; Handle=$handle; Ip=$ip })
            }

            $done = 0
            foreach ($j in $jobs) {
                $result = $null
                try { $result = $j.Ps.EndInvoke($j.Handle) } catch { } finally { $j.Ps.Dispose() }

                if ($result) {
                    $r = $result | Select-Object -First 1
                    if ($r) {
                        $ip = $r.IP
                        $dhcpFlag = ''
                        if ($r.IsDhcpUdp) { [void]$dhcpSet.Add($ip) }
                        if ($dhcpSet.Contains($ip)) {
                            $dhcpFlag = if ($knownSet.Contains($ip)) { 'YES (AUTHORIZED)' } else { 'YES (CHECK!)' }
                        } elseif ($knownSet.Contains($ip)) {
                            $dhcpFlag = 'Authorized'
                        }
                        $row = [pscustomobject]@{
                            IP = $ip; MAC = $r.MAC; Vendor = $r.Vendor; RespMs = if ($r.RespMs) { "$($r.RespMs) ms" } elseif ($r.ViaArp) { 'ARP' } elseif ($r.ViaDhcpOnly) { 'DHCP' } else { '-' }
                            Hostname = $r.Hostname; OpenPorts = ($r.OpenPorts -join ', '); DhcpFlag = $dhcpFlag
                            Details = if (-not $r.Online -and -not $r.ViaDhcpOnly) { 'No ping reply' } else { '' }
                        }
                        Emit ([pscustomobject]@{ Kind='Row'; Row=$row })
                    }
                }

                $done++
                if (($done % 5) -eq 0 -or $done -eq $total) {
                    $pct = [int](($done / $total) * 100)
                    Emit ([pscustomobject]@{ Kind='Status'; Message="Scanned $done / $total"; Progress=$pct })
                }
            }

            $pool.Close(); $pool.Dispose()
            Emit ([pscustomobject]@{ Kind='Done'; Message='Scan complete.' })
        }

        $Script:ScanJob = Start-Job -ScriptBlock $jobScript -ArgumentList @($ips, $ports, $settings, $known, $NmapPath, $ouiMap)
        Write-AppLog "Scan job started, Id=$($Script:ScanJob.Id)"

        $Script:LastReceiveCount = 0
        if ($Script:ScanTimer) { try { $Script:ScanTimer.Stop(); $Script:ScanTimer.Dispose() } catch { } }
        $timer = New-Object Windows.Forms.Timer
        $timer.Interval = 250
        $timer.Add_Tick({ Poll-ScanJob })
        $Script:ScanTimer = $timer
        $timer.Start()

    } catch {
        Write-AppLog "Start-Scan failed: $($_.Exception.ToString())" "ERROR"
        Ui-Log "Failed to start scan: $($_.Exception.Message)" "ERROR"
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, "Cannot start scan", "OK", "Error") | Out-Null
        $Script:Ui.BtnScan.Enabled = $true
        $Script:Ui.BtnStop.Enabled = $false
    }
}

function Poll-ScanJob {
    try {
        if (-not $Script:ScanJob) { return }
        $items = @(Receive-Job -Job $Script:ScanJob -Keep -ErrorAction SilentlyContinue)
        if ($null -eq $Script:LastReceiveCount) { $Script:LastReceiveCount = 0 }

        if ($items.Count -gt $Script:LastReceiveCount) {
            $newItems = $items[$Script:LastReceiveCount..($items.Count - 1)]
            $Script:LastReceiveCount = $items.Count
            foreach ($data in @($newItems)) {
                if (-not $data) { continue }
                switch ($data.Kind) {
                    'Row'    { Add-ResultToGrid $data.Row }
                    'Log'    { Ui-Log $data.Message $data.Level }
                    'Status' {
                        if ($data.Progress -ge 0 -and $data.Progress -le 100) { $Script:Ui.Progress.Value = $data.Progress }
                        $Script:Ui.StatusLabel.Text = $data.Message
                    }
                    'Done'   { Ui-Log $data.Message "OK" }
                }
            }
        }

        if ($Script:ScanJob.State -in @('Completed','Failed','Stopped')) {
            $Script:ScanTimer.Stop()
            $Script:Ui.BtnScan.Enabled = $true
            $Script:Ui.BtnStop.Enabled = $false
            $elapsed = if ($Script:ScanStart) { [int]((Get-Date) - $Script:ScanStart).TotalSeconds } else { 0 }

            if ($Script:ScanJob.State -eq 'Completed') {
                $Script:Ui.Progress.Value = 100
                $rogueCount = (@($Script:Results) | Where-Object { $_.DhcpFlag -eq 'YES (CHECK!)' }).Count
                Ui-Log "Scan finished in $elapsed sec. $($Script:Results.Count) device(s) found." "OK"
                if ($rogueCount -gt 0) {
                    $rogueIps = (@($Script:Results) | Where-Object { $_.DhcpFlag -eq 'YES (CHECK!)' } | ForEach-Object { $_.IP }) -join ', '
                    Ui-Log "WARNING: $rogueCount unexpected DHCP server(s) found: $rogueIps" "ERROR"
                    $Script:Ui.StatusLabel.Text = "Done - $rogueCount possible ROGUE DHCP server(s) found!"
                    Write-AppLog "Rogue DHCP alert: $rogueIps" "ERROR"
                    [Windows.Forms.MessageBox]::Show(
                        "Found $rogueCount unexpected DHCP server(s) on this network:`r`n`r`n$rogueIps`r`n`r`n" +
                        "These are highlighted in red in the results table. If you recognize and trust them, add them to the authorized whitelist in Settings > DHCP Detection so they stop being flagged.",
                        "Possible Rogue DHCP Server Detected", "OK", "Warning") | Out-Null
                } else {
                    $Script:Ui.StatusLabel.Text = "Done - $($Script:Results.Count) device(s)"
                }
                Write-AppLog "Scan job completed OK in $elapsed sec"
            } elseif ($Script:ScanJob.State -eq 'Stopped') {
                Ui-Log "Scan stopped by user after $elapsed sec." "WARN"
                $Script:Ui.StatusLabel.Text = "Stopped"
                Write-AppLog "Scan job stopped by user"
            } else {
                $reason = try { $Script:ScanJob.ChildJobs[0].JobStateInfo.Reason | Out-String } catch { "Unknown error" }
                Ui-Log "Scan job failed: $reason" "ERROR"
                $Script:Ui.StatusLabel.Text = "Failed - see log"
                Write-AppLog "Scan job FAILED: $reason" "ERROR"
            }

            try { Remove-Job -Job $Script:ScanJob -Force -ErrorAction SilentlyContinue } catch { }
            $Script:ScanJob = $null
            $Script:LastReceiveCount = 0
        }
    } catch {
        Write-AppLog "Poll-ScanJob exception: $($_.Exception.ToString())" "ERROR"
    }
}

function Stop-Scan {
    try {
        if ($Script:ScanJob -and $Script:ScanJob.State -eq 'Running') {
            Stop-Job -Job $Script:ScanJob -ErrorAction SilentlyContinue
            Write-AppLog "Stop-Job sent to scan job"
        }
    } catch { Write-AppLog "Stop-Scan error: $($_.Exception.Message)" "ERROR" }
}

function Export-Results {
    if ($Script:Results.Count -eq 0) {
        [Windows.Forms.MessageBox]::Show("No results to export.","Export","OK","Information") | Out-Null
        return
    }
    $dlg = New-Object Windows.Forms.SaveFileDialog
    $dlg.Filter = "CSV (*.csv)|*.csv"
    $dlg.FileName = "NetScan-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    if ($dlg.ShowDialog() -eq 'OK') {
        try {
            $Script:Results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $dlg.FileName
            Ui-Log "Exported: $($dlg.FileName)" "OK"
        } catch {
            Write-AppLog "Export failed: $($_.Exception.Message)" "ERROR"
            [Windows.Forms.MessageBox]::Show($_.Exception.Message,"Export failed","OK","Error") | Out-Null
        }
    }
}

# ============================================================
# APPLICATION ENTRY POINT
# ============================================================
try {
    Write-AppLog "Building UI..."
    $form = Build-MainForm

    $form.Add_Shown({
        try {
            Write-AppLog "Form shown - populating interfaces and network info"
            $ifaces = Get-LocalInterfaces
            $Script:Ui.Combo.Items.Clear()
            foreach ($i in $ifaces) { [void]$Script:Ui.Combo.Items.Add($i) }
            if ($Script:Ui.Combo.Items.Count -gt 0) { $Script:Ui.Combo.SelectedIndex = 0 }

            $Script:Ui.NetInfoBox.Text = Get-NetInfoText
            $Script:Ui.NmapLabel.Text = "nmap: not checked yet"

            Apply-Theme

            Ui-Log "Network Scanner v6 ready." "OK"
            Ui-Log "User: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)" "INFO"
            Ui-Log "Log file: $Script:LogFile" "INFO"
            Ui-Log "nmap will be checked when you click Start Scanning (not at startup)." "INFO"
            $Script:Ui.StatusLabel.Text = "Ready - click Start Scanning"

            Ensure-OuiDatabase
            if (Test-Path $Script:OuiFile) {
                Ui-Log "NIC vendor database: $Script:OuiFile" "INFO"
            }

            Write-AppLog "Startup sequence completed successfully"
        } catch {
            Write-AppLog "Error during form Shown handler: $($_.Exception.ToString())" "ERROR"
            [Windows.Forms.MessageBox]::Show("Startup error:`r`n$($_.Exception.Message)`r`n`r`nSee log:`r`n$Script:LogFile","Startup Error","OK","Error") | Out-Null
        }
    })

    Write-AppLog "Calling Application.Run..."
    [Windows.Forms.Application]::Run($form)
    Write-AppLog "Application.Run returned - app closing normally"

} catch {
    Write-AppLog "FATAL error during startup: $($_.Exception.ToString())" "ERROR"
    try {
        [Windows.Forms.MessageBox]::Show(
            "The application failed to start:`r`n`r`n$($_.Exception.Message)`r`n`r`nDetails were written to:`r`n$Script:LogFile",
            "Fatal Error", "OK", "Error") | Out-Null
    } catch {
        try { "$($_.Exception.ToString())" | Out-File "$env:TEMP\NetScanner_FATAL.txt" -Encoding UTF8 } catch { }
    }
}
