; ---------------------------------------------------------------------------
;  TNT - TEC Network Tool  |  Inno Setup 6.3+ script  (installer\tnt.iss)
;
;  Compiled by installer\build.ps1:
;      ISCC.exe /Qp /DMyAppVersion=1.0.0 installer\tnt.iss
;  Output: installer\output\TNT-Setup-<version>.exe
;
;  What it does
;    * refuses to start (sources: learn.microsoft.com/windows/arm/apps-on-arm-x86-emulation,
;      learn.microsoft.com/dotnet/framework/install/versions-and-dependencies,
;      learn.microsoft.com/deployedge/microsoft-edge-supported-operating-systems):
;        - not 64-bit (x64) Windows, or Windows 10 on ARM   ArchitecturesAllowed=x64compatible
;          (Windows 11 on ARM passes: it runs x64 programs through emulation)
;        - older than Windows 10 1809 / build 17763          MinVersion
;        - .NET Framework older than 4.7.2                   InitializeSetup (Release DWORD under
;          HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full < MinDotNetRelease); TNT.exe hosts
;          WebView2 through pythonnet on the .NET Framework that is built into Windows
;      both OS refusals show the WindowsVersionNotSupported text in [Messages]; all three are
;      logged and, with /SUPPRESSMSGBOXES, end a silent install with exit code 1 (tested) instead
;      of waiting on a message box
;    * installs dist\TNTService (service, support files in _service\) and
;      dist\TNT (tray client, support files in _client\) into {autopf}\TNT
;    * HKLM Run "TNT" = "{app}\TNT.exe" --minimized  (tray starts at sign-in)
;    * stops the old service + client before copying (PrepareToInstall), then
;      "TNTService.exe install" + "sc start"; if the service is still not
;      registered/running afterwards it falls back to sc create/start
;    * WebView2: if the Evergreen runtime is missing OR older than MinWebView2Major (the oldest
;      Chromium the UI renders correctly in) it downloads the bootstrapper from Microsoft on the
;      Ready page and runs it /silent /install; the service is installed either way, and setup
;      says so when the download fails or the runtime is still missing/too old afterwards
;    * uninstall: taskkill TNT.exe, sc stop, "TNTService.exe remove" (sc delete
;      as a fallback), and the Windows Firewall rules the service adds for itself
;      ("TNT DHCP server (UDP 67 in)", "TNT LAN discovery (UDP 7132 in)",
;      "TNT LAN throughput (TCP 7133 in)") are deleted. %ProgramData%\TNT is KEPT
;      unless the user answers Yes to "Remove monitoring data" (or runs the
;      uninstaller with /REMOVEDATA=1); the downloaded IP location data
;      (%ProgramData%\TNT\geoip) is always removed
;    * launches TNT.exe after install as the signed-in (non-elevated) user
;    * installs LICENSE (TNT's MIT licence) and THIRD-PARTY-NOTICES.txt (the licences of the
;      bundled third-party components) into {app}; no license page: TNT is published under the
;      MIT licence, which needs no acceptance to install or use it
;
;  Silent install:   TNT-Setup-1.0.0.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
;  Silent uninstall: "%ProgramFiles%\TNT\unins000.exe" /VERYSILENT [/REMOVEDATA=1]
; ---------------------------------------------------------------------------

#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif
#define MyAppName "TNT"
#define MyAppLongName "TNT - TEC Network Tool"
#define MyAppPublisher "Total Electronics"
#define MyAppURL "https://totalelectronics.com"
#define MyAppExeName "TNT.exe"
#define MyServiceExeName "TNTService.exe"
#define MyServiceName "TNTService"
#define MyServiceDisplayName "TNT - TEC Network Tool Service"
#define MyServiceDescription "Background network monitor for TNT (TEC Network Tool): continuous ping monitoring, outage detection, scheduled internet speed tests and on-demand network discovery. Serves the local TNT UI on 127.0.0.1."
; inbound-allow rule the service creates (netsh advfirewall) the first time the DHCP server tool is switched on;
; must match tnt.dhcp.FIREWALL_RULE_NAME
#define MyDhcpFirewallRule "TNT DHCP server (UDP 67 in)"
; inbound-allow rules the service creates at every start for the LAN peer service (beacon on UDP 7132,
; throughput server on TCP 7133); must match tnt.lanpeers.BEACON_FIREWALL_RULE / THROUGHPUT_FIREWALL_RULE
#define MyLanBeaconFirewallRule "TNT LAN discovery (UDP 7132 in)"
#define MyLanThroughputFirewallRule "TNT LAN throughput (TCP 7133 in)"
#define WebView2ClientKey "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
#define WebView2UserKey "Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
#define WebView2Url "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
#define WebView2Bootstrapper "MicrosoftEdgeWebview2Setup.exe"
; Prerequisites of the TNT window (the service needs neither). Sources:
; learn.microsoft.com/dotnet/framework/install/how-to-determine-which-versions-are-installed and
; learn.microsoft.com/microsoft-edge/webview2/concepts/distribution.
;   .NET Framework 4.7.2 = Release 461808 (Microsoft's documented minimum value; 1803 reports it,
;   1809 reports 461814, 1903+ report 4.8 values). Python.Runtime.dll targets .NET Standard 2.0,
;   Microsoft.Web.WebView2.WinForms.dll .NET Framework 4.6.2.
#define MinDotNetRelease 461808
#define MinDotNetName ".NET Framework 4.7.2"
;   WebView2 / Chromium major version: CSS color-mix() (Chromium 111) colours the status pill,
;   badges and tiles in ui\css\tnt.css; every other web feature the UI uses is older
#define MinWebView2Major 111

[Setup]
AppId={{8E6C2C7E-4B1E-4C7C-9C6B-TNT000000001}}
AppName={#MyAppLongName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppLongName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
AppCopyright=Copyright (C) {#MyAppPublisher}
DefaultDirName={autopf}\TNT
DefaultGroupName=TNT
DisableProgramGroupPage=yes
DisableWelcomePage=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=output
OutputBaseFilename=TNT-Setup-{#MyAppVersion}
SetupIconFile=..\assets\tnt.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppLongName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; TNT.exe and the service are stopped by [Code] (PrepareToInstall), not by the Restart Manager
CloseApplications=no
RestartApplications=no
SetupLogging=yes
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppLongName} Setup
VersionInfoProductName={#MyAppLongName}
VersionInfoProductVersion={#MyAppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
; Inno Setup 6.7.0 shows WindowsVersionNotSupported for BOTH refusals: when ArchitecturesAllowed does
; not match (documented; it replaced OnlyOnTheseArchitectures in 6.3) and when MinVersion is not met
; (observed with a failing major, minor and build number; WinVersionTooLowError was not used), so
; this one text has to explain both. 1809 is also Windows 10 Enterprise LTSC 2019; 1803 is the
; first release with .NET Framework 4.7.2 built in but is no longer serviced.
WindowsVersionNotSupported=This version of Windows is not supported.%n%nTNT needs 64-bit (x64) Windows 10 version 1809 (build 17763) or later, or Windows 11.%n%n- Older Windows 10 releases lack the .NET Framework 4.7.2 that the TNT window needs, or no longer receive updates. Windows 7 and 8.1 are not supported.%n- 32-bit Windows and Windows 10 on ARM cannot run TNT's 64-bit programs. Windows 11 on ARM runs them through its built-in x64 emulation.%n%nTo see this PC's version: press Win+R, type winver, press Enter.
; kept in step in case an Inno Setup build shows this one for MinVersion instead (6.7.0 does not)
WinVersionTooLowError=TNT needs 64-bit (x64) Windows 10 version 1809 (build 17763) or later, or Windows 11.%n%nOlder Windows 10 releases lack the .NET Framework 4.7.2 that the TNT window needs, or no longer receive updates. Update Windows, then run this setup again.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; wipe the support folders so files removed in a newer build do not linger
Type: filesandordirs; Name: "{app}\_service"
Type: filesandordirs; Name: "{app}\_client"
Type: filesandordirs; Name: "{app}\_internal"
; the optional tools folder earlier versions created (nothing uses it since 1.7.0): the Ookla
; speedtest.exe an administrator may have put there, then the folder itself if nothing else is left
Type: files; Name: "{app}\bin\speedtest.exe"
Type: dirifempty; Name: "{app}\bin"

[Files]
Source: "..\dist\TNTService\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\TNT\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; TNT's licence and the notices for everything the two bundles redistribute
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD-PARTY-NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
; monitoring data: created here (before the service starts) so its ACL can be tightened below
Name: "{commonappdata}\TNT"

[Icons]
Name: "{group}\TNT"; Filename: "{app}\{#MyAppExeName}"; Comment: "{#MyAppLongName}"
Name: "{group}\TNT dashboard (browser)"; Filename: "http://127.0.0.1:7130/"; Comment: "Open the TNT dashboard in the default browser"
Name: "{autodesktop}\TNT"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "TNT"; ValueData: """{app}\{#MyAppExeName}"" --minimized"; Flags: uninsdeletevalue

[Run]
; %ProgramData%\TNT: SYSTEM + Administrators full control, Users read-only. By default ProgramData lets
; any user create files there; the LocalSystem service must never read config or run code a
; standard user could have planted. The tray client never writes to this folder.
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\TNT"" /inheritance:r /grant:r ""*S-1-5-18:(OI)(CI)F"" ""*S-1-5-32-544:(OI)(CI)F"" ""*S-1-5-32-545:(OI)(CI)RX"""; StatusMsg: "Securing the TNT data folder..."; Flags: runhidden waituntilterminated
; Microsoft Edge WebView2 Evergreen runtime (only when it was missing or older than MinWebView2Major and the
; bootstrapper was downloaded; CheckWebView2AfterInstall reports a runtime that is still unusable afterwards)
Filename: "{tmp}\{#WebView2Bootstrapper}"; Parameters: "/silent /install"; StatusMsg: "Installing Microsoft Edge WebView2 Runtime..."; Check: WebView2BootstrapperReady; Flags: waituntilterminated
; Register and start the service (the previous version was stopped in PrepareToInstall)
Filename: "{app}\{#MyServiceExeName}"; Parameters: "install"; StatusMsg: "Registering the TNT service..."; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "start {#MyServiceName}"; StatusMsg: "Starting the TNT service..."; Flags: runhidden waituntilterminated
; Launch the tray client as the signed-in user (not as the elevated installer)
Filename: "{app}\{#MyAppExeName}"; Description: "Launch TNT"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/IM {#MyAppExeName} /F"; RunOnceId: "KillTntClient"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "stop {#MyServiceName}"; RunOnceId: "StopTntService"; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyServiceExeName}"; Parameters: "remove"; RunOnceId: "RemoveTntService"; Flags: runhidden waituntilterminated
; the DHCP server tool's firewall rule (harmless non-zero exit when the tool was never switched on)
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#MyDhcpFirewallRule}"""; RunOnceId: "TNTDhcpFw"; Flags: runhidden waituntilterminated
; the LAN peer service's rules (created at every service start while lan.enabled is on)
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#MyLanBeaconFirewallRule}"""; RunOnceId: "TNTLanBeaconFw"; Flags: runhidden waituntilterminated
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#MyLanThroughputFirewallRule}"""; RunOnceId: "TNTLanThroughputFw"; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{app}\_service"
Type: filesandordirs; Name: "{app}\_client"
; the IP location data the service downloaded (tnt.geoip); the rest of %ProgramData%\TNT is kept unless the user removes it
Type: filesandordirs; Name: "{commonappdata}\TNT\geoip"

[Code]
var
  DownloadPage: TDownloadWizardPage;
  WebView2Downloaded: Boolean;
  RemoveData: Boolean;

// ----------------------------------------------------------------- helpers
function BoolText(B: Boolean): String;
begin
  if B then Result := 'yes' else Result := 'no';
end;

function RunHidden(const Exe, Params: String): Integer;
var
  Code: Integer;
begin
  Code := -1;
  if not Exec(Exe, Params, '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Log(Format('exec failed: %s %s', [Exe, Params]))
  else
    Log(Format('%s %s -> %d', [Exe, Params, Code]));
  Result := Code;
end;

function SysTool(const Name: String): String;
begin
  Result := ExpandConstant('{sys}\' + Name);
end;

// ----------------------------------------------------------------- version helpers (pure: no registry, no UI)
// Part Index (0-based) of a dotted version: VersionPart('152.0.4191.66', 2) = 4191.
// A missing, empty, negative or non-numeric part counts as 0.
function VersionPart(const Version: String; const Index: Integer): Integer;
var
  S: String;
  I, P: Integer;
begin
  Result := 0;
  S := Trim(Version);
  for I := 1 to Index do
  begin
    P := Pos('.', S);
    if P = 0 then
      Exit;
    S := Copy(S, P + 1, Length(S));
  end;
  P := Pos('.', S);
  if P > 0 then
    S := Copy(S, 1, P - 1);
  Result := StrToIntDef(Trim(S), 0);
  if Result < 0 then
    Result := 0;
end;

// < 0 when A is older than B, 0 when equal, > 0 when newer (first four parts, numerically)
function CompareVersion(const A, B: String): Integer;
var
  I: Integer;
begin
  Result := 0;
  for I := 0 to 3 do
  begin
    Result := VersionPart(A, I) - VersionPart(B, I);
    if Result <> 0 then
      Exit;
  end;
end;

// True when a WebView2 "pv" registry value names a runtime of at least MinMajor; '' and
// '0.0.0.0' mean "not installed" (Microsoft's documented detection rule)
function WebView2VersionUsable(const PV: String; const MinMajor: Integer): Boolean;
begin
  Result := (CompareVersion(PV, '0.0.0.0') > 0) and (CompareVersion(PV, IntToStr(MinMajor)) >= 0);
end;

// .NET Framework 4.5+ version for a Release DWORD (Microsoft's minimum value per version); '' below 4.5
function DotNetVersionName(const Release: Cardinal): String;
begin
  if Release >= 533320 then Result := '4.8.1'
  else if Release >= 528040 then Result := '4.8'
  else if Release >= 461808 then Result := '4.7.2'
  else if Release >= 461308 then Result := '4.7.1'
  else if Release >= 460798 then Result := '4.7'
  else if Release >= 394802 then Result := '4.6.2'
  else if Release >= 394254 then Result := '4.6.1'
  else if Release >= 393295 then Result := '4.6'
  else if Release >= 378389 then Result := '4.5.x'
  else Result := '';
end;

// ----------------------------------------------------------------- prerequisites
// TNT.exe loads pythonnet on the .NET Framework built into Windows (not the separate .NET 6/7/8
// runtimes). Without 4.7.2 the service would still run, but a TNT install without its window is
// not a working install, so setup stops here: before any page, file or service change.
function InitializeSetup: Boolean;
var
  Release: Cardinal;
  Found, Msg: String;
begin
  Release := 0;
  if not RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) then
    Release := 0;
  Found := DotNetVersionName(Release);
  Log('.NET Framework 4.x Release: ' + IntToStr(Release) + ' (' + Found + '); TNT needs {#MinDotNetRelease} ({#MinDotNetName}) or later');
  Result := Release >= {#MinDotNetRelease};
  if not Result then
  begin
    if Found = '' then
      Found := 'not found'
    else
      Found := 'version ' + Found;
    Msg :=
      'TNT needs Microsoft {#MinDotNetName} or later. This PC: ' + Found + '.' + #13#10#13#10 +
      'The TNT window (tray icon and dashboard) runs on the .NET Framework that is built into ' +
      'Windows 10 version 1803 and later and into Windows 11, so it is normally already there. ' +
      'Install .NET Framework 4.8 from https://dotnet.microsoft.com/download/dotnet-framework ' +
      '(the .NET 6/7/8 runtimes do not replace it), then run this setup again.';
    // Setup logs the message box text itself (also when /SUPPRESSMSGBOXES answers it)
    Log('setup stopped: {#MinDotNetName} or later is required');
    SuppressibleMsgBox(Msg, mbCriticalError, MB_OK, IDOK);
  end;
end;

// ----------------------------------------------------------------- service state
function ServiceExists: Boolean;
begin
  // sc query returns 0 when the service exists, 1060 when it does not
  Result := RunHidden(SysTool('sc.exe'), 'query {#MyServiceName}') = 0;
end;

function ServiceStopped: Boolean;
begin
  if not ServiceExists then
  begin
    Result := True;
    Exit;
  end;
  // find returns 0 when "STOPPED" is present in the sc query output
  Result := RunHidden(ExpandConstant('{cmd}'),
    '/C ' + SysTool('sc.exe') + ' query {#MyServiceName} | ' + SysTool('find.exe') + ' "STOPPED" >nul') = 0;
end;

procedure StopServiceAndClient;
var
  I: Integer;
begin
  RunHidden(SysTool('taskkill.exe'), '/IM {#MyAppExeName} /F');
  if ServiceExists then
  begin
    RunHidden(SysTool('sc.exe'), 'stop {#MyServiceName}');
    I := 0;
    while (not ServiceStopped) and (I < 30) do
    begin
      Sleep(1000);
      I := I + 1;
    end;
    if not ServiceStopped then
    begin
      Log('service did not stop within 30 s; killing {#MyServiceExeName}');
      RunHidden(SysTool('taskkill.exe'), '/IM {#MyServiceExeName} /F');
      Sleep(1500);
    end;
  end
  else
    // an orphaned console run, or a service that was removed while running
    RunHidden(SysTool('taskkill.exe'), '/IM {#MyServiceExeName} /F');
end;

procedure EnsureServiceRegisteredAndRunning;
var
  Exe: String;
begin
  Exe := ExpandConstant('{app}\{#MyServiceExeName}');
  if not ServiceExists then
  begin
    Log('service not registered by "{#MyServiceExeName} install"; falling back to sc create');
    RunHidden(SysTool('sc.exe'), 'create {#MyServiceName} binPath= "' + Exe + '" start= auto DisplayName= "{#MyServiceDisplayName}"');
    RunHidden(SysTool('sc.exe'), 'description {#MyServiceName} "{#MyServiceDescription}"');
    RunHidden(SysTool('sc.exe'), 'failure {#MyServiceName} reset= 86400 actions= restart/5000/restart/10000/restart/30000');
  end;
  if ServiceStopped then
  begin
    Log('service not running after [Run]; trying "{#MyServiceExeName} start" then sc start');
    RunHidden(Exe, 'start');
    Sleep(1500);
    if ServiceStopped then
    begin
      RunHidden(SysTool('sc.exe'), 'start {#MyServiceName}');
      Sleep(1500);
    end;
  end;
  if ServiceStopped then
    SuppressibleMsgBox(
      'The TNT service could not be started.' + #13#10#13#10 +
      'Open services.msc, start "{#MyServiceDisplayName}" ({#MyServiceName}) and check' + #13#10 +
      '%ProgramData%\TNT\logs\tnt-service.log for the reason (usually another program owns port 7130).',
      mbError, MB_OK, IDOK)
  else
    Log('{#MyServiceName} is running');
end;

// ----------------------------------------------------------------- WebView2
// The one WebView2 check. Found = the registered Evergreen runtime version (the newer of the
// per-machine and the per-user "pv"), or 'not installed'. True when it is at least
// MinWebView2Major; a missing and an outdated runtime are handled alike, because the Evergreen
// bootstrapper installs the current runtime in both cases.
function IsWebView2Usable(var Found: String): Boolean;
var
  PV: String;
begin
  Found := '';
  if RegQueryStringValue(HKLM, '{#WebView2ClientKey}', 'pv', PV) then
    Found := Trim(PV);
  PV := '';
  if RegQueryStringValue(HKCU, '{#WebView2UserKey}', 'pv', PV) then
    if CompareVersion(Trim(PV), Found) > 0 then
      Found := Trim(PV);
  Result := WebView2VersionUsable(Found, {#MinWebView2Major});
  if CompareVersion(Found, '0.0.0.0') <= 0 then
    Found := 'not installed';
  Log('WebView2 runtime: ' + Found + ' (TNT needs {#MinWebView2Major} or newer); usable: ' + BoolText(Result));
end;

function WebView2BootstrapperReady: Boolean;
begin
  Result := WebView2Downloaded and FileExists(ExpandConstant('{tmp}\{#WebView2Bootstrapper}'));
end;

function OnDownloadProgress(const Url, FileName: String; const Progress, ProgressMax: Int64): Boolean;
begin
  if Progress = ProgressMax then
    Log('downloaded ' + FileName + ' (' + IntToStr(ProgressMax) + ' bytes)');
  Result := True;
end;

procedure InitializeWizard;
begin
  WebView2Downloaded := False;
  RemoveData := False;
  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing), SetupMessage(msgPreparingDesc), @OnDownloadProgress);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Found: String;
begin
  Result := True;
  if (CurPageID = wpReady) and (not IsWebView2Usable(Found)) then
  begin
    Log('WebView2 runtime missing or older than {#MinWebView2Major}; downloading the Evergreen bootstrapper');
    DownloadPage.Clear;
    DownloadPage.Add('{#WebView2Url}', '{#WebView2Bootstrapper}', '');
    DownloadPage.Show;
    try
      try
        DownloadPage.Download;
        WebView2Downloaded := True;
      except
        if DownloadPage.AbortedByUser then
          Log('WebView2 download aborted by the user')
        else
          Log('WebView2 download failed: ' + GetExceptionMessage);
        SuppressibleMsgBox(
          'The Microsoft Edge WebView2 Runtime could not be downloaded (' + GetExceptionMessage + ').' + #13#10#13#10 +
          'This PC has WebView2: ' + Found + '. The TNT window needs version {#MinWebView2Major} or newer.' + #13#10#13#10 +
          'TNT will be installed anyway: the monitoring service works without it. ' +
          'Install or update WebView2 later from https://developer.microsoft.com/microsoft-edge/webview2/ ' +
          '(the Evergreen Standalone Installer works offline) or run this setup again while online.',
          mbInformation, MB_OK, IDOK);
      end;
    finally
      DownloadPage.Hide;
    end;
  end;
end;

// ----------------------------------------------------------------- install steps
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  Log('stopping the previous TNT client/service before copying files');
  StopServiceAndClient;
end;

// [Run] has executed the bootstrapper by now: if WebView2 is still missing or too old (typically
// WebView2 Runtime installs/updates blocked by policy), say so instead of leaving a blank window
procedure CheckWebView2AfterInstall;
var
  Found: String;
begin
  if not WebView2BootstrapperReady then
    Exit;
  if not IsWebView2Usable(Found) then
    SuppressibleMsgBox(
      'Setup ran the Microsoft Edge WebView2 Runtime installer, but this PC still has WebView2: ' + Found + '.' + #13#10#13#10 +
      'The TNT window needs version {#MinWebView2Major} or newer; the monitoring service is installed and works without it. ' +
      'If WebView2 installs or updates are blocked by policy, ask IT to allow them, or install the Evergreen ' +
      'Standalone Installer from https://developer.microsoft.com/microsoft-edge/webview2/.',
      mbInformation, MB_OK, IDOK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    EnsureServiceRegisteredAndRunning;
    CheckWebView2AfterInstall;
  end;
end;

// ----------------------------------------------------------------- uninstall
function ShouldRemoveData: Boolean;
var
  P: String;
begin
  P := ExpandConstant('{param:REMOVEDATA|0}');
  if (P = '1') or (CompareText(P, 'yes') = 0) or (CompareText(P, 'true') = 0) then
  begin
    Result := True;
    Exit;
  end;
  if UninstallSilent then
  begin
    Result := False;
    Exit;
  end;
  Result := MsgBox(
    'Remove monitoring data?' + #13#10#13#10 +
    'TNT keeps its ping logs, outage and speed-test history and settings in' + #13#10 +
    ExpandConstant('{commonappdata}\TNT') + #13#10#13#10 +
    'Yes = delete that folder too.  No = keep it (a later reinstall picks it up again).',
    mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    RemoveData := ShouldRemoveData;
    Log('remove monitoring data: ' + BoolText(RemoveData));
    StopServiceAndClient;
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    if ServiceExists then
    begin
      Log('service still registered after "{#MyServiceExeName} remove"; falling back to sc delete');
      RunHidden(SysTool('sc.exe'), 'delete {#MyServiceName}');
    end;
    if RemoveData then
    begin
      if DelTree(ExpandConstant('{commonappdata}\TNT'), True, True, True) then
        Log('removed ' + ExpandConstant('{commonappdata}\TNT'))
      else
        Log('could not fully remove ' + ExpandConstant('{commonappdata}\TNT'));
    end;
  end;
end;
