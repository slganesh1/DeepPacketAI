; ============================================================================
; DeepPacketAI Windows Installer  —  Inno Setup 6 script
;
; Build prerequisites:
;   1. make build-release          → produces installer/deeppacketai.exe
;   2. Place npcap-installer.exe   → installer/npcap-installer.exe
;      (download from https://npcap.com/#download)
;   3. ISCC installer/deeppacketai.iss
;
; Output: installer/Output/DeepPacketAI-Setup.exe
; ============================================================================

#define MyAppName      "DeepPacketAI"
#define MyAppVersion   "1.0.0"
#define MyAppPublisher "DeepPacketAI"
#define MyAppURL       "https://deeppacketai.com"
#define MyAppExe       "deeppacketai.exe"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Install to Program Files
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes

; Output
OutputDir=Output
OutputBaseFilename=DeepPacketAI-Setup
SetupIconFile=

; Compression
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes

; Require admin for Npcap driver installation
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

; Minimum Windows version: Windows 10 (6.2 = Win8, 10.0 = Win10)
MinVersion=10.0

; 64-bit only
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

WizardStyle=modern
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#MyAppExe}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startupicon"; Description: "Start DeepPacketAI automatically with Windows"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
; Main application binary (compiled Go, includes embedded React UI)
Source: "deeppacketai.exe"; DestDir: "{app}"; Flags: ignoreversion

; Npcap installer — bundled, installed silently if not already present
Source: "npcap-installer.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
; Start Menu
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Comment: "Deep Packet Inspection & AI Analysis"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

; Desktop shortcut (optional)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

; Startup (optional)
Name: "{autostartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: startupicon

[Registry]
; Store the install path for reference
Root: HKLM; Subkey: "Software\{#MyAppName}"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey

[Run]
; --- Step 1: Install Npcap silently if not already present ---
Filename: "{tmp}\npcap-installer.exe"; \
    Parameters: "/S /winpcap_mode=no"; \
    StatusMsg: "Installing Npcap packet capture driver..."; \
    Check: NpcapNotInstalled; \
    Flags: waituntilterminated

; --- Step 2: Launch DeepPacketAI after install ---
Filename: "{app}\{#MyAppExe}"; \
    Description: "Launch {#MyAppName}"; \
    Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop any running instance before uninstall
Filename: "taskkill"; Parameters: "/F /IM {#MyAppExe}"; Flags: runhidden; RunOnceId: "KillApp"

[Code]
// ---------------------------------------------------------------------------
// NpcapNotInstalled() — returns True if Npcap is NOT installed.
// The installer will only run the Npcap setup when this returns True.
// ---------------------------------------------------------------------------
function NpcapNotInstalled(): Boolean;
begin
  // Check for the Npcap DLL in the system Npcap sub-folder
  Result := not FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll'));
  // Also accept a legacy WinPcap installation
  if Result then
    Result := not FileExists(ExpandConstant('{sys}\wpcap.dll'));
end;

// ---------------------------------------------------------------------------
// InitializeSetup() — called before the wizard appears.
// Warn if running on an unsupported OS.
// ---------------------------------------------------------------------------
function InitializeSetup(): Boolean;
begin
  Result := True;
end;
