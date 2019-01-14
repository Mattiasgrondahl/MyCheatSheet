@Echo OFF
rem #FileIntegrity check download to C:\temp
rem #http://download.microsoft.com/download/c/f/4/cf454ae0-a4bb-4123-8333-a1b6737712f7/windows-kb841290-x86-enu.exe
rem #Sysinternal Accesscheck download to C:\temp
rem #https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk
REM "Local checks"
rem #Tests to perform

mkdir C:\temp\%computername%
systeminfo > C:\temp\%computername%\systeminfo.txt
net user > C:\temp\%computername%\users.txt
net localgroup > C:\temp\%computername%\localgroups.txt
netsh advfirewall show allprofiles > C:\temp\%computername%\firewall.txt
schtasks /query /fo LIST /v > C:\temp\%computername%\schtasks.txt
tasklist /SVC > C:\temp\%computername%\tasklist.txt
DRIVERQUERY > C:\temp\%computername%\drivequery.txt
wmic qfe get Caption,Description,HotFixID,InstalledOn > C:\temp\%computername%\securityupdates.txt
type %WINDIR%\Panther\Unattend\Unattended.xml > C:\temp\%computername%\sysprep.txt
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated" > C:\temp\%computername%\reg_elevated_localmachine.txt

reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated" > C:\temp\%computername%\reg_elevated_currentuser.txt
reg query "HKLM\SYSTEM\CurrentControlSet\services\mrxsmb10" > C:\temp\%computername%\SMBv1_regentry.txt
reg query "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters " > C:\temp\%computername%\SMB_parameters.txt
type C:\temp\%computername%\SMB_parameters.txt | findstr "RequireSecuritySignature    REG_DWORD    0x0" |findstr 0x0
dir /s *pass* == *cred* == *vnc* == *.config* > C:\temp\%computername%\findfiles.txt
findstr /si password *.xml *.ini *.txt > C:\temp\%computername%\findpass.txt
accesschk.exe e –accepteula -uwcqv "Authenticated Users" * > C:\temp\%computername%\services_authuser.txt
sc.exe qc lanmanworkstation C:\temp\%computername%\smbv1.txt

rem #Hash files
C:\temp\FCIV C:\temp\%computername% -md5 -sha1 "%G" >> C:\temp\%computername%\hash.txt
pause
