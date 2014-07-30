<#
.SYNOPSIS
    All in one IT GUI.
.DESCRIPTION
    This script will display a GUI to make installing software and managing users faster and easier.
    
    Written by the Crittenton IT Dept on 4/23/2014
    
    @creds = ( DV, LA, BK, KH )

.NOTES
    Author: Crittenton SoCal IT Dept
    Requires: Powershell V2
#>

################
# Begin Script #

################### 
# Run as Elevated #

$MyWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$MyWindowsPrincipal=New-Object System.Security.Principal.WindowsPrincipal($MyWindowsID)
$AdminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

if ($MyWindowsPrincipal.IsInRole($AdminRole)) 
{
    $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
    $Host.UI.RawUI.BackgroundColor = "DarkBlue"
    Clear-Host
}
else 
{
    $NewProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
    $NewProcess.Arguments = $MyInvocation.MyCommand.Definition;
    $NewProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($NewProcess);
    exit
}

Write-Host -NoNewLine "Press any key to continue..."
$Null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# End Elevation #
#################

##############
# Start Form #

$ScriptPath = Split-Path -parent $MyInvocation.MyCommand.Definition
cd $ScriptPath

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")  

$Form = New-Object System.Windows.Forms.Form    
$Form.Size = New-Object System.Drawing.Size(600,600)  
$Form.StartPosition = "CenterScreen" # Loads the window in the center of the screen.
$Form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow # Modifies the window border.
$Form.Text = "IT Install Tool" # Window description.


$Voice = New-Object -com SAPI.SpVoice
$OS = (Get-WmiObject -class Win32_OperatingSystem).Caption
$DriveHome = (Get-Location).Drive.Name + ":"

# End Form #
############

################### 
# Start Functions #

function AddUser 
{
    $wks1=$InputBox1.text;
    $wks2=$Inputbox2.text;
    $Passwd=net user $wks1 $wks2 /add | net localgroup administrators $wks1 /add | Out-String;
    $OutputBox.text=$Passwd
}

function SysInfo 
{
    $SysInfoCMD=systeminfo | fl | Out-String;
    $OutputBox.text=$sysinfocmd
}

function Ninite
{
    Invoke-Item "$DriveHome\CritUSB\Scripts\Move\Ninite.exe"
}

function MSE
{
    Invoke-Item "$DriveHome\CritUSB\Scripts\Move\MSE.exe"
    $OutputBox.text="Installing Microsoft Security Essentials."
}

function HOSTS 
{
    Invoke-Item "$DriveHome\CritUSB\Scripts\HOSTS.bat"
    $OutputBox.text="HOST file set to default."
}

function DropAdmin 
{
    net localgroup users $env:username /add
    net localgroup administrators $env:username /delete
    $OutputBox.text="User removed from Administrator group."
}
                
function RunOffice2010 
{
    $ShowCopy=robocopy /e "$DriveHome\CritUSB\Apps-Drivers\OfficePro2010" "$env:TEMP\2010" | fl | Out-String;
    $OutputBox.text=$ShowCopy;
    Invoke-Item "$env:TEMP\2010\setup.exe";
}
                    
function DisableWM 
{
    $OutputBox.text=Dism /online /Disable-Feature /FeatureName:MediaPlayback /FeatureName:MediaCenter /FeatureName:WindowsMediaPlayer /NoRestart | fl | Out-String;
}
                  
function Decrapify 
{
    Invoke-Item "$DriveHome\CritUSB\Apps-Drivers\pc-decrapifier-2.3.1.exe"
}                  

function TrueCrypt
{
    Invoke-Item "$DriveHome\CritUSB\Apps-Drivers\TrueCrypt.exe"
}                               

function WinUpdate 
{
    wuauclt /detectnow
    wuauclt /updatenow
    $OutputBox.text="Windows is now downloading and installing updates."
}     
                
function LogMeIn 
{
    $OutputBox.text="Installing LogMeIn..."
    msiexec /i $DriveHome\CritUSB\Scripts\Move\LogMeIn.msi /passive DEPLOYID=01_4jkca0s5m6brzb4xfqwuh1ewivmwbshiyoccp INSTALLMETHOD=5 FQDNDESC=1
}

function RestartSpool 
{
    $OutputBox.text="Refreshing printer connections..."
    Stop-Service Spooler -force
    Remove-Item $env:SYSTEM32\Spool\PRINTERS\*
    Start-Service Spooler
}

function CleanDesktop 
{
    del "C:\Users\Public\Desktop\*.lnk"
    del "C:\Users\$Env:USERNAME\Desktop\*.lnk"
    $OutputBox.text="Desktop links cleared"
}

function TechTools 
{
    $OutputBox.text="Installing tech tools"
    Invoke-Item "$DriveHome\CritUSB\Tech_Tools\ToolsInstall.exe"
}

function InstallAcrobat 
{
    $ShowCopy=robocopy /e "$DriveHome\CritUSB\Apps-Drivers\Acrobat9Pro" "$env:TEMP\Acro" | fl | Out-String;
    $OutputBox.text=$ShowCopy;
    Invoke-Item "$env:TEMP\Acro\AcroPro.msi";
}

function AntiSpy 
{
    $OutputBox.text="Installing anti-spyware programs."
    Invoke-Item "$DriveHome\CritUSB\Apps-Drivers\AntiSpy.exe"
}

function LogonBanner
{
if ($OS.Contains("7"))
{
    Invoke-Item "$DriveHome\CritUSB\Scripts\Move\Banner-7.vbs"
    $OutputBox.text="Applying Windows 7 Logon Banner"
}
elseif ($OS.Contains("8"))
{
    Invoke-Item "$DriveHome\CritUSB\Scripts\Move\Banner-8.vbs"
    $OutputBox.text="Applying Windows 8 Logon Banner"
}
}

function BlankReset
{
    Invoke-Item "$DriveHome\CritUSB\Scripts\Move\Blank_Icon_Reset.bat"
    $OutputBox.text="Initializing notification area icon reset script."
}

############################ 
# Begin Registry Functions #

function EnableUAC 
{
    reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
    $OutputBox.text="User Account Control Enabled"
}

function BitLock 
{
if ((Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE") -eq 0)
{
    $OutputBox.text="TPM no longer required for Bitlocker."
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Type Directory -Force
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name "UseAdvancedStartup" -Value "00000001" -PropertyType "dword"
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name "EnableBDEWithNoTPM" -Value "00000001" -PropertyType "dword"
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name "UseTPM" -Value "00000002" -PropertyType "dword"
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name "UseTPMPIN" -Value "00000002" -PropertyType "dword"
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name "UseTPMKey" -Value "00000002" -PropertyType "dword"
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name "UseTPMKeyPIN" -Value "00000002" -PropertyType "dword"
}
elseif ((Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE") -eq 1)
{
    $OutputBox.text="TPM no longer required for Bitlocker."
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name "UseAdvancedStartup" -Value "00000001" -PropertyType "dword"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name "EnableBDEWithNoTPM" -Value "00000001" -PropertyType "dword"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name "UseTPM" -Value "00000002" -PropertyType "dword"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name "UseTPMPIN" -Value "00000002" -PropertyType "dword"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name "UseTPMKey" -Value "00000002" -PropertyType "dword"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name "UseTPMKeyPIN" -Value "00000002" -PropertyType "dword"
}
}

function LockBG 
{
if ((Test-Path HKU:\) -eq 0)
{    
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
}
    
if ((Test-Path C:\CrittentonIT) -eq 0)
{
    New-Item -ItemType directory -Path C:\CrittentonIT
}

if ($OS.Contains("7"))
{
    copy "$DriveHome\CritUSB\Scripts\Move\Wallpaper-7.jpg" "C:\CrittentonIT\Wallpaper.jpg"
    $OutputBox.text="Applying Windows 7 Background Policy"
}
elseif ($OS.Contains("8"))
{
    copy "$DriveHome\CritUSB\Scripts\Move\Wallpaper-8.jpg" "C:\CrittentonIT\Wallpaper.jpg"
    $OutputBox.text="Applying Windows 8 Background Policy"
}

if ((Test-Path 'HKU:\.DEFAULT\Control Panel\Desktop') -eq 0)
{
    New-ItemProperty -Path 'HKU:\.DEFAULT\Control Panel\Desktop' -Name "Wallpaper" -Value "C:\CrittentonIT\Wallpaper.jpg"
    $OutputBox.text="Background lock has been applied. Restart to see changes."
}
elseif ((Test-Path 'HKU:\.DEFAULT\Control Panel\Desktop') -eq 1)
{
    echo "Background Policy has already been applied."
}

if ((Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System') -eq 0)
{
    New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies -Type Directory -Name "System"
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name "Wallpaper" -Value "C:\CrittentonIT\Wallpaper.jpg"
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name "NoDispScrSavPage" -Value 1
}

    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name "Wallpaper" -Value "C:\CrittentonIT\Wallpaper.jpg"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name "NoDispScrSavPage" -Value 1
}

function RestrictUser 
{
    $OutputBox.text="User restrictions have been applied."
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "DisableCAD" -Value 0

if ((Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer") -eq 0)
{
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Type Directory -Force
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "NoControlPanel" -Value 1
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "NoDriveTypeAutoRun" -Value 1
}
elseif ((Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer") -eq 1)
{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "NoControlPanel" -Value 1
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "NoDriveTypeAutoRun" -Value 1
}

if ((Test-Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel") -eq 0) 
{
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel" -Type Directory -Force
    New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel' -Name "DiasableDeleteBrowsingHistory" -Value 1
}
elseif ((Test-Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel") -eq 1)
{
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel' -Name "DiasableDeleteBrowsingHistory" -Value 1
}

if ((Test-Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN") -eq 0)
{
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" -Type Directory -Force
    New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings' -Name "LOCALMACHINE_CD_UNLOCK" -Value 0
}
elseif ((Test-Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN") -eq 1)
{
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings' -Name "LOCALMACHINE_CD_UNLOCK" -Value 0
}

if ((Test-Path "HKCU:\Software\Policies\Microsoft\Messenger\Client") -eq 0)
{
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Messenger\Client" -Type Directory -Force
    New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Messenger\Client' -Name "PreventRun" -Value 1
}
elseif ((Test-Path "HKCU:\Software\Policies\Microsoft\Messenger\Client") -eq 1)
{
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Messenger\Client' -Name "PreventRun" -Value 1
}

if ((Test-Path "HKCU:\Software\Policies\Microsoft\Windows\LocationAndSensors") -eq 0)
{
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Type Directory -Force
    New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\LocationAndSensors' -Name "DisableLocation" -Value 1
}
elseif ((Test-Path "HKCU:\Software\Policies\Microsoft\Windows\LocationAndSensors") -eq 1)
{
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\LocationAndSensors' -Name "DisableLocation" -Value 1
}

if ((Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Network Connections") -eq 0)
{
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Network Connections" -Type Directory -Force
    New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\Network Connections' -Name "NC_AllowAdvancedTCPIPConfig" -Value 0
}
elseif ((Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Network Connections") -eq 1)
{
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\Network Connections' -Name "NC_AllowAdvancedTCPIPConfig" -Value 0
}

if ((Test-Path "HKCU:\Software\Policies\Microsoft\Windows\System\Power") -eq 0)
{
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\System\Power" -Type Directory -Force
    New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\System\Power' -Name "PromptPasswordOnResume" -Value 1
}
elseif ((Test-Path "HKCU:\Software\Policies\Microsoft\Windows\System\Power") -eq 1)
{
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\System\Power' -Name "PromptPasswordOnResume" -Value 1
}
}

function UnrestrictUser 
{
    $OutputBox.text="User restrictions have been removed."
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "DisableCAD" -Value 1

if ((Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer") -eq 1)
{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "NoControlPanel" -Value 0
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "NoDriveTypeAutoRun" -Value 0
}

if ((Test-Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel") -eq 1) 
{
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel' -Name "DiasableDeleteBrowsingHistory" -Value 0
}

if ((Test-Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN") -eq 1)
{
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings' -Name "LOCALMACHINE_CD_UNLOCK" -Value 1
}

if ((Test-Path "HKCU:\Software\Policies\Microsoft\Messenger\Client") -eq 1)
{
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Messenger\Client' -Name "PreventRun" -Value 0
}

if ((Test-Path "HKCU:\Software\Policies\Microsoft\Windows\LocationAndSensors") -eq 1)
{
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\LocationAndSensors' -Name "DisableLocation" -Value 0
}

if ((Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Network Connections") -eq 1)
{
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\Network Connections' -Name "NC_AllowAdvancedTCPIPConfig" -Value 1
}

if ((Test-Path "HKCU:\Software\Policies\Microsoft\Windows\System\Power") -eq 1)
{
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\System\Power' -Name "PromptPasswordOnResume" -Value 0
}
}

# End Functions #
################# 

#####################
# Start Text Fields #

$InputBox1 = New-Object System.Windows.Forms.TextBox
$InputBox1.Location = New-Object System.Drawing.Size(485,160) 
$InputBox1.Size = New-Object System.Drawing.Size(90,20)
$InputBox1.Text = "Username"
$Form.Controls.Add($InputBox1) 

$InputBox2 = New-Object System.Windows.Forms.TextBox 
$InputBox2.Location = New-Object System.Drawing.Size(485,180) 
$InputBox2.Size = New-Object System.Drawing.Size(90,20) 
$InputBox2.Text = "Password"
$Form.Controls.Add($InputBox2)

$OutputBox = New-Object System.Windows.Forms.TextBox 
$OutputBox.Location = New-Object System.Drawing.Size(10,260) 
$OutputBox.Size = New-Object System.Drawing.Size(565,280) 
$OutputBox.MultiLine = $True 
$OutputBox.ScrollBars = "Vertical" 
$Form.Controls.Add($OutputBox) 

# End Text Fields #
###################

########################
# Start Buttons: Row 1 #

$Button1 = New-Object System.Windows.Forms.Button 
$Button1.Location = New-Object System.Drawing.Size(10,10) 
$Button1.Size = New-Object System.Drawing.Size(90,40) 
$Button1.Text = "Windows Update" 
$Button1.Add_Click({WinUpdate}) 
$Form.Controls.Add($Button1) 

$Button2 = New-Object System.Windows.Forms.Button 
$Button2.Location = New-Object System.Drawing.Size(105,10) 
$Button2.Size = New-Object System.Drawing.Size(90,40) 
$Button2.Text = "Install Acobat" 
$Button2.Add_Click({InstallAcrobat}) 
$Form.Controls.Add($Button2) 

$Button3 = New-Object System.Windows.Forms.Button 
$Button3.Location = New-Object System.Drawing.Size(200,10) 
$Button3.Size = New-Object System.Drawing.Size(90,40) 
$Button3.Text = "Run Ninite" 
$Button3.Add_Click({Ninite}) 
$Form.Controls.Add($Button3) 

$Button4 = New-Object System.Windows.Forms.Button 
$Button4.Location = New-Object System.Drawing.Size(295,10) 
$Button4.Size = New-Object System.Drawing.Size(90,40) 
$Button4.Text = "Install LogMeIn"
$Button4.Add_Click({LogMeIn})
$Form.Controls.Add($Button4)

$Button5 = New-Object System.Windows.Forms.Button 
$Button5.Location = New-Object System.Drawing.Size(390,10) 
$Button5.Size = New-Object System.Drawing.Size(90,40) 
$Button5.Text = "Install Office 2010" 
$Button5.Add_Click({RunOffice2010})
$Form.Controls.Add($Button5) 

$Button6 = New-Object System.Windows.Forms.Button 
$Button6.Location = New-Object System.Drawing.Size(485,10) 
$Button6.Size = New-Object System.Drawing.Size(90,40) 
$Button6.Text = "Install TrueCrypt" 
$Button6.Add_Click({TrueCrypt}) 
$Form.Controls.Add($Button6)

# End Buttons: Row 1 #
######################

########################
# Start Buttons: Row 2 #

$Button7 = New-Object System.Windows.Forms.Button 
$Button7.Location = New-Object System.Drawing.Size(10,60) 
$Button7.Size = New-Object System.Drawing.Size(90,40) 
$Button7.Text = "Decrapify" 
$Button7.Add_Click({Decrapify}) 
$Form.Controls.Add($Button7) 

$Button8 = New-Object System.Windows.Forms.Button 
$Button8.Location = New-Object System.Drawing.Size(105,60) 
$Button8.Size = New-Object System.Drawing.Size(90,40) 
$Button8.Text = "Disable WM" 
$Button8.Add_Click({DisableWM}) 
$Form.Controls.Add($Button8)

$Button9 = New-Object System.Windows.Forms.Button 
$Button9.Location = New-Object System.Drawing.Size(200,60) 
$Button9.Size = New-Object System.Drawing.Size(90,40) 
$Button9.Text = "" 
$Button9.Add_Click({}) 
$Form.Controls.Add($Button9)

$Button10 = New-Object System.Windows.Forms.Button 
$Button10.Location = New-Object System.Drawing.Size(295,60) 
$Button10.Size = New-Object System.Drawing.Size(90,40) 
$Button10.Text = "Logon Banner" 
$Button10.Add_Click({LogonBanner}) 
$Form.Controls.Add($Button10)

$Button11 = New-Object System.Windows.Forms.Button 
$Button11.Location = New-Object System.Drawing.Size(390,60) 
$Button11.Size = New-Object System.Drawing.Size(90,40) 
$Button11.Text = "No TPM Bitlocker" 
$Button11.Add_Click({BitLock}) 
$Form.Controls.Add($Button11)

$Button12 = New-Object System.Windows.Forms.Button 
$Button12.Location = New-Object System.Drawing.Size(485,60) 
$Button12.Size = New-Object System.Drawing.Size(90,40) 
$Button12.Text = "Anti Spyware" 
$Button12.Add_Click({AntiSpy}) 
$Form.Controls.Add($Button12)

# End Buttons: Row 2 #
######################

########################
# Start Buttons: Row 3 #

$Button13 = New-Object System.Windows.Forms.Button 
$Button13.Location = New-Object System.Drawing.Size(10,110) 
$Button13.Size = New-Object System.Drawing.Size(90,40) 
$Button13.Text = "Lock Background" 
$Button13.Add_Click({LockBG}) 
$Form.Controls.Add($Button13) 

$Button14 = New-Object System.Windows.Forms.Button 
$Button14.Location = New-Object System.Drawing.Size(105,110) 
$Button14.Size = New-Object System.Drawing.Size(90,20) 
$Button14.Text = "Restrict User" 
$Button14.Add_Click({RestrictUser}) 
$Form.Controls.Add($Button14)

$Button15 = New-Object System.Windows.Forms.Button 
$Button15.Location = New-Object System.Drawing.Size(105,130) 
$Button15.Size = New-Object System.Drawing.Size(90,20) 
$Button15.Text = "Unrestrict User" 
$Button15.Add_Click({UnrestrictUser}) 
$Form.Controls.Add($Button15)

$Button16 = New-Object System.Windows.Forms.Button 
$Button16.Location = New-Object System.Drawing.Size(200,110) 
$Button16.Size = New-Object System.Drawing.Size(90,40) 
$Button16.Text = "Drop Admin" 
$Button16.Add_Click({DropAdmin}) 
$Form.Controls.Add($Button16)

$Button17 = New-Object System.Windows.Forms.Button 
$Button17.Location = New-Object System.Drawing.Size(295,110) 
$Button17.Size = New-Object System.Drawing.Size(90,40) 
$Button17.Text = "Blank Icon Reset" 
$Button17.Add_Click({BlankReset}) 
$Form.Controls.Add($Button17)

$Button18 = New-Object System.Windows.Forms.Button 
$Button18.Location = New-Object System.Drawing.Size(390,110) 
$Button18.Size = New-Object System.Drawing.Size(90,40) 
$Button18.Text = "Clean Desktop" 
$Button18.Add_Click({CleanDesktop}) 
$Form.Controls.Add($Button18)

$Button19 = New-Object System.Windows.Forms.Button 
$Button19.Location = New-Object System.Drawing.Size(485,110) 
$Button19.Size = New-Object System.Drawing.Size(90,40) 
$Button19.Text = "Create Local User" 
$Button19.Add_Click({AddUser}) 
$Form.Controls.Add($Button19)

# End Buttons: Row 3 #
######################

########################
# Start Buttons: Row 4 #

$Button20 = New-Object System.Windows.Forms.Button 
$Button20.Location = New-Object System.Drawing.Size(10,160) 
$Button20.Size = New-Object System.Drawing.Size(90,40) 
$Button20.Text = "Enable UAC" 
$Button20.Add_Click({EnableUAC}) 
$Form.Controls.Add($Button20)

$Button21 = New-Object System.Windows.Forms.Button 
$Button21.Location = New-Object System.Drawing.Size(105,160) 
$Button21.Size = New-Object System.Drawing.Size(90,40) 
$Button21.Text = "Default HOSTS" 
$Button21.Add_Click({HOSTS}) 
$Form.Controls.Add($Button21)

$Button22 = New-Object System.Windows.Forms.Button 
$Button22.Location = New-Object System.Drawing.Size(200,160) 
$Button22.Size = New-Object System.Drawing.Size(90,40) 
$Button22.Text = "Restart Printer Connection" 
$Button22.Add_Click({RestartSpool}) 
$Form.Controls.Add($Button22)

$Button23 = New-Object System.Windows.Forms.Button 
$Button23.Location = New-Object System.Drawing.Size(295,160) 
$Button23.Size = New-Object System.Drawing.Size(90,40) 
$Button23.Text = "System Information" 
$Button23.Add_Click({SysInfo}) 
$Form.Controls.Add($Button23)

$Button24 = New-Object System.Windows.Forms.Button 
$Button24.Location = New-Object System.Drawing.Size(390,160) 
$Button24.Size = New-Object System.Drawing.Size(90,40) 
$Button24.Text = "Network Information" 
$Button24.Add_Click({NetInfo}) 
$Form.Controls.Add($Button24)

$Button25 = New-Object System.Windows.Forms.Button 
$Button25.Location = New-Object System.Drawing.Size(485,160) 
$Button25.Size = New-Object System.Drawing.Size(90,40) 
$Button25.Text = "" 
$Button25.Add_Click({}) 
$Form.Controls.Add($Button25)

# End Buttons: Row 4 #
######################

########################
# Start Buttons: Row 5 #

$Button26 = New-Object System.Windows.Forms.Button 
$Button26.Location = New-Object System.Drawing.Size(10,210) 
$Button26.Size = New-Object System.Drawing.Size(90,40) 
$Button26.Text = "" 
$Button26.Add_Click({}) 
$Form.Controls.Add($Button26)

$Button27 = New-Object System.Windows.Forms.Button 
$Button27.Location = New-Object System.Drawing.Size(105,210) 
$Button27.Size = New-Object System.Drawing.Size(90,40) 
$Button27.Text = "" 
$Button27.Add_Click({}) 
$Form.Controls.Add($Button27)

$Button28 = New-Object System.Windows.Forms.Button 
$Button28.Location = New-Object System.Drawing.Size(200,210) 
$Button28.Size = New-Object System.Drawing.Size(90,40) 
$Button28.Text = "" 
$Button28.Add_Click({}) 
$Form.Controls.Add($Button28)

$Button29 = New-Object System.Windows.Forms.Button 
$Button29.Location = New-Object System.Drawing.Size(295,210) 
$Button29.Size = New-Object System.Drawing.Size(90,40) 
$Button29.Text = "" 
$Button29.Add_Click({}) 
$Form.Controls.Add($Button29)

$Button30 = New-Object System.Windows.Forms.Button 
$Button30.Location = New-Object System.Drawing.Size(390,210) 
$Button30.Size = New-Object System.Drawing.Size(90,40) 
$Button30.Text = "" 
$Button30.Add_Click({}) 
$Form.Controls.Add($Button30)

$Button31 = New-Object System.Windows.Forms.Button 
$Button31.Location = New-Object System.Drawing.Size(485,210) 
$Button31.Size = New-Object System.Drawing.Size(90,40) 
$Button31.Text = "Install Tech Tools" 
$Button31.Add_Click({TechTools}) 
$Form.Controls.Add($Button31)

# End Buttons #
###############

$Form.Add_Shown({$Form.Activate()})
[void] $Form.ShowDialog()

# End Script #
##############