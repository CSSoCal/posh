# Set error colors
$Host.PrivateData.DebugBackgroundColor = "Black"
$Host.PrivateData.ErrorBackgroundColor = "Black"

# Fancy Pants Custom Prompt
function prompt
{
    Write-Host("[ ") -nonewline -foregroundcolor "Cyan"
    Write-Host($PWD) -nonewline -foregroundcolor "Cyan"
    Write-Host(" ]") -foregroundcolor "Cyan"
    Write-VcsStatus -nonewline
    Write-Host(">") -nonewline -foregroundcolor "Yellow"
    return " "
}

function vpr
{
    ise $profile
}

function say($text)
{
    $loadSpeech = New-Object -ComObject SAPI.SpVoice
    $loadSpeech.Speak($text)
}

function rdp($site)
{
    if($site)
    {
        if($site.Length -eq '2')
        {
            mstsc /v:cs-$site.ddns.net:54323
        }
        else
        {
            mstsc /v:$site
        }
    }
    else
    {
        $a = Read-Host 'Site code?'
        mstsc /v:cs-$a.ddns.net:54323
    }
}

function deliverFinger()
{
[string]$private:Finger = @"
DQoJICAgICAgICAgLyJcDQoJICAgICAgICB8XC4vfA0KCSAgICAgICAgfCAgIHwNCgkgICAgICAgIHwgICB8DQoJ
ICAgICAgICB8Pn48fA0KCSAgICAgICAgfCAgIHwNCgkgICAgIC8nXHwgICB8LydcLi4NCgkgL35cfCAgIHwgICB8
ICAgfCBcDQoJfCAgID1bQF09ICAgfCAgIHwgIFwNCgl8ICAgfCAgIHwgICB8ICAgfCAgIFwNCgl8IH4gICB+ICAg
fiAgIH4gfGAgICApDQoJfCAgICAgICAgICAgICAgICAgICAvDQoJIFwgICAgICAgICAgICAgICAgIC8NCgkgIFwg
ICAgICAgICAgICAgICAvDQoJICAgXCAgICBfX19fXyAgICAvDQoJICAgIHwtLS8vJydgXC0tfA0KCSAgICB8ICgo
ICs9PSkpIHwNCgkgICAgfC0tXF98Xy8vLS18DQo= 
"@
	return [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Finger)) ;
}

function psr($pc)
{
    Enter-PSSession -ComputerName $pc
}

function startAD()
{
    $session = New-PSSession -ComputerName Chapman
    Invoke-Command -Session $session {Import-Module ActiveDirectory}
    Import-PSSession $session -Module ActiveDirectory
}

function lastloguser($user)
{
	Get-ADUser $user -Properties LastLogonDate | Select Name, LastLogonDate
}

function md5-check($someFilePath)
{
    $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    $hash = [System.BitConverter]::ToString($md5.ComputeHash([System.IO.File]::ReadAllBytes($someFilePath)))
    echo $hash
}