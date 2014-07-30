:: Created by: Shawn Brink
:: http://www.sevenforums.com
:: Tutorial:  http://www.sevenforums.com/tutorials/13102-notification-area-icons-reset.html


@echo off
cls
set regPath=HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify
set regKey1=IconStreams
set regKey2=PastIconsStream
set choice=Bad-Response

echo The Explorer process must be killed to reset the Notification Area Icons Cache. 
echo.
echo Please SAVE ALL OPEN WORK before continuing
echo.
pause

echo.
taskkill /IM explorer.exe /F
echo.
FOR /F "tokens=*" %%a in ('Reg Query "%regpath%" /v %regkey1% ^| find /i "%regkey1%"') do goto iconstreams
echo Registry key "IconStreams" already deleted.
echo.

:verify-PastIconsStream
FOR /F "tokens=*" %%a in ('Reg Query "%regpath%" /v %regkey2% ^| find /i "%regkey2%"') do goto PastIconsStream
echo Registry key "PastIconsStream" already deleted.
echo.
goto confirm-restart

:iconstreams
reg delete "%regpath%" /f /v "%regkey1%"
goto verify-PastIconsStream

:PastIconsStream
reg delete "%regpath%" /f /v "%regkey2%"

:confirm-restart
echo.
echo.
echo Windows must be restarted to finish resetting the Notification Area Icons. 
echo.

:wrong 
set /p choice=Restart now? (Y/N) and press Enter:
If %choice% == y goto Yes
If %choice% == Y goto Yes
If %choice% == n goto No
If %choice% == N goto No
set choice=Bad-Response
goto wrong

:Yes
shutdown /R /f /t 00
exit


:No
echo.
echo Restart aborted. Please remember to restart the computer later.
echo.
echo You can now close this command prompt window.
explorer.exe