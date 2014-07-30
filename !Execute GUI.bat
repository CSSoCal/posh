@echo off

set mypath=%~dp0

set rootdir=%mypath:~0,3%

Powershell.exe -executionpolicy remotesigned -File  "%rootdir%\CritUSB\Scripts\IT_GUI_Tool.ps1"