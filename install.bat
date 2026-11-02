@echo off
rem =====================================================================
rem  Traceroute installer - double-click to install into C:\Windows\System32
rem  (prompts for Administrator elevation via UAC)
rem =====================================================================
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
