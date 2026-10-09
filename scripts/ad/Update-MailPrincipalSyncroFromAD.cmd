@echo off
rem Lance Update-MailPrincipalSyncroFromAD.ps1 (meme dossier) sans controle de signature,
rem pour cette execution uniquement. Les arguments sont transmis au script.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Update-MailPrincipalSyncroFromAD.ps1" %*
echo.
pause
