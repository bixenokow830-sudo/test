@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0init-backup.ps1" -ProjectDir "%~dp0" -Remote "https://github.com/bixenokow830-sudo/test.git"
set "BACKUP_EXIT=%ERRORLEVEL%"
echo.
if "%BACKUP_EXIT%"=="0" (
  echo Backup completed successfully.
) else (
  echo Backup stopped with exit code %BACKUP_EXIT%.
)
pause
exit /b %BACKUP_EXIT%
