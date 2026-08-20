@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if %errorlevel%==0 (
  py app.py
) else (
  python app.py
)
endlocal
