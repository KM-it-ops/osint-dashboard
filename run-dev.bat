@echo off
setlocal EnableExtensions
rem Run from osint-dashboard folder (same folder as this .bat).
cd /d "%~dp0"

if not exist ".venv\Scripts\activate.bat" (
  echo Creating virtual environment...
  python -m venv .venv
  if errorlevel 1 (
    echo Failed to create venv. Is Python installed and on PATH?
    pause
    exit /b 1
  )
)

call ".venv\Scripts\activate.bat"
python -m pip install -q -r requirements.txt
if errorlevel 1 (
  echo pip install failed.
  pause
  exit /b 1
)

cd /d "%~dp0backend"
rem Open the local URL in your default browser after a short delay so the server can start.
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:8000/"

python -m uvicorn app.main:app --reload
