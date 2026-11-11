@echo off
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python nao encontrado. Instale o Python 3 e tente novamente.
  echo https://www.python.org/downloads/
  pause
  exit /b 1
)
python server.py
if errorlevel 1 (
  echo.
  echo O organizador foi encerrado com erro.
  pause
)
