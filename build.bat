@echo off
setlocal
cd /d "%~dp0"

echo ==========================================
echo   SpecterBroker Build
echo ==========================================

echo [*] Restoring packages...
msbuild SpecterBroker.csproj /t:Restore /v:minimal

echo [*] Building Release...
msbuild SpecterBroker.csproj /p:Configuration=Release /v:minimal

echo.
if exist bin\Release\net48\SpecterBroker.exe (
    echo [+] SUCCESS: bin\Release\net48\SpecterBroker.exe
    for %%I in (bin\Release\net48\SpecterBroker.exe) do echo [+] Size: %%~zI bytes
) else (
    echo [-] FAILED
)
pause
