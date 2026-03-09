@echo off
setlocal

echo [1/4] Installing dependencies...
go mod tidy
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: go mod tidy
    exit /b 1
)

if not exist build mkdir build

echo [2/4] Building server for Linux (amd64)...
set GOOS=linux
set GOARCH=amd64
go build -ldflags="-s -w" -o build/server ./cmd/server
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: server build
    exit /b 1
)

echo [3/4] Building client for Windows (amd64)...
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w" -o build/client.exe ./cmd/client
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: client build
    exit /b 1
)

set GOOS=
set GOARCH=

echo.
echo [4/4] Done!
echo   build\server      -- upload to Ubuntu 138.124.3.221
echo   build\client.exe  -- run on this machine
echo.
echo Deploy server:
echo   scp build\server user@138.124.3.221:/opt/dns-tunnel/server
echo   scp config\server.yaml user@138.124.3.221:/opt/dns-tunnel/server.yaml
echo.
