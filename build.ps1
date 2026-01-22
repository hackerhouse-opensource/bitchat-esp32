#Requires -Version 5.1
param(
    [Parameter(Position=0)]
    [ValidateSet('build','clean','flash','monitor','all')]
    [string]$Command = 'build'
)

$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
Push-Location $projectRoot

# Check if environment is set up
if (-not $env:ZEPHYR_BASE) {
    Write-Host "Environment not configured. Running setup_env.ps1..." -ForegroundColor Yellow
    . .\setup_env.ps1
}

$BOARD = "esp32c6_devkitc/esp32c6/hpcore"

try {
    switch ($Command) {
        'clean' {
            Write-Host "Cleaning build directory..." -ForegroundColor Yellow
            if (Test-Path "build") {
                Remove-Item "build" -Recurse -Force
            }
            Write-Host "Clean complete." -ForegroundColor Green
        }
        
        'build' {
            Write-Host "Building for $BOARD..." -ForegroundColor Cyan
            Write-Host "Toolchain: $env:ESPRESSIF_TOOLCHAIN_PATH" -ForegroundColor Gray
            Write-Host "ESP-IDF: $env:ESP_IDF_PATH" -ForegroundColor Gray
            Write-Host "Ninja: $env:NINJA_HOME\ninja.exe" -ForegroundColor Gray
            
            west build -b $BOARD -- `
                "-DZEPHYR_TOOLCHAIN_VARIANT=espressif" `
                "-DESPRESSIF_TOOLCHAIN_PATH=$env:ESPRESSIF_TOOLCHAIN_PATH" `
                "-DCROSS_COMPILE_TARGET=riscv32-esp-elf" `
                "-DESP_IDF_PATH=$env:ESP_IDF_PATH" `
                "-DCMAKE_MAKE_PROGRAM=$env:NINJA_HOME\ninja.exe"
            
            if ($LASTEXITCODE -ne 0) { throw "Build failed" }
            Write-Host "Build complete." -ForegroundColor Green
        }
        
        'flash' {
            Write-Host "Flashing firmware..." -ForegroundColor Cyan
            west flash
            if ($LASTEXITCODE -ne 0) { throw "Flash failed" }
            Write-Host "Flash complete." -ForegroundColor Green
        }
        
        'monitor' {
            Write-Host "Starting serial monitor (Ctrl+C to exit)..." -ForegroundColor Cyan
            west espressif monitor
        }
        
        'all' {
            Write-Host "=== Full Build Cycle ===" -ForegroundColor Cyan
            & $PSCommandPath clean
            
            west build -p always -b $BOARD -- `
                "-DZEPHYR_TOOLCHAIN_VARIANT=espressif" `
                "-DESPRESSIF_TOOLCHAIN_PATH=$env:ESPRESSIF_TOOLCHAIN_PATH" `
                "-DCROSS_COMPILE_TARGET=riscv32-esp-elf" `
                "-DESP_IDF_PATH=$env:ESP_IDF_PATH" `
                "-DCMAKE_MAKE_PROGRAM=$env:NINJA_HOME\ninja.exe"
            
            if ($LASTEXITCODE -ne 0) { throw "Build failed" }
            
            & $PSCommandPath flash
            & $PSCommandPath monitor
        }
    }
} finally {
    Pop-Location
}
