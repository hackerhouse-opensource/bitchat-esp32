@echo off
REM Build script for Covekey ESP32-C6

REM Activate Python venv (for west command)
if exist .venv\Scripts\activate.bat (
    call .venv\Scripts\activate.bat
) else (
    echo ERROR: Python venv not found! Run: . .\setup_env.ps1
    exit /b 1
)

REM Setup Espressif toolchain - PARENT directory (no riscv32-esp-elf suffix)
set "ESPRESSIF_TOOLCHAIN_PATH=C:\Users\Fantastic\.espressif\tools\riscv32-esp-elf\esp-14.2.0_20251107"
set "PATH=%ESPRESSIF_TOOLCHAIN_PATH%\riscv32-esp-elf\bin;%PATH%"

REM Add Ninja to PATH
set "NINJA_HOME=C:\Users\Fantastic\.espressif\tools\ninja\1.12.1"
set "PATH=%NINJA_HOME%;%PATH%"

REM Set ESP-IDF path
set "ESP_IDF_PATH=%~dp0modules\hal\espressif"

REM Set Zephyr paths
set "ZEPHYR_BASE=%~dp0zephyr"
set "ZEPHYR_SDK_INSTALL_DIR=%~dp0zephyr-sdk-0.17.4"

REM CRITICAL: Set CROSS_COMPILE for toolchain prefix
set "CROSS_COMPILE=riscv32-esp-elf-"


if "%1"=="" (
    echo Usage: build.bat [build^|all^|clean^|flash^|monitor]
    echo   build   - Build only
    echo   all     - Clean, build, flash and monitor
    echo   clean   - Clean build directory
    echo   flash   - Flash only
    echo   monitor - Monitor only
    exit /b 1
)

set "BOARD=esp32c6_devkitc/esp32c6"

if "%1"=="clean" (
    echo Cleaning build directory...
    if exist build rmdir /s /q build
    echo Clean complete.
    exit /b 0
)

if "%1"=="build" (
    echo Building for %BOARD%...
    echo Toolchain path: %ESPRESSIF_TOOLCHAIN_PATH%
    echo ESP-IDF path: %ESP_IDF_PATH%
    echo Ninja: %NINJA_HOME%\ninja.exe
    echo Cross-compile prefix: %CROSS_COMPILE%
    west build -b %BOARD% -- -DZEPHYR_TOOLCHAIN_VARIANT=espressif "-DESPRESSIF_TOOLCHAIN_PATH=%ESPRESSIF_TOOLCHAIN_PATH%" "-DCROSS_COMPILE_TARGET=riscv32-esp-elf" "-DESP_IDF_PATH=%ESP_IDF_PATH%" "-DCMAKE_MAKE_PROGRAM=%NINJA_HOME%\ninja.exe" || exit /b 1
    echo Build complete.
    exit /b 0
)

if "%1"=="all" (
    echo Cleaning build directory...
    if exist build rmdir /s /q build
    
    echo Building for %BOARD%...
    echo Toolchain path: %ESPRESSIF_TOOLCHAIN_PATH%
    echo ESP-IDF path: %ESP_IDF_PATH%
    west build -p always -b %BOARD% -- -DZEPHYR_TOOLCHAIN_VARIANT=espressif "-DESPRESSIF_TOOLCHAIN_PATH=%ESPRESSIF_TOOLCHAIN_PATH%" "-DCROSS_COMPILE_TARGET=riscv32-esp-elf" "-DESP_IDF_PATH=%ESP_IDF_PATH%" "-DCMAKE_MAKE_PROGRAM=%NINJA_HOME%\ninja.exe" || exit /b 1
    
    echo Auto-detecting ESP32-C6 serial port...
    set ESP_PORT=
    
    echo Flashing to %ESP_PORT% @ 921600...
    west flash || exit /b 1
    
    echo Flash successful
    
    echo Monitoring serial output...
    west espressif monitor
    exit /b 0
)

if "%1"=="flash" (
    echo Flashing firmware...
    west flash || exit /b 1
    echo Flash complete.
    exit /b 0
)

if "%1"=="monitor" (
    echo Starting serial monitor...
    west espressif monitor
    exit /b 0
)

echo Unknown command: %1
echo Usage: build.bat [build^|all^|clean^|flash^|monitor]
exit /b 1