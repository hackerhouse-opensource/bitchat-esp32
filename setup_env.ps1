# Covekey Zephyr Development Environment Setup Script
# Dot-source to keep env vars in the current shell:
#   . .\setup_env.ps1

Write-Host "Setting up Covekey Zephyr development environment..." -ForegroundColor Green

# --- Project-local paths ---
$projectRoot = $PSScriptRoot
$zephyrBase  = Join-Path $projectRoot "zephyr"
$zephyrSdk   = Join-Path $projectRoot "zephyr-sdk-0.17.4"
$venvPath    = Join-Path $projectRoot ".venv"  # Build venv at PROJECT ROOT (not zephyr/)

# --- Tool locations (adjust here if you move them) ---
$ninjaHome = "C:\Users\Fantastic\.espressif\tools\ninja\1.12.1"
$toolchainRoot = "C:\Users\Fantastic\.espressif\tools\riscv32-esp-elf\esp-14.2.0_20251107"  # PARENT directory (no riscv32-esp-elf suffix)

# DON'T set ZEPHYR_BASE yet - it confuses West init
# We'll set it after West workspace is initialized
$zephyrBaseValue = $zephyrBase

# --- Build prerequisites PATH (prepend, don't spam duplicates) ---
function Prepend-Path([string]$p) {
	if (-not $p) { return }
	if (-not (Test-Path $p)) { return }
	$parts = $env:PATH -split ';'
	if ($parts -notcontains $p) {
		$env:PATH = "$p;$($env:PATH)"
	}
}

# Toolchain bin
Prepend-Path (Join-Path $toolchainRoot "riscv32-esp-elf\bin")

# GCC libexec
Prepend-Path (Join-Path $toolchainRoot "riscv32-esp-elf\libexec\gcc\riscv32-esp-elf\14.2.0")

# Zephyr SDK host tools (dtc, etc.)
Prepend-Path (Join-Path $zephyrSdk "usr\bin")

# Ninja
Prepend-Path $ninjaHome

# --- Step 1: Initialize git submodules (Zephyr source ONLY) ---
$gitmodulesFile = Join-Path $projectRoot ".gitmodules"
$zephyrGitDir = Join-Path $zephyrBase ".git"

if ((Test-Path $gitmodulesFile) -and -not (Test-Path $zephyrGitDir)) {
	Write-Host "`nStep 1/5: Downloading Zephyr submodule..." -ForegroundColor Yellow
	
	Push-Location $projectRoot
	try {
		# Clean stale refs
		git rm --cached bootloader/mcuboot -f 2>$null
		git rm --cached modules -r -f 2>$null
		git rm --cached tools -r -f 2>$null
		
		git submodule sync
		git submodule update --init --recursive
		
		if ($LASTEXITCODE -ne 0) {
			Write-Host "WARNING: Submodule init failed (stale commit reference)" -ForegroundColor Yellow
			Write-Host "Attempting manual clone of Zephyr main branch..." -ForegroundColor Yellow
			
			# Fallback: manual clone if submodule init fails
			if (-not (Test-Path $zephyrBase)) {
				git clone -b main --depth 1 https://github.com/zephyrproject-rtos/zephyr.git zephyr
				if ($LASTEXITCODE -ne 0) {
					Write-Host "ERROR: Manual clone also failed!" -ForegroundColor Red
					Pop-Location
					return
				}
				Write-Host "Zephyr cloned manually (shallow clone of main branch)" -ForegroundColor Green
			}
		} else {
			Write-Host "Zephyr downloaded via submodule" -ForegroundColor Green
		}
	} finally {
		Pop-Location
	}
} else {
	Write-Host "`nStep 1/5: Zephyr submodule OK" -ForegroundColor Gray
}

# --- Step 2: Verify/Extract Zephyr SDK ---
Write-Host "`nStep 2/5: Verifying Zephyr SDK..." -ForegroundColor Yellow

$sdkHostTools = Join-Path $zephyrSdk "cmake\zephyr\host-tools.cmake"
$sdkArchive = Join-Path $projectRoot "zephyr-sdk-minimal.7z"

if (-not (Test-Path $sdkHostTools)) {
	# SDK incomplete, try extracting from archive
	if (Test-Path $sdkArchive) {
		Write-Host "Extracting Zephyr SDK from archive..." -ForegroundColor Yellow
		
		# Check for 7-Zip
		$sevenZip = Get-Command "7z.exe" -ErrorAction SilentlyContinue
		if (-not $sevenZip) {
			Write-Host "ERROR: 7-Zip not found!" -ForegroundColor Red
			Write-Host "Install from: https://www.7-zip.org/" -ForegroundColor Yellow
			return
		}
		
		# Extract directly to project root (archive contains zephyr-sdk-0.17.4/ folder)
		# Use -aoa to overwrite without prompting
		& 7z.exe x $sdkArchive "-o$projectRoot" -aoa | Out-Null
		
		# Check if extraction created wrong path (zephyr-sdk-minimal.zephyr-sdk-0.17.4/)
		$wrongPath = Join-Path $projectRoot "zephyr-sdk-minimal\zephyr-sdk-0.17.4"
		if (Test-Path $wrongPath) {
			Write-Host "Fixing extraction path..." -ForegroundColor Gray
			# Move from wrong location to correct location
			if (Test-Path $zephyrSdk) {
				Remove-Item $zephyrSdk -Recurse -Force
			}
			Move-Item $wrongPath $zephyrSdk
			# Clean up intermediate directory
			Remove-Item (Join-Path $projectRoot "zephyr-sdk-minimal") -Recurse -Force -ErrorAction SilentlyContinue
		}
		
		if ($LASTEXITCODE -ne 0) {
			Write-Host "ERROR: 7z extraction failed!" -ForegroundColor Red
			return
		}
		
		# Verify extraction
		if (-not (Test-Path $sdkHostTools)) {
			Write-Host "ERROR: SDK still incomplete after extraction!" -ForegroundColor Red
			return
		}
		
		Write-Host "SDK extracted successfully" -ForegroundColor Green
	} else {
		Write-Host "ERROR: Zephyr SDK incomplete!" -ForegroundColor Red
		Write-Host "Missing: zephyr-sdk-0.17.4/cmake/zephyr/host-tools.cmake" -ForegroundColor Yellow
		Write-Host "Missing: zephyr-sdk-minimal.7z archive for auto-extraction" -ForegroundColor Yellow
		Write-Host "" -ForegroundColor Yellow
		Write-Host "Solutions:" -ForegroundColor Cyan
		Write-Host "  1. Add zephyr-sdk-minimal.7z to repo root for auto-extraction" -ForegroundColor White
		Write-Host "  2. Manually copy zephyr-sdk-0.17.4/ from working repo" -ForegroundColor White
		Write-Host "  3. Contact repo maintainer to commit complete SDK files" -ForegroundColor White
		return
	}
} else {
	Write-Host "Zephyr SDK verified (minimal SDK with cmake integration)" -ForegroundColor Green
}

# --- Step 3: Create build venv ---
if (-not (Test-Path $venvPath)) {
	Write-Host "`nStep 3/5: Creating build venv..." -ForegroundColor Yellow
	python -m venv $venvPath
	
	Write-Host "Upgrading pip..." -ForegroundColor Yellow
	& "$venvPath\Scripts\python.exe" -m pip install --upgrade pip --quiet
	
	Write-Host "Installing west..." -ForegroundColor Yellow
	& "$venvPath\Scripts\pip.exe" install west --quiet
} else {
	Write-Host "`nStep 3/5: Build venv exists" -ForegroundColor Gray
}

# Activate venv in current PS session
& "$venvPath\Scripts\Activate.ps1"

# --- Step 4: Initialize West workspace (inside zephyr/) ---
$westDirCorrect = Join-Path $zephyrBase ".west"
$westDirWrong = Join-Path $projectRoot ".west"

# Clean up misplaced workspace if it exists at project root
if ((Test-Path $westDirWrong) -and ($westDirWrong -ne $westDirCorrect)) {
	Write-Host "`nRemoving misplaced West workspace from project root..." -ForegroundColor Yellow
	Remove-Item $westDirWrong -Recurse -Force
}

if (-not (Test-Path $westDirCorrect)) {
	Write-Host "`nStep 4/5: Initializing West workspace in zephyr/..." -ForegroundColor Yellow
	Push-Location $zephyrBase
	try {
		# CRITICAL: Unset ZEPHYR_BASE during west init
		$savedZephyrBase = $env:ZEPHYR_BASE
		$env:ZEPHYR_BASE = $null
		
		west init -l .
		if ($LASTEXITCODE -ne 0) {
			Write-Host "ERROR: west init failed!" -ForegroundColor Red
			# Restore ZEPHYR_BASE
			$env:ZEPHYR_BASE = $savedZephyrBase
			Pop-Location
			return
		}
		
		# Restore ZEPHYR_BASE after successful init
		$env:ZEPHYR_BASE = $savedZephyrBase
		
		Write-Host "West workspace initialized in zephyr/" -ForegroundColor Green
	} finally {
		Pop-Location
	}
} else {
	Write-Host "`nStep 4/5: West workspace OK (in zephyr/.west/)" -ForegroundColor Gray
	
	# Verify West config
	Push-Location $zephyrBase
	try {
		# Check if west build is available
		$westHelp = & west help 2>&1 | Out-String
		if ($westHelp -notlike "*build*") {
			Write-Host "West build command not found - reinitializing workspace..." -ForegroundColor Yellow
			Remove-Item $westDirCorrect -Recurse -Force
			
			# CRITICAL: Unset ZEPHYR_BASE during west init
			$savedZephyrBase = $env:ZEPHYR_BASE
			$env:ZEPHYR_BASE = $null
			
			west init -l .
			
			# Restore ZEPHYR_BASE
			$env:ZEPHYR_BASE = $savedZephyrBase
			
			Write-Host "West workspace reinitialized in zephyr/" -ForegroundColor Green
		}
	} finally {
		Pop-Location
	}
}

# NOW set all environment variables (after West is initialized)
$env:ZEPHYR_BASE = $zephyrBaseValue
$env:ZEPHYR_SDK_INSTALL_DIR = $zephyrSdk
$env:ZEPHYR_TOOLCHAIN_VARIANT = "espressif"
$env:ESPRESSIF_TOOLCHAIN_PATH = $toolchainRoot
$env:ESP_IDF_PATH = Join-Path $projectRoot "modules\hal\espressif"
$env:CROSS_COMPILE = "riscv32-esp-elf-"  # CRITICAL: Toolchain prefix for compiler detection
$env:NINJA_HOME = $ninjaHome

# --- Step 5: Download additional West modules (HAL, bootloader, etc.) ---
$espIdfPath = Join-Path $projectRoot "modules\hal\espressif"
$espSocInclude = Join-Path $espIdfPath "components\soc\esp32c6\include"

if (-not (Test-Path $espSocInclude)) {
	Write-Host "`nStep 5/5: Downloading West modules..." -ForegroundColor Yellow
	Push-Location $zephyrBase
	try {
		west update
		if ($LASTEXITCODE -ne 0) {
			Write-Host "WARNING: west update had errors" -ForegroundColor Yellow
		}
		
		# Verify ESP-IDF components
		if (-not (Test-Path $espSocInclude)) {
			Write-Host "ERROR: ESP-IDF components missing after west update!" -ForegroundColor Red
			Write-Host "Expected: modules/hal/espressif/components/soc/esp32c6/include" -ForegroundColor Yellow
			return
		}
		Write-Host "West modules downloaded" -ForegroundColor Green
	} finally {
		Pop-Location
	}
} else {
	Write-Host "`nStep 5/5: West modules OK" -ForegroundColor Gray
}

# --- Install Zephyr Python dependencies if needed ---
$requirementsFile = Join-Path $zephyrBase "scripts\requirements.txt"
if (Test-Path $requirementsFile) {
	$pyElftoolsInstalled = Test-Path (Join-Path $venvPath "Lib\site-packages\pyelftools")
	if (-not $pyElftoolsInstalled) {
		Write-Host "`nInstalling Zephyr dependencies..." -ForegroundColor Yellow
		& "$venvPath\Scripts\pip.exe" install -r $requirementsFile --quiet
	}
}

# --- Install ESP tools (esptool, etc.) if needed ---
$esptoolInstalled = Test-Path (Join-Path $venvPath "Lib\site-packages\esptool")
if (-not $esptoolInstalled) {
	Write-Host "Installing esptool..." -ForegroundColor Yellow
	& "$venvPath\Scripts\pip.exe" install "esptool>=5.0.2" --quiet
}

# --- Status ---
Write-Host "`n=== Environment Ready ===" -ForegroundColor Green
Write-Host "ZEPHYR_BASE: $env:ZEPHYR_BASE" -ForegroundColor Gray
Write-Host "ZEPHYR_SDK_INSTALL_DIR: $env:ZEPHYR_SDK_INSTALL_DIR" -ForegroundColor Gray
Write-Host "ESP_IDF_PATH: $env:ESP_IDF_PATH" -ForegroundColor Gray
Write-Host "ESPRESSIF_TOOLCHAIN_PATH: $env:ESPRESSIF_TOOLCHAIN_PATH" -ForegroundColor Gray
Write-Host "Python: $((Get-Command python).Source)" -ForegroundColor Gray
Write-Host "West: $((Get-Command west -ErrorAction SilentlyContinue).Source)" -ForegroundColor Gray

if (Test-Path (Join-Path $zephyrBase "CMakeLists.txt")) {
	Write-Host "`nReady to build! Run: .\build.bat build" -ForegroundColor Cyan
} else {
	Write-Host "`nERROR: Zephyr not found" -ForegroundColor Red
}
