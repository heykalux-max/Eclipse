# Compila Eclipse in un singolo Eclipse.exe con Nuitka (onefile).
# Requisiti: Python 3.14, Visual Studio Build Tools (MSVC), pip install -r requirements.txt nuitka zstandard
# Uso:  .\build.ps1                         (output in .\dist\Eclipse.exe)
#       .\build.ps1 -BuildDir C:\temp\ecl   (file intermedi fuori da OneDrive)
param(
    [string]$Python = "python",
    [string]$Version = "1.2.0",
    [string]$BuildDir = "",
    [string]$DistDir = ""
)
# "Continue": Nuitka writes progress to stderr, which Windows PowerShell 5.1 would turn into a terminating error
$ErrorActionPreference = "Continue"
$root = $PSScriptRoot
if (-not $BuildDir) { $BuildDir = Join-Path $root "build" }
if (-not $DistDir) { $DistDir = Join-Path $root "dist" }

& $Python -m nuitka "$root\src\main.py" `
    --onefile --msvc=latest --assume-yes-for-downloads `
    --enable-plugin=pyside6 `
    --windows-console-mode=disable `
    --windows-icon-from-ico="$root\src\eclipse.ico" `
    --onefile-tempdir-spec="{CACHE_DIR}/Eclipse/{VERSION}" `
    --company-name="Eclipse" --product-name="Eclipse" `
    --file-version=$Version --product-version=$Version `
    --include-module=pefile --include-module=psutil --include-module=fullscan `
    --noinclude-qt-translations --noinclude-qt-plugins=tls `
    --noinclude-dlls=opengl32sw.dll --noinclude-dlls=qt6pdf.dll --noinclude-dlls=qt6network.dll `
    --noinclude-dlls=*qpdf.dll --noinclude-dlls=*qdirect2d.dll `
    --output-dir="$BuildDir" --output-filename=Eclipse.exe
if ($LASTEXITCODE -ne 0) { throw "Nuitka failed (exit $LASTEXITCODE)" }

New-Item -ItemType Directory -Force $DistDir | Out-Null
Copy-Item (Join-Path $BuildDir "Eclipse.exe") (Join-Path $DistDir "Eclipse.exe") -Force
Write-Host "OK -> $(Join-Path $DistDir 'Eclipse.exe')"
