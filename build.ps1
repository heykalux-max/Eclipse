# Compila Eclipse in un singolo Eclipse.exe con Nuitka (onefile).
# Requisiti: Python 3.14, Visual Studio Build Tools (MSVC), pip install -r requirements.txt nuitka zstandard
# Uso:  .\build.ps1            (output in .\dist\Eclipse.exe)
param(
    [string]$Python = "python",
    [string]$Version = "1.1.0"
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

& $Python -m nuitka "$root\src\main.py" `
    --onefile --msvc=latest `
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
    --output-dir="$root\build" --output-filename=Eclipse.exe

New-Item -ItemType Directory -Force "$root\dist" | Out-Null
Copy-Item "$root\build\Eclipse.exe" "$root\dist\Eclipse.exe" -Force
Write-Host "OK -> $root\dist\Eclipse.exe"
