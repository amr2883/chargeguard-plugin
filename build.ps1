# ChargeGuard for WooCommerce -- build.ps1
# Builds a clean release ZIP by staging the plugin source into a temp
# folder (excluding .distignore patterns via robocopy), verifying no
# forbidden files or missing runtime assets, then zipping the result.
# Never modifies or deletes anything in the source directory.

$ErrorActionPreference = "Stop"

$SourceDir   = "C:\Users\Future\chargeguard-woocommerce-backend\woocommerce-chargeguard"
$DistIgnore  = Join-Path $SourceDir ".distignore"
$PluginSlug  = "chargeguard-woocommerce"
$OutputZip   = "C:\Users\Future\chargeguard-woocommerce-backend\chargeguard-woocommerce.zip"
$StagingRoot = Join-Path $env:TEMP ("cg-build-" + [guid]::NewGuid().ToString("N"))
$StagingDir  = Join-Path $StagingRoot $PluginSlug

$ForbiddenPatterns = @(
    ".git", ".gitignore", ".gitattributes", ".github",
    ".env", "*.env",
    "*.bak", "*.orig", "*.log", "*.tmp",
    ".DS_Store", "Thumbs.db", "desktop.ini",
    "node_modules", ".idea", ".vscode",
    "phpunit.xml", "phpunit.xml.dist",
    "composer.lock",
    ".distignore", "build.ps1", "build.sh",
    # Draft/parked/WIP files — mirrors the .distignore rule of the same
    # name. Kept here too as a hard build-time safety net: even if
    # .distignore is ever edited incorrectly, or a file like this ends
    # up somewhere .distignore's exclusion doesn't reach, the build must
    # fail loudly rather than silently ship it. Do not remove this entry
    # when cleaning up this list just because it currently matches
    # nothing in the repo — that is the same reasoning as the CA-bundle
    # check below, which also has nothing to verify until the day it
    # matters.
    "_deferred.*", "*.txt.js",
    "dev-notes"
)

function Write-Step($msg) {
    Write-Host ("--> " + $msg) -ForegroundColor Cyan
}

function Fail($msg) {
    Write-Host ("BUILD FAILED: " + $msg) -ForegroundColor Red
    exit 1
}

try {
    if (-not (Test-Path $SourceDir)) {
        Fail "Source directory not found: $SourceDir"
    }
    if (-not (Test-Path $DistIgnore)) {
        Fail ".distignore not found at: $DistIgnore"
    }

    Write-Step "Reading .distignore patterns"
    $rawLines = Get-Content $DistIgnore | Where-Object {
        $_.Trim() -ne "" -and (-not $_.Trim().StartsWith("#"))
    }

    $excludePatterns = $rawLines | Where-Object { -not $_.StartsWith("!") }
    $reincludePaths = $rawLines | Where-Object { $_.StartsWith("!") } | ForEach-Object { $_.Substring(1).Trim() }

    $xdArgs = @()
    $xfArgs = @()
    foreach ($pattern in $excludePatterns) {
        $p = $pattern.Trim()
        if ($p -eq "") { continue }
        $p = $p.TrimStart("/", "\")
        if ($p -eq "") { continue }
        if ($p -match "[\*\?]" -or $p -match "\.[A-Za-z0-9]+$") {
            $xfArgs += $p
        } else {
            $xdArgs += $p
            $xfArgs += $p
        }
    }

    Write-Step "Creating staging folder: $StagingDir"
    New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null

    Write-Step "Copying plugin source to staging (excluding .distignore patterns)"
    $robocopyArgs = @(
        $SourceDir,
        $StagingDir,
        "/E",
        "/NFL", "/NDL",
        "/NJH", "/NJS"
    )
    if ($xdArgs.Count -gt 0) {
        $robocopyArgs += "/XD"
        $robocopyArgs += $xdArgs
    }
    if ($xfArgs.Count -gt 0) {
        $robocopyArgs += "/XF"
        $robocopyArgs += $xfArgs
    }

    $proc = Start-Process -FilePath "robocopy" -ArgumentList $robocopyArgs -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ge 8) {
        Fail "robocopy failed with exit code $($proc.ExitCode)"
    }

    if ($reincludePaths.Count -gt 0) {
        Write-Step "Restoring explicitly re-included paths"
        foreach ($relPath in $reincludePaths) {
            $srcPath = Join-Path $SourceDir $relPath
            $dstPath = Join-Path $StagingDir $relPath

            if (-not (Test-Path $srcPath)) {
                Write-Host ("  (skip) re-include path not found in source: " + $relPath) -ForegroundColor Yellow
                continue
            }

            $dstParent = Split-Path $dstPath -Parent
            if (-not (Test-Path $dstParent)) {
                New-Item -ItemType Directory -Path $dstParent -Force | Out-Null
            }

            if ((Get-Item $srcPath).PSIsContainer) {
                Copy-Item -Path $srcPath -Destination $dstPath -Recurse -Force
            } else {
                Copy-Item -Path $srcPath -Destination $dstPath -Force
            }
            Write-Host ("  restored: " + $relPath) -ForegroundColor Green
        }
    }

    Write-Step "Verifying Stripe CA bundle is present"
    $caBundle = Join-Path $StagingDir "vendor\stripe-php\data\ca-certificates.crt"
    if (-not (Test-Path $caBundle)) {
        Fail "vendor/stripe-php/data/ca-certificates.crt is missing from staged output. Stripe HTTPS calls would fail at runtime. Check .distignore for an over-broad data exclusion."
    }

    Write-Step "Scanning staged output for forbidden files"
    # Matched with -like against each item's Name, rather than
    # Get-ChildItem's -Filter parameter. -Filter delegates to the
    # filesystem provider's legacy 8.3-style wildcard matching, which is
    # known to sometimes match more (or less) than a pattern visually
    # implies for short extensions. -like is a plain, predictable
    # PowerShell wildcard comparison, so a pattern here matches exactly
    # what it looks like it should — important for patterns like
    # "*.txt.js" and "_deferred.*" where a silent false-negative would
    # defeat the whole point of this check.
    $allStagedItems = Get-ChildItem -Path $StagingDir -Recurse -Force
    $violations = @()
    foreach ($pattern in $ForbiddenPatterns) {
        $found = $allStagedItems | Where-Object { $_.Name -like $pattern }
        if ($found) {
            $violations += $found | ForEach-Object { $_.FullName.Substring($StagingDir.Length + 1) }
        }
    }
    if ($violations.Count -gt 0) {
        Write-Host "Forbidden files found in staged output:" -ForegroundColor Red
        $violations | ForEach-Object { Write-Host ("  - " + $_) -ForegroundColor Red }
        Fail "Build aborted -- forbidden files present. Fix .distignore or remove these from source."
    }

    # ── Final cleanup: remove Stripe SDK doc/metadata files that
    # robocopy may not have excluded, so the release ZIP stays lean.
    Write-Step "Removing Stripe SDK documentation files"
    $stripeRoot = Join-Path $StagingDir "vendor\stripe-php"
    if (Test-Path $stripeRoot) {
        @("CHANGELOG.md","README.md","composer.json","LICENSE","OPENAPI_VERSION","VERSION","phpunit.xml.dist") | ForEach-Object {
            $path = Join-Path $stripeRoot $_
            if (Test-Path $path) { Remove-Item $path -Force }
        }
    }

    Write-Step "Compressing staged output to $OutputZip"
    if (Test-Path $OutputZip) {
        Remove-Item $OutputZip -Force
    }
    Compress-Archive -Path $StagingDir -DestinationPath $OutputZip -CompressionLevel Optimal

    $zipInfo = Get-Item $OutputZip
    $fileCount = (Get-ChildItem -Path $StagingDir -Recurse -File).Count
    $sizeMB = [Math]::Round($zipInfo.Length / 1MB, 2)

    Write-Host ""
    Write-Host "BUILD SUCCEEDED" -ForegroundColor Green
    Write-Host ("  ZIP:        " + $OutputZip)
    Write-Host ("  Size:       " + $sizeMB + " MB")
    Write-Host ("  File count: " + $fileCount)

} finally {
    if (Test-Path $StagingRoot) {
        Remove-Item -Path $StagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

