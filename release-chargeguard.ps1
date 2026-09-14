<#
.SYNOPSIS
    سكريبت إصدار موحّد لـ ChargeGuard WooCommerce Plugin.
    الهدف: منع تكرار مشكلة "تاج على كوميت قديم" أو "sync يدوي بيمسح فيكسات أمنية".

.DESCRIPTION
    القواعد الصارمة اللي السكريبت ده بيفرضها:
    1. لازم تشتغل فقط من المصدر الرسمي المتصل بـ GitHub (chargeguard-plugin-sync).
    2. لازم الـ working tree يكون clean (مفيش uncommitted changes) قبل أي حاجة.
    3. لازم الفرع يكون main ومتزامن 100% مع origin/main (مفيش commits لسه محليين بس).
    4. رقم النسخة (Version header) لازم يتحدث في كوميت واحد قبل التاج مباشرة.
    5. التاج بيتحط على HEAD مباشرة بعد كوميت رفع النسخة - مفيش تاج على كوميت قديم أبدًا.
    6. بعد الـ push، السكريبت بيتحقق من GitHub API إن الـ tag ده فعلاً أحدث تاج بالتاريخ.

.USAGE
    .\release-chargeguard.ps1 -NewVersion "1.0.25"
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$NewVersion,

    [string]$RepoPath = "C:\Users\Future\chargeguard-plugin-sync",
    [string]$MainPluginFile = "chargeguard-woocommerce.php",
    [string]$GitHubRepoSlug = "amr2883/chargeguard-plugin"
)

$ErrorActionPreference = "Stop"

function Fail($msg) {
    Write-Host "`n❌ توقف: $msg" -ForegroundColor Red
    exit 1
}

function Step($msg) {
    Write-Host "`n▶ $msg" -ForegroundColor Cyan
}

# ── 0) تأكيد إننا في المصدر الصح ──────────────────────────────
Step "التحقق من أن المسار هو المصدر الرسمي المتصل بـ GitHub"

if (-not (Test-Path $RepoPath)) {
    Fail "المسار $RepoPath مش موجود. عدّل -RepoPath لمكان النسخة الصحيحة."
}

$remoteUrl = git -C $RepoPath remote get-url origin 2>$null
if ($remoteUrl -notmatch [regex]::Escape($GitHubRepoSlug)) {
    Fail "الـ origin remote ($remoteUrl) مش بيشاور على $GitHubRepoSlug. ده مش المصدر الرسمي - وقف فورًا."
}
Write-Host "  ✅ Remote صحيح: $remoteUrl"

# ── 1) Working tree لازم يكون clean ──────────────────────────
Step "التحقق من أن working tree نضيف (مفيش تعديلات معلّقة)"

$status = git -C $RepoPath status --porcelain
if ($status) {
    Fail "فيه تعديلات غير محفوظة (uncommitted changes). اعمل commit أو stash الأول:`n$status"
}
Write-Host "  ✅ Working tree نضيف"

# ── 2) لازم تكون على main ومتزامن مع origin ──────────────────
Step "التحقق من الفرع الحالي والتزامن مع origin/main"

$currentBranch = git -C $RepoPath rev-parse --abbrev-ref HEAD
if ($currentBranch -ne "main") {
    Fail "انت مش على main (انت على $currentBranch). اعمل checkout main الأول."
}

git -C $RepoPath fetch origin main 2>&1 | Out-Null
$localHead  = git -C $RepoPath rev-parse HEAD
$remoteHead = git -C $RepoPath rev-parse origin/main

if ($localHead -ne $remoteHead) {
    Fail "main المحلي ($localHead) مش نفس origin/main ($remoteHead). اعمل git pull الأول وتأكد مفيش commits ضايعة."
}
Write-Host "  ✅ main متزامن تمامًا مع origin/main على $localHead"

# ── 3) تحديث رقم النسخة في الملف الرئيسي ─────────────────────
Step "تحديث Version header إلى $NewVersion"

$mainFilePath = Join-Path $RepoPath $MainPluginFile
if (-not (Test-Path $mainFilePath)) {
    Fail "الملف الرئيسي $mainFilePath مش موجود."
}

$content = Get-Content $mainFilePath -Raw
if ($content -notmatch 'Version:\s*[\d.]+') {
    Fail "معرفتش ألاقي سطر 'Version:' جوه $MainPluginFile - راجع الملف يدويًا."
}

$updated = $content -replace 'Version:\s*[\d.]+', "Version:     $NewVersion"
Set-Content -Path $mainFilePath -Value $updated -NoNewline -Encoding UTF8
Write-Host "  ✅ اتحدث Version header في $MainPluginFile إلى $NewVersion"

# ── 4) Commit رفع النسخة ──────────────────────────────────────
Step "عمل commit لرفع رقم النسخة"

git -C $RepoPath add $MainPluginFile
git -C $RepoPath commit -m "Bump version to $NewVersion"
if ($LASTEXITCODE -ne 0) { Fail "فشل الـ commit." }

$newCommitHash = git -C $RepoPath rev-parse HEAD
Write-Host "  ✅ Commit جديد: $newCommitHash"

# ── 5) التاج بيتحط على HEAD الجديد مباشرة - مفيش استثناءات ───
Step "وضع التاج v$NewVersion على HEAD مباشرة (نفس الكوميت اللي فوق بالظبط)"

$tagName = "v$NewVersion"
$existingTag = git -C $RepoPath tag -l $tagName
if ($existingTag) {
    Fail "التاج $tagName موجود بالفعل! ده بالظبط النمط اللي عمل مشكلة v1.0.24 قبل كده. اختار رقم نسخة جديد."
}

git -C $RepoPath tag -a $tagName -m "Release $tagName" $newCommitHash
Write-Host "  ✅ اتحط تاج $tagName على $newCommitHash"

# ── 6) Push للكوميت والتاج مع بعض - أتوماتيك مش يدوي ─────────
Step "رفع الكوميت والتاج لـ GitHub"

git -C $RepoPath push origin main
if ($LASTEXITCODE -ne 0) { Fail "فشل push للـ main branch." }

git -C $RepoPath push origin $tagName
if ($LASTEXITCODE -ne 0) { Fail "فشل push للتاج. راجع الحالة على GitHub يدويًا فورًا." }

Write-Host "  ✅ اتعمل push لـ main والتاج $tagName"

# ── 7) تحقق نهائي: هل GitHub API شايف التاج ده كأحدث حاجة؟ ───
Step "التحقق النهائي من GitHub API - هل $tagName ظاهر كأحدث تاج بالتاريخ؟"

Start-Sleep -Seconds 3  # مهلة بسيطة لـ GitHub يعالج التاج

try {
    $tags = Invoke-RestMethod -Uri "https://api.github.com/repos/$GitHubRepoSlug/tags"
    $latestTagOnGitHub = $tags[0].name
    if ($latestTagOnGitHub -ne $tagName) {
        Write-Host "  ⚠️ تحذير: أحدث تاج ظاهر على GitHub هو '$latestTagOnGitHub' مش '$tagName'. راجع يدويًا." -ForegroundColor Yellow
    } else {
        Write-Host "  ✅ GitHub API مؤكد: $tagName هو أحدث تاج"
    }
} catch {
    Write-Host "  ⚠️ معرفتش أتحقق من GitHub API - راجع يدويًا: https://github.com/$GitHubRepoSlug/tags" -ForegroundColor Yellow
}

Write-Host "`n🎉 تم إصدار $tagName بنجاح من الكوميت $newCommitHash" -ForegroundColor Green
Write-Host "لو عندك GitHub Action لبناء الـ Release/zip تلقائيًا، تابع الـ Actions tab دلوقتي للتأكد إنه اشتغل صح." -ForegroundColor Green
