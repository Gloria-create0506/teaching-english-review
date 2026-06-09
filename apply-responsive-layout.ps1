param()

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$targets = @(
    "index.html",
    "chapter-2.html",
    "chapter-3.html",
    "chapter-4.html",
    "chapter-5.html",
    "chapter-6.html"
) | ForEach-Object { Join-Path $projectRoot $_ }

$responsiveCss = @'

/* Public web responsive overrides */
:root {
  --page-gutter: clamp(18px, 4vw, 68px);
  --topbar-height: 78px;
  --bottom-nav-height: 70px;
}

html {
  font-size: clamp(15px, 1.05vw + 11px, 20px);
}

body {
  overflow-x: hidden;
  overflow-y: auto;
}

.app {
  min-height: 100dvh;
  height: auto;
}

.topbar {
  min-height: 78px;
  height: auto;
  grid-template-columns: minmax(0, 1fr) auto auto;
  padding: 14px clamp(16px, 2vw, 24px);
  position: sticky;
  top: 0;
}

.toolbar {
  flex-wrap: wrap;
  justify-content: flex-end;
}

.slide-shell {
  min-height: calc(100dvh - var(--topbar-height, 78px) - var(--bottom-nav-height, 70px));
  overflow: visible;
}

.slide {
  padding: 74px var(--page-gutter) 46px;
}

.slide.active {
  position: relative;
  z-index: 1;
}

.slide-title {
  font-size: clamp(1.8rem, 1.45rem + 1.35vw, 2.6rem);
}

.hero-copy h1 {
  font-size: clamp(2rem, 1.55rem + 1.8vw, 2.78rem);
}

.visual-stage {
  min-height: clamp(300px, 42vh, 455px);
}

.bottom-nav {
  min-height: 70px;
  height: auto;
  grid-template-columns: auto minmax(0, 1fr) auto;
  padding: 10px clamp(16px, 2vw, 24px) 14px;
  position: sticky;
  bottom: 0;
}

.slide-tabs {
  flex-wrap: wrap;
}

@media (max-width: 1050px) {
  .topbar {
    grid-template-columns: minmax(0, 1fr) auto;
  }

  .slide {
    padding: 38px clamp(24px, 4vw, 32px) 48px;
  }
}

@media (max-height: 760px) and (min-width: 761px) {
  .slide-shell {
    min-height: max(860px, calc(100dvh - var(--topbar-height, 78px) - var(--bottom-nav-height, 70px)));
  }
}

@media (max-width: 760px) {
  .topbar {
    grid-template-columns: 1fr;
    gap: 12px;
    padding: 14px 16px;
    position: static;
  }

  .brand {
    align-items: flex-start;
  }

  .brand-title strong {
    font-size: 0.98rem;
  }

  .toolbar {
    justify-content: flex-start;
  }

  .slide-shell {
    min-height: max(860px, calc(100dvh - var(--topbar-height, 78px) - var(--bottom-nav-height, 70px)));
  }

  .slide {
    align-content: start;
    padding: 58px 18px 34px;
  }

  .progress-monkey {
    top: 10px;
    width: 42px;
    height: 42px;
  }

  .bottom-nav {
    grid-template-columns: 1fr;
    gap: 12px;
    padding: 10px 16px 14px;
  }

  .slide-tabs {
    justify-content: flex-start;
    overflow-x: auto;
    padding-bottom: 4px;
  }
}

@media (max-width: 520px) {
  .toolbar .text-button,
  .toolbar .icon-button {
    min-width: 0;
  }

  .slide-title,
  .hero-copy h1 {
    font-size: 1.75rem;
  }
}
'@

$responsiveScript = @'
  function syncResponsiveShell() {
    var root = document.documentElement;
    var topbar = document.querySelector(".topbar");
    var bottomNav = document.querySelector(".bottom-nav");
    root.style.setProperty("--topbar-height", (topbar ? topbar.offsetHeight : 78) + "px");
    root.style.setProperty("--bottom-nav-height", (bottomNav ? bottomNav.offsetHeight : 70) + "px");
  }

'@

$resizeHook = @'

  window.addEventListener("resize", syncResponsiveShell);
  window.addEventListener("orientationchange", syncResponsiveShell);
'@

foreach ($file in $targets) {
    $content = Get-Content -LiteralPath $file -Raw -Encoding UTF8

    if ($content -notmatch [regex]::Escape("Public web responsive overrides")) {
        $content = $content -replace '</style>', ($responsiveCss + "`r`n</style>")
    }

    if ($content -notmatch 'function syncResponsiveShell\(\)') {
        $content = [regex]::Replace(
            $content,
            '(function icon\(name\) \{[\s\S]*?return ''<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2\.4">'' \+ paths\[name\] \+ ''</svg>'';\s+\})',
            ('$1' + "`r`n`r`n" + $responsiveScript),
            1
        )
    }

    if ($content -notmatch 'footerStatus\.textContent = .*syncResponsiveShell\(\);') {
        $content = $content -replace '(footerStatus\.textContent = .*?;)', ('$1' + "`r`n    syncResponsiveShell();")
    }
    $content = [regex]::Replace(
        $content,
        '(?m)(^[ \t]*syncResponsiveShell\(\);\r?\n){2,}',
        "    syncResponsiveShell();`r`n"
    )

    if ($content -notmatch 'window\.addEventListener\("resize", syncResponsiveShell\);') {
        $content = $content -replace '(document\.addEventListener\("keydown", function \(event\) \{[\s\S]*?\n  \}\);)', ('$1' + $resizeHook)
    }
    else {
        $content = [regex]::Replace($content, '(?m)^[ \t]*window\.addEventListener\("resize", syncResponsiveShell\);\r?\n', "")
        $content = [regex]::Replace($content, '(?m)^[ \t]*window\.addEventListener\("orientationchange", syncResponsiveShell\);\r?\n', "")
        $content = [regex]::Replace(
            $content,
            '(\}\);\r?\n)\s*window\.addEventListener\("resize", syncResponsiveShell\);\r?\n\s*window\.addEventListener\("orientationchange", syncResponsiveShell\);\r?\n(\s*var articleWordParts = \{)',
            '$1$2'
        )
        $content = $content -replace '(document\.addEventListener\("keydown", function \(event\) \{[\s\S]*?\n  \}\);)', ('$1' + $resizeHook)
    }

    if ($content -notmatch 'renderSentence\(\);\s+syncResponsiveShell\(\);\s+updateSlide\(\);') {
        $content = $content -replace 'renderSentence\(\);\s+updateSlide\(\);', "renderSentence();`r`n  syncResponsiveShell();`r`n  updateSlide();"
    }

    [System.IO.File]::WriteAllText($file, $content, [System.Text.UTF8Encoding]::new($false))
}
