# Установка / обновление OSINT Recon как настольного приложения.
# Запуск: powershell -ExecutionPolicy Bypass -File install.ps1
# Каталог установки — в профиле пользователя (не в AppData: Python из Microsoft Store
# перенаправляет туда запись, и файлы становятся невидимы для других программ).
param(
    [string]$Target = (Join-Path $env:USERPROFILE "OSINT Recon"),
    [switch]$NoShortcuts
)
$ErrorActionPreference = "Stop"
$Src = $PSScriptRoot
Write-Host "OSINT Recon → $Target"

# 1. Python
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { throw "Не найден Python 3.10+. Установите его (python.org или Microsoft Store) и повторите." }
$ver = & $py -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ([version]$ver -lt [version]"3.10") { throw "Нужен Python 3.10+, найден $ver" }

# 2. Код приложения
New-Item -ItemType Directory -Force "$Target\app", "$Target\data" | Out-Null
robocopy "$Src\osint_recon" "$Target\app\osint_recon" /MIR /XD __pycache__ /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "Ошибка копирования файлов (robocopy $LASTEXITCODE)" }
Copy-Item "$Src\requirements.txt", "$Src\launch.pyw" "$Target\" -Force
if (Test-Path "$Src\README.md") { Copy-Item "$Src\README.md" "$Target\" -Force }

# 3. Виртуальное окружение и зависимости
$venvPy = "$Target\venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    Write-Host "Создаю окружение Python…"
    & $py -m venv "$Target\venv"
}
Write-Host "Устанавливаю зависимости…"
& $venvPy -m pip install --disable-pip-version-check -q --upgrade pip | Out-Null
& $venvPy -m pip install --disable-pip-version-check -q -r "$Target\requirements.txt"
if ($LASTEXITCODE -ne 0) { throw "pip install завершился с ошибкой" }
& $venvPy -c "import sys; sys.path.insert(0, r'$Target\app'); import osint_recon.main, webview; print('проверка импорта: ok')"
if ($LASTEXITCODE -ne 0) { throw "Проверка импорта не прошла" }

# 4. Ярлыки
if (-not $NoShortcuts) {
    $pyw = "$Target\venv\Scripts\pythonw.exe"
    $icon = "$Target\app\osint_recon\static\app.ico"
    $shell = New-Object -ComObject WScript.Shell
    $places = @(
        [Environment]::GetFolderPath("Desktop"),
        (Join-Path ([Environment]::GetFolderPath("Programs")) "")
    )
    foreach ($dir in $places) {
        $lnk = $shell.CreateShortcut((Join-Path $dir "OSINT Recon.lnk"))
        $lnk.TargetPath = $pyw
        $lnk.Arguments = "`"$Target\launch.pyw`""
        $lnk.WorkingDirectory = $Target
        $lnk.IconLocation = "$icon,0"
        $lnk.Description = "OSINT Recon — разведка по домену и организации"
        $lnk.Save()
        Write-Host "Ярлык: $(Join-Path $dir 'OSINT Recon.lnk')"
    }
}
Write-Host "Готово. Данные и настройки: $Target\data"
