@echo off
setlocal enabledelayedexpansion

set "output_file=combined_files.txt"
set "bat_file=%~nx0"

if exist "%output_file%" del "%output_file%"

echo Объединение файлов рекурсивно...
echo.

for /r %%f in (*) do (
    if /i not "%%f"=="%~f0" (
        echo Добавляю содержимое файла: %%f
        echo ------------------------- "%%f" ------------------------- >> "%output_file%"
        type "%%f" >> "%output_file%"
        echo. >> "%output_file%"
    )
)

echo.
echo Все файлы объединены в %output_file%
pause