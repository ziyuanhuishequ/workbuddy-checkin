@echo off
chcp 936 >nul 2>&1
title 找凭据文件 credentials.json
setlocal enabledelayedexpansion
set "FIRST="
set "N=0"
echo ============================================
echo    WorkBuddy 自动签到 - 找凭据文件
echo ============================================
echo.
echo 第一步：先看最常见的几个位置（几秒钟）...
echo.
call :scan "%USERPROFILE%\.codebuddy\instances"
call :scan "%USERPROFILE%\.codebuddy"
call :scan "%APPDATA%\CodeBuddy"
call :scan "%LOCALAPPDATA%\CodeBuddy"
call :scan "%USERPROFILE%\Documents"
call :scan "%USERPROFILE%\Desktop"
call :scan "%USERPROFILE%\Downloads"

if defined FIRST goto :found

echo.
echo 常见位置里没有。它也可能被装在别的盘、别的目录，
echo 要不要全盘再搜一次？
echo （要 1-3 分钟，中途别关窗口）
echo.
set "ANS="
set /p "ANS=要全盘搜索请输入 Y 再回车（直接回车 = 跳过）："
if /i not "%ANS%"=="Y" goto :notfound

for %%D in (C D E F G H) do (
    if exist "%%D://" (
        echo.
        echo 正在搜索 %%D: 盘 ...
        call :scan "%%D:"
    )
)

if defined FIRST goto :found

:notfound
echo.
echo ============================================
echo    这台电脑上没有 credentials.json
echo ============================================
echo.
echo 不用再找了 —— 这个文件是「命令行版（CLI）」登录后才生成的，
echo 只装桌面版图形客户端的人根本没有它，不是你操作错了。
echo.
echo 接下来这样做（不需要任何文件）：
echo   1. 用浏览器打开管理员给你的那个链接（.../join?t=...）
echo   2. 点「打开电脑端登录页」
echo   3. 手机微信扫电脑屏幕上出现的二维码，手机上点确认
echo.
pause
exit /b 0

:found
echo.
echo ============================================
echo    找到 %N% 个，用第一个：
echo    !FIRST!
echo ============================================
echo.
echo 要不要把它里面的内容直接复制到剪贴板？
echo （复制好后，在网页的输入框里按 Ctrl+V 就能粘进去）
set "CP="
set /p "CP=复制请输入 Y 再回车（直接回车 = 只打开文件夹）："
if /i "!CP!"=="Y" (
    clip < "!FIRST!"
    echo.
    echo 已复制到剪贴板。
)
echo.
echo 正在打开它所在的文件夹 ...
explorer.exe /select,"!FIRST!"
echo.
pause
exit /b 0

:scan
if not exist "%~1" goto :eof
for /f "delims=" %%F in ('dir /s /b "%~1\credentials*.json" 2^>nul') do (
    echo    [找到] %%F
    if not defined FIRST set "FIRST=%%F"
    set /a N+=1
)
goto :eof
