@echo off
rem Builds the portable package: dist\PacketStory\ and PacketStory-Portable.zip
rem Needs: pip install pyinstaller cryptography   (end users need nothing, not even Python)
cd /d "%~dp0"
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
python -m PyInstaller --noconfirm --windowed --name PacketStory --add-data "index.html;." app.py || goto :err
copy /y README-PORTABLE.txt dist\PacketStory\README.txt >nul
copy /y LICENSE dist\PacketStory\LICENSE.txt >nul
if exist PacketStory-Portable.zip del PacketStory-Portable.zip
python make_zip.py || goto :err
echo.
echo Done: PacketStory-Portable.zip
goto :eof
:err
echo Build failed.
exit /b 1
