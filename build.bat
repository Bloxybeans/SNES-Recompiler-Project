@echo off
REM ─────────────────────────────────────────────────────────────────
REM Build SNESRecompilerGUI with MinGW/g++ and Qt Moc
REM ─────────────────────────────────────────────────────────────────

REM 1) Point this to your Qt for MinGW installation:
set "QT_DIR=C:\Qt\5.15.2\mingw81_64"

REM 2) Include and library flags:
set "INCLUDE_FLAGS=-I%QT_DIR%\include ^
 -I%QT_DIR%\include\QtWidgets ^
 -I%QT_DIR%\include\QtCore ^
 -I%QT_DIR%\include\QtGui ^
 -I%QT_DIR%\mkspecs\win32-g++"
set "LIB_FLAGS=-L%QT_DIR%\lib ^
 -lmingw32 -lQt5Widgets -lQt5Gui -lQt5Core ^
 -lopengl32 -lgdi32 -luser32 -lkernel32"

REM 3) Run Qt’s Meta-Object Compiler on main.cpp:
"%QT_DIR%\bin\moc.exe" main.cpp -o moc_main.cpp
if errorlevel 1 (
  echo *** ERROR: moc failed ***
  pause & exit /b 1
)

REM 4) Compile all sources into SNESRecompilerGUI.exe:
g++ -std=c++17 main.cpp moc_main.cpp recompiler.cpp %INCLUDE_FLAGS% %LIB_FLAGS% -o SNESRecompilerGUI.exe
if errorlevel 1 (
  echo *** ERROR: compilation failed ***
  pause & exit /b 1
)

echo.
echo Build succeeded: SNESRecompilerGUI.exe
pause
