@echo off
REM =====================================================
REM Build Script for SNES Recompiler Project
REM =====================================================

REM 1) Compile the SNES recompiler CLI tool
if not exist recompiler.cpp (
    echo ERROR: recompiler.cpp not found.
    pause
    exit /b 1
)
g++ -std=c++17 recompiler.cpp -o recompiler.exe
if errorlevel 1 (
    echo ERROR: Failed building recompiler.exe
    pause
    exit /b 1
)

echo recompiler.exe built successfully.

REM 2) Compile the Win32 GUI (if present)
if exist main_cpp_gui.cpp (
    echo Building Win32 GUI...
    g++ -std=c++17 main_cpp_gui.cpp -o gui.exe -municode -static -static-libstdc++ -static-libgcc -lgdi32 -lcomdlg32 -lshell32
    if errorlevel 1 (
        echo ERROR: Failed building gui.exe
        pause
        exit /b 1
    )
    echo gui.exe built successfully.
) else (
    echo Skipping Win32 GUI: main_cpp_gui.cpp not found.
)

echo All builds complete.
pause

// End of project
