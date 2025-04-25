# SNES-to-x86_64 Recompiler

This toolchain converts Super Nintendo (SNES) ROMs into x86-64 assembly and optionally into native Windows executables.

## Features
- **Disassembles** 65c816 instructions from SNES ROMs into an intermediate representation.
- **Translates** IR to x86-64 NASM assembly (`.asm`).
- **Minimal dependencies**: written in C++17, no Qt required.
- **Optional GUI**: pure Win32 frontend (`main_cpp_gui.cpp`).

## Prerequisites
- **MinGW-w64** toolchain (g++ in PATH)
- **NASM** assembler in PATH (for `asm2exe` wrapper)
- **Windows** environment (cmd / PowerShell)

## Build Instructions
1. Open a Command Prompt with MinGW and NASM in your `PATH`.
2. Run the provided `build.bat`:
   ```bat
   build.bat
   ```
   This builds:
   - `recompiler.exe` (SNES ROM → `.asm`)
   - `asm2exe.exe`  (Experimental)   (NASM + linker wrapper)
   - `gui.exe`         (optional Win32 GUI frontend)

## Usage
### Command-Line Mode
```bat
rem Generate x86-64 assembly from SNES ROM
recompiler.exe game.sfc game.asm

(For use with asm2exe move the built asm file to the project directory)

rem Assemble & link into executable
asm2exe.exe game.asm
```
The above produces `game.exe` in the same directory.

### GUI Mode
```bat
gui.exe
```
- Click **Add ROM...** to select a `.sfc`/`.smc` file.
- Select a ROM in the list and click **Compile**.
- A `.asm` will be generated next to your ROM, then assembled and linked.

## Directory Layout
```
project/
├── recompiler.cpp
├── recompiler.h
├── asm2exe.cpp  (experimental)
├── main_cpp_gui.cpp  (optional)
├── build.bat
├── README_recompiler.md
└── README_asm2exe.md
```

---
