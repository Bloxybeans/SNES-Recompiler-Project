// SNES-to-x86_64 Recompiler GUI (Python/Tkinter)
// ========================================
// PREREQUISITES:
// 1. Python 3.6+ (with tkinter) installed and on PATH.
// 2. A compiled C++ recompiler CLI tool `recompiler.exe` built from recompiler.cpp:
//      g++ -std=c++17 recompiler.cpp -o recompiler.exe
// 3. Place `recompiler.exe` and `gui.py` in the same directory.
//
// USAGE:
// 1. Run `python gui.py` to launch the GUI.
// 2. "Add ROM..." to select one or more SNES ROMs (.sfc/.smc).
// 3. Select an entry and click "Compile" to generate `<rom>.asm` via recompiler.exe.
