# ---------- recompiler.h ----------
#ifndef RECOMPILER_H
#define RECOMPILER_H

#include <string>

/**
 * Loads, disassembles, and translates a SNES ROM into x86-64 assembly.
 * CLI: recompiler <inputRom> <outputAsm>
 */
bool recompileRom(const std::string &inputPath, const std::string &outputAsm);

#endif // RECOMPILER_H
