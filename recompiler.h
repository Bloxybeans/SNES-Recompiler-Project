#ifndef RECOMPILER_H
#define RECOMPILER_H

#include <string>

/**
 * Loads, disassembles, and translates a SNES ROM into x86-64 assembly.
 * @param inputPath Path to the SNES ROM file.
 * @param outputAsm Path for the generated assembly (.asm) file.
 * @return true on success, false on failure.
 */
bool recompileRom(const std::string &inputPath, const std::string &outputAsm);

#endif // RECOMPILER_H