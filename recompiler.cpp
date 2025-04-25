#include "recompiler.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>

using byte  = uint8_t;
using word  = uint16_t;
using dword = uint32_t;

enum class IRKind { NOP, LDA_IMM, STA_ABS, JMP };

struct IR {
    IRKind kind;
    dword  operand;
};

static std::unordered_map<byte, IRKind> opcodeMap = {
    {0xA9, IRKind::LDA_IMM},  // LDA #imm
    {0x8D, IRKind::STA_ABS},  // STA abs
    {0x4C, IRKind::JMP},      // JMP abs
};

static std::vector<byte> loadROM(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    return std::vector<byte>(
        std::istreambuf_iterator<char>(f), {}
    );
}

static std::vector<IR> disassemble(const std::vector<byte> &rom) {
    std::vector<IR> irs;
    size_t pc = 0x8000;
    while (pc < rom.size()) {
        byte op = rom[pc++];
        auto it = opcodeMap.find(op);
        if (it == opcodeMap.end()) break;
        IR inst{ it->second, 0 };
        switch (inst.kind) {
            case IRKind::LDA_IMM:
                inst.operand = rom[pc++];
                break;
            case IRKind::STA_ABS:
            case IRKind::JMP:
                inst.operand = rom[pc] | (rom[pc+1] << 8);
                pc += 2;
                break;
            default:
                break;
        }
        irs.push_back(inst);
    }
    return irs;
}

static void emitPrologue(std::ostream &out) {
    out << "global _start\n_start:\n";
}

static void emitEpilogue(std::ostream &out) {
    out << "  mov rax, 60\n  xor rdi, rdi\n  syscall\n";
}

static void translate(const std::vector<IR> &irs, std::ostream &out) {
    emitPrologue(out);
    for (const auto &i : irs) {
        switch (i.kind) {
            case IRKind::LDA_IMM:
                out << "  mov al, " << i.operand << "\n";
                break;
            case IRKind::STA_ABS:
                out << "  mov [mem+" << i.operand << "], al\n";
                break;
            case IRKind::JMP:
                out << "  jmp label_" << i.operand << "\n";
                break;
            default:
                break;
        }
    }
    emitEpilogue(out);
    out << "section .bss\nmem: resb 0x10000\n";
    for (const auto &i : irs) {
        if (i.kind == IRKind::JMP)
            out << "label_" << i.operand << ":\n";
    }
}

bool recompileRom(const std::string &inputPath, const std::string &outputAsm) {
    auto rom = loadROM(inputPath);
    if (rom.empty()) return false;
    auto irs = disassemble(rom);
    std::ofstream out(outputAsm);
    if (!out) return false;
    translate(irs, out);
    return true;
}

// ---------- Build with g++ (MinGW) ----------
// Adjust the Qt path to match your installation
// Example command:
// g++ -std=c++17 main.cpp recompiler.cpp \
//     -IC:/Qt/5.15.2/mingw81_64/include \
//     -IC:/Qt/5.15.2/mingw81_64/include/QtWidgets \
//     -IC:/Qt/5.15.2/mingw81_64/include/QtCore \
//     -IC:/Qt/5.15.2/mingw81_64/include/QtGui \
//     -IC:/Qt/5.15.2/mingw81_64/mkspecs/win32-g++ \
//     -LC:/Qt/5.15.2/mingw81_64/lib \
//     -lmingw32 -lQt5Widgets -lQt5Gui -lQt5Core \
//     -lopengl32 -lgdi32 -luser32 -lkernel32 -o SNESRecompilerGUI.exe
//
// After building, ensure Qt DLLs (if dynamically linked) are available in PATH or next to the .exe.
