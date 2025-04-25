#include "recompiler.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
using byte = uint8_t; using dword = uint32_t;

enum class IRKind { NOP, LDA_IMM, STA_ABS, JMP };
struct IR { IRKind kind; dword operand; };
static std::unordered_map<byte, IRKind> opcodeMap = {
    {0xA9, IRKind::LDA_IMM},
    {0x8D, IRKind::STA_ABS},
    {0x4C, IRKind::JMP},
};
static std::vector<byte> loadROM(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(f), {} };
}
static std::vector<IR> disassemble(const std::vector<byte>& rom) {
    std::vector<IR> irs; size_t pc = 0x8000;
    while (pc < rom.size()) {
        byte op = rom[pc++]; auto it = opcodeMap.find(op);
        if (it == opcodeMap.end()) break;
        IR inst{it->second,0};
        if (inst.kind == IRKind::LDA_IMM)
            inst.operand = rom[pc++];
        else if (inst.kind==IRKind::STA_ABS || inst.kind==IRKind::JMP) {
            inst.operand = rom[pc] | (rom[pc+1]<<8); pc+=2;
        }
        irs.push_back(inst);
    }
    return irs;
}
static void emitPrologue(std::ostream &out) { out<<"global _start\n_start:\n"; }
static void emitEpilogue(std::ostream &out) { out<<"  mov rax,60\n  xor rdi,rdi\n  syscall\n"; }
static void translate(const std::vector<IR>& irs, std::ostream &out) {
    emitPrologue(out);
    for (auto &i:irs) {
        switch(i.kind) {
            case IRKind::LDA_IMM: out<<"  mov al,"<<i.operand<<"\n"; break;
            case IRKind::STA_ABS: out<<"  mov [mem+"<<i.operand<<"],al\n"; break;
            case IRKind::JMP:    out<<"  jmp label_"<<i.operand<<"\n"; break;
            default: break;
        }
    }
    emitEpilogue(out);
    out<<"section .bss\nmem: resb 0x10000\n";
    for(auto &i:irs) if(i.kind==IRKind::JMP)
        out<<"label_"<<i.operand<<":\n";
}
bool recompileRom(const std::string &in, const std::string &outPath) {
    auto rom = loadROM(in);
    if (rom.empty()) return false;
    auto irs = disassemble(rom);
    std::ofstream o(outPath);
    if (!o) return false;
    translate(irs, o);
    return true;
}
int main(int argc, char**argv) {
    if(argc!=3) { std::cerr<<"Usage: recompiler <input.rom> <output.asm>\n"; return 1; }
    return recompileRom(argv[1], argv[2])?0:1;
}
