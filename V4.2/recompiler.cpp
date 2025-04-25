#include "recompiler.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <set>
#include <string>
#include <algorithm>
#include <iomanip>

using byte = uint8_t; 
using word = uint16_t;
using dword = uint32_t;

enum class IRKind { 
    NOP, LDA_IMM, LDA_ABS, LDA_ABSX, LDX_IMM, LDY_IMM,
    STA_ABS, STA_ABSX, STX_ABS, STY_ABS,
    JMP, JSR, RTS, BRA, BEQ, BNE, BMI, BPL, BCS, BCC,
    CMP_IMM, CPX_IMM, CPY_IMM, 
    INX, INY, DEX, DEY, INC_ABS, DEC_ABS,
    ADC_IMM, SBC_IMM, AND_IMM, ORA_IMM, EOR_IMM,
    ASL_ACC, LSR_ACC, ROL_ACC, ROR_ACC,
    TAX, TXA, TAY, TYA, TXS, TSX,
    PHA, PLA, PHP, PLP, 
    CLC, SEC, CLI, SEI, CLV
};

struct IR { 
    IRKind kind; 
    dword operand; 
    dword address; // Store the original address for generating labels
};

// Extended opcode map for 65816 processor
static std::unordered_map<byte, std::pair<IRKind, byte>> opcodeMap = {
    {0xEA, {IRKind::NOP, 0}},        // NOP
    
    // Load/Store operations
    {0xA9, {IRKind::LDA_IMM, 1}},    // LDA immediate
    {0xAD, {IRKind::LDA_ABS, 2}},    // LDA absolute
    {0xBD, {IRKind::LDA_ABSX, 2}},   // LDA absolute,X
    {0xA2, {IRKind::LDX_IMM, 1}},    // LDX immediate
    {0xA0, {IRKind::LDY_IMM, 1}},    // LDY immediate
    {0x8D, {IRKind::STA_ABS, 2}},    // STA absolute
    {0x9D, {IRKind::STA_ABSX, 2}},   // STA absolute,X
    {0x8E, {IRKind::STX_ABS, 2}},    // STX absolute
    {0x8C, {IRKind::STY_ABS, 2}},    // STY absolute
    
    // Transfer operations
    {0xAA, {IRKind::TAX, 0}},        // TAX
    {0x8A, {IRKind::TXA, 0}},        // TXA
    {0xA8, {IRKind::TAY, 0}},        // TAY
    {0x98, {IRKind::TYA, 0}},        // TYA
    {0x9A, {IRKind::TXS, 0}},        // TXS
    {0xBA, {IRKind::TSX, 0}},        // TSX
    
    // Stack operations
    {0x48, {IRKind::PHA, 0}},        // PHA
    {0x68, {IRKind::PLA, 0}},        // PLA
    {0x08, {IRKind::PHP, 0}},        // PHP
    {0x28, {IRKind::PLP, 0}},        // PLP
    
    // Jump/branch operations
    {0x4C, {IRKind::JMP, 2}},        // JMP absolute
    {0x20, {IRKind::JSR, 2}},        // JSR absolute
    {0x60, {IRKind::RTS, 0}},        // RTS
    {0x80, {IRKind::BRA, 1}},        // BRA relative
    {0xF0, {IRKind::BEQ, 1}},        // BEQ relative
    {0xD0, {IRKind::BNE, 1}},        // BNE relative
    {0x30, {IRKind::BMI, 1}},        // BMI relative
    {0x10, {IRKind::BPL, 1}},        // BPL relative
    {0xB0, {IRKind::BCS, 1}},        // BCS relative
    {0x90, {IRKind::BCC, 1}},        // BCC relative
    
    // Compare operations
    {0xC9, {IRKind::CMP_IMM, 1}},    // CMP immediate
    {0xE0, {IRKind::CPX_IMM, 1}},    // CPX immediate
    {0xC0, {IRKind::CPY_IMM, 1}},    // CPY immediate
    
    // Increment/Decrement operations
    {0xE8, {IRKind::INX, 0}},        // INX
    {0xC8, {IRKind::INY, 0}},        // INY
    {0xCA, {IRKind::DEX, 0}},        // DEX
    {0x88, {IRKind::DEY, 0}},        // DEY
    {0xEE, {IRKind::INC_ABS, 2}},    // INC absolute
    {0xCE, {IRKind::DEC_ABS, 2}},    // DEC absolute
    
    // Arithmetic/Logic operations
    {0x69, {IRKind::ADC_IMM, 1}},    // ADC immediate
    {0xE9, {IRKind::SBC_IMM, 1}},    // SBC immediate
    {0x29, {IRKind::AND_IMM, 1}},    // AND immediate
    {0x09, {IRKind::ORA_IMM, 1}},    // ORA immediate
    {0x49, {IRKind::EOR_IMM, 1}},    // EOR immediate
    
    // Shift operations
    {0x0A, {IRKind::ASL_ACC, 0}},    // ASL accumulator
    {0x4A, {IRKind::LSR_ACC, 0}},    // LSR accumulator
    {0x2A, {IRKind::ROL_ACC, 0}},    // ROL accumulator
    {0x6A, {IRKind::ROR_ACC, 0}},    // ROR accumulator
    
    // Status flag operations
    {0x18, {IRKind::CLC, 0}},        // CLC
    {0x38, {IRKind::SEC, 0}},        // SEC
    {0x58, {IRKind::CLI, 0}},        // CLI
    {0x78, {IRKind::SEI, 0}},        // SEI
    {0xB8, {IRKind::CLV, 0}}         // CLV
};

// Print a detailed hex dump of the ROM for debugging
static void printROMHeader(const std::vector<byte>& rom, size_t offset = 0, size_t count = 64) {
    std::cout << "ROM Header Dump (offset " << std::hex << offset << "):" << std::endl;
    
    count = std::min(count, rom.size() - offset);
    for (size_t i = 0; i < count; i += 16) {
        std::cout << std::hex << std::setw(4) << std::setfill('0') << (offset + i) << ": ";
        
        // Print hex values
        for (size_t j = 0; j < 16 && (i + j) < count; j++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(rom[offset + i + j]) << " ";
        }
        
        // Print ASCII representation
        std::cout << "  ";
        for (size_t j = 0; j < 16 && (i + j) < count; j++) {
            byte c = rom[offset + i + j];
            std::cout << (c >= 32 && c <= 126 ? static_cast<char>(c) : '.');
        }
        
        std::cout << std::endl;
    }
    std::cout << std::dec; // Reset to decimal
}

// LoROM mapping: logical address 0x8000-0xFFFF -> ROM offset
static size_t mapSNEStoPC(dword address, const std::vector<byte>& rom) {
    // For LoROM mapping:
    if (address >= 0x8000 && address <= 0xFFFF) {
        // Convert SNES address to ROM file offset
        return (address - 0x8000) % rom.size();
    }
    // For addresses below 0x8000, return the original address (RAM or I/O)
    return address % rom.size();
}

// Detect ROM header and load content
static std::vector<byte> loadROM(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "Failed to open ROM file: " << path << std::endl;
        return {};
    }
    
    std::vector<byte> rom((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    
    if (rom.empty()) {
        std::cerr << "ROM file is empty" << std::endl;
        return {};
    }
    
    std::cout << "ROM size: " << rom.size() << " bytes" << std::endl;
    
    // Check for SMC header (512 bytes)
    if (rom.size() % 1024 == 512) {
        std::cout << "Detected 512-byte SMC header, removing..." << std::endl;
        rom.erase(rom.begin(), rom.begin() + 512);
    }
    
    // Print the first bytes of the ROM for debugging
    printROMHeader(rom);
    
    return rom;
}

// Simplified ROM header analysis to find reset vector
static dword findResetVector(const std::vector<byte>& rom) {
    // In standard SNES ROMs, the reset vector is located at specific offsets
    // For LoROM, it's at 0x7FFC-0x7FFD in the ROM
    if (rom.size() >= 0x8000) {
        // Make sure we have enough data
        size_t resetVectorOffset = mapSNEStoPC(0xFFFC, rom);
        if (resetVectorOffset + 1 < rom.size()) {
            word resetVector = rom[resetVectorOffset] | (rom[resetVectorOffset + 1] << 8);
            std::cout << "Reset vector found at 0x" << std::hex << resetVector << std::dec << std::endl;
            return resetVector;
        }
    }
    
    // Default to 0x8000 if we can't determine the reset vector
    std::cout << "Could not determine reset vector, defaulting to 0x8000" << std::endl;
    return 0x8000;
}

// Disassemble ROM into intermediate representation
static std::vector<IR> disassemble(const std::vector<byte>& rom) {
    std::vector<IR> irs;
    
    // Try to find the reset vector as starting point
    dword startAddress = findResetVector(rom);
    dword pc = startAddress; // SNES logical address
    
    // For debugging: create a map of processed addresses to avoid infinite loops
    std::set<dword> processedAddresses;
    int instructionCount = 0;
    constexpr int maxInstructions = 5000; // Limit to prevent infinite loops
    
    std::cout << "Starting disassembly at 0x" << std::hex << pc << std::dec << std::endl;
    
    while (instructionCount < maxInstructions) {
        // Convert logical SNES address to ROM offset
        size_t offset = mapSNEStoPC(pc, rom);
        
        if (offset >= rom.size()) {
            std::cerr << "Warning: Address 0x" << std::hex << pc << " (offset 0x" << offset
                      << ") is out of ROM bounds" << std::dec << std::endl;
            break;
        }
        
        // Check if we've already processed this address to avoid infinite loops
        if (processedAddresses.find(pc) != processedAddresses.end()) {
            std::cout << "Already processed address 0x" << std::hex << pc 
                      << ", stopping disassembly" << std::dec << std::endl;
            break;
        }
        
        processedAddresses.insert(pc);
        
        byte opcode = rom[offset];
        dword originalAddress = pc;
        pc++;
        
        auto it = opcodeMap.find(opcode);
        if (it == opcodeMap.end()) {
            std::cerr << "Warning: Unknown opcode 0x" << std::hex << static_cast<int>(opcode) 
                      << " at address 0x" << originalAddress << " (offset 0x" << offset << ")" << std::dec << std::endl;
            
            // Insert a NOP and continue
            IR inst{IRKind::NOP, 0, originalAddress};
            irs.push_back(inst);
            continue;
        }
        
        IRKind kind = it->second.first;
        byte operandSize = it->second.second;
        IR inst{kind, 0, originalAddress};
        
        // Handle operands based on operand size
        switch (operandSize) {
            case 1: // 1-byte operand
                if (offset + 1 < rom.size()) {
                    inst.operand = rom[offset + 1];
                    pc += 1;
                }
                break;
                
            case 2: // 2-byte operand (16-bit address)
                if (offset + 2 < rom.size()) {
                    inst.operand = rom[offset + 1] | (rom[offset + 2] << 8);
                    pc += 2;
                }
                break;
                
            default: // No operand
                break;
        }
        
        // Special handling for branch instructions
        if (kind == IRKind::BEQ || kind == IRKind::BNE || 
            kind == IRKind::BMI || kind == IRKind::BPL ||
            kind == IRKind::BCS || kind == IRKind::BCC || 
            kind == IRKind::BRA) {
            // Convert relative branch to absolute address
            int8_t offset = static_cast<int8_t>(inst.operand);
            inst.operand = pc + offset;
        }
        
        irs.push_back(inst);
        instructionCount++;
        
        // Stop at RTS for now
        if (kind == IRKind::RTS) {
            break;
        }
    }
    
    std::cout << "Disassembled " << irs.size() << " instructions" << std::endl;
    return irs;
}

// Emit assembly prologue
static void emitPrologue(std::ostream &out) {
    out << "; SNES to x86_64 Recompiled Code\n";
    out << "bits 64\n";
    out << "default rel\n\n";
    out << "section .text\n";
    out << "global _start\n\n";
    out << "_start:\n";
    out << "  ; Initialize CPU registers\n";
    out << "  xor rax, rax    ; A register\n";
    out << "  xor rbx, rbx    ; X register\n";
    out << "  xor rcx, rcx    ; Y register\n";
    out << "  xor rdx, rdx    ; Status register (Z,N,C,V flags)\n";
    out << "  mov rsp, stack_end ; Initialize stack pointer\n";
    out << "\n";
}

// Emit assembly epilogue
static void emitEpilogue(std::ostream &out) {
    out << "\n  ; Exit the program\n";
    out << "exit_program:\n";
    out << "  mov rax, 60     ; syscall: exit\n";
    out << "  xor rdi, rdi    ; status: 0\n";
    out << "  syscall\n";
}

// Find all jump targets to generate labels
static std::set<dword> findJumpTargets(const std::vector<IR>& irs) {
    std::set<dword> targets;
    
    for (const auto& ir : irs) {
        switch (ir.kind) {
            case IRKind::JMP:
            case IRKind::JSR:
            case IRKind::BRA:
            case IRKind::BEQ:
            case IRKind::BNE:
            case IRKind::BMI:
            case IRKind::BPL:
            case IRKind::BCS:
            case IRKind::BCC:
                targets.insert(ir.operand);
                break;
            default:
                break;
        }
    }
    
    return targets;
}

// Translate IR to x86_64 assembly
static void translate(const std::vector<IR>& irs, std::ostream &out) {
    emitPrologue(out);
    
    // Find all jump targets first
    std::set<dword> jumpTargets = findJumpTargets(irs);
    
    // Generate assembly code
    for (const auto& ir : irs) {
        // If this address is a jump target, add a label
        if (jumpTargets.find(ir.address) != jumpTargets.end()) {
            out << "label_" << std::hex << ir.address << ":\n";
        }
        
        // Convert IR to x86_64 instructions with comments showing original SNES instruction
        out << "  ; 0x" << std::hex << ir.address << ": ";
        
        switch (ir.kind) {
            // No-operation
            case IRKind::NOP:
                out << "NOP\n";
                out << "  nop\n";
                break;
                
            // Load operations
            case IRKind::LDA_IMM:
                out << "LDA #$" << std::hex << ir.operand << "\n";
                out << "  mov al, " << std::dec << ir.operand << "\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::LDA_ABS:
                out << "LDA $" << std::hex << ir.operand << "\n";
                out << "  mov al, [mem+" << std::dec << ir.operand << "]\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::LDA_ABSX:
                out << "LDA $" << std::hex << ir.operand << ",X\n";
                out << "  movzx rsi, bl       ; X register\n";
                out << "  add rsi, " << std::dec << ir.operand << "\n";
                out << "  and rsi, 0xFFFF     ; 16-bit address space\n";
                out << "  mov al, [mem+rsi]\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::LDX_IMM:
                out << "LDX #$" << std::hex << ir.operand << "\n";
                out << "  mov bl, " << std::dec << ir.operand << "\n";
                out << "  mov dl, bl\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::LDY_IMM:
                out << "LDY #$" << std::hex << ir.operand << "\n";
                out << "  mov cl, " << std::dec << ir.operand << "\n";
                out << "  mov dl, cl\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            // Store operations
            case IRKind::STA_ABS:
                out << "STA $" << std::hex << ir.operand << "\n";
                out << "  mov [mem+" << std::dec << ir.operand << "], al\n";
                break;
                
            case IRKind::STA_ABSX:
                out << "STA $" << std::hex << ir.operand << ",X\n";
                out << "  movzx rsi, bl       ; X register\n";
                out << "  add rsi, " << std::dec << ir.operand << "\n";
                out << "  and rsi, 0xFFFF     ; 16-bit address space\n";
                out << "  mov [mem+rsi], al\n";
                break;
                
            case IRKind::STX_ABS:
                out << "STX $" << std::hex << ir.operand << "\n";
                out << "  mov [mem+" << std::dec << ir.operand << "], bl\n";
                break;
                
            case IRKind::STY_ABS:
                out << "STY $" << std::hex << ir.operand << "\n";
                out << "  mov [mem+" << std::dec << ir.operand << "], cl\n";
                break;
                
            // Register transfer operations
            case IRKind::TAX:
                out << "TAX\n";
                out << "  mov bl, al\n";
                out << "  mov dl, bl\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::TXA:
                out << "TXA\n";
                out << "  mov al, bl\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::TAY:
                out << "TAY\n";
                out << "  mov cl, al\n";
                out << "  mov dl, cl\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::TYA:
                out << "TYA\n";
                out << "  mov al, cl\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::TXS:
                out << "TXS\n";
                out << "  mov sil, bl         ; Set stack pointer from X\n";
                break;
                
            case IRKind::TSX:
                out << "TSX\n";
                out << "  mov bl, sil         ; Set X from stack pointer\n";
                out << "  mov dl, bl\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            // Stack operations
            case IRKind::PHA:
                out << "PHA\n";
                out << "  dec rsp\n";
                out << "  mov [rsp], al\n";
                break;
                
            case IRKind::PLA:
                out << "PLA\n";
                out << "  mov al, [rsp]\n";
                out << "  inc rsp\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::PHP:
                out << "PHP\n";
                out << "  dec rsp\n";
                out << "  mov [rsp], dl       ; Save status flags\n";
                break;
                
            case IRKind::PLP:
                out << "PLP\n";
                out << "  mov dl, [rsp]       ; Restore status flags\n";
                out << "  inc rsp\n";
                break;
                
            // Jump/Branch operations
            case IRKind::JMP:
                out << "JMP $" << std::hex << ir.operand << "\n";
                out << "  jmp label_" << std::hex << ir.operand << "\n";
                break;
                
            case IRKind::JSR:
                out << "JSR $" << std::hex << ir.operand << "\n";
                out << "  ; Push return address - 1\n";
                out << "  mov r8, " << std::dec << ir.address + 3 - 1 << "\n";
                out << "  sub rsp, 2\n";
                out << "  mov [rsp], r8w\n";
                out << "  jmp label_" << std::hex << ir.operand << "\n";
                break;
                
            case IRKind::RTS:
                out << "RTS\n";
                out << "  ; Pop return address and add 1\n";
                out << "  movzx r8, word [rsp]\n";
                out << "  add rsp, 2\n";
                out << "  inc r8\n";
                out << "  jmp label_r8         ; Dynamic jump to address in r8\n";
                break;
                
            case IRKind::BRA:
                out << "BRA $" << std::hex << ir.operand << "\n";
                out << "  jmp label_" << std::hex << ir.operand << "\n";
                break;
                
            case IRKind::BEQ:
                out << "BEQ $" << std::hex << ir.operand << "\n";
                out << "  test dh, 1          ; Test Z flag\n";
                out << "  jnz label_" << std::hex << ir.operand << "\n";
                break;
                
            case IRKind::BNE:
                out << "BNE $" << std::hex << ir.operand << "\n";
                out << "  test dh, 1          ; Test Z flag\n";
                out << "  jz label_" << std::hex << ir.operand << "\n";
                break;
                
            case IRKind::BMI:
                out << "BMI $" << std::hex << ir.operand << "\n";
                out << "  test dl, 0x80       ; Test N flag\n";
                out << "  jnz label_" << std::hex << ir.operand << "\n";
                break;
                
            case IRKind::BPL:
                out << "BPL $" << std::hex << ir.operand << "\n";
                out << "  test dl, 0x80       ; Test N flag\n";
                out << "  jz label_" << std::hex << ir.operand << "\n";
                break;
                
            case IRKind::BCS:
                out << "BCS $" << std::hex << ir.operand << "\n";
                out << "  test r9b, 1         ; Test C flag\n";
                out << "  jnz label_" << std::hex << ir.operand << "\n";
                break;
                
            case IRKind::BCC:
                out << "BCC $" << std::hex << ir.operand << "\n";
                out << "  test r9b, 1         ; Test C flag\n";
                out << "  jz label_" << std::hex << ir.operand << "\n";
                break;
                
            // Compare operations
            case IRKind::CMP_IMM:
                out << "CMP #$" << std::hex << ir.operand << "\n";
                out << "  cmp al, " << std::dec << ir.operand << "\n";
                out << "  setc r9b            ; Set C flag\n";
                out << "  setz dh             ; Set Z flag\n";
                out << "  sets dl             ; Set N flag\n";
                break;
                
            case IRKind::CPX_IMM:
                out << "CPX #$" << std::hex << ir.operand << "\n";
                out << "  cmp bl, " << std::dec << ir.operand << "\n";
                out << "  setc r9b            ; Set C flag\n";
                out << "  setz dh             ; Set Z flag\n";
                out << "  sets dl             ; Set N flag\n";
                break;
                
            case IRKind::CPY_IMM:
                out << "CPY #$" << std::hex << ir.operand << "\n";
                out << "  cmp cl, " << std::dec << ir.operand << "\n";
                out << "  setc r9b            ; Set C flag\n";
                out << "  setz dh             ; Set Z flag\n";
                out << "  sets dl             ; Set N flag\n";
                break;
                
            // Increment/Decrement operations
            case IRKind::INX:
                out << "INX\n";
                out << "  inc bl\n";
                out << "  mov dl, bl\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::INY:
                out << "INY\n";
                out << "  inc cl\n";
                out << "  mov dl, cl\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
break;
                
            case IRKind::DEX:
                out << "DEX\n";
                out << "  dec bl\n";
                out << "  mov dl, bl\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::DEY:
                out << "DEY\n";
                out << "  dec cl\n";
                out << "  mov dl, cl\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::INC_ABS:
                out << "INC $" << std::hex << ir.operand << "\n";
                out << "  inc byte [mem+" << std::dec << ir.operand << "]\n";
                out << "  mov r8b, [mem+" << ir.operand << "]\n";
                out << "  mov dl, r8b\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::DEC_ABS:
                out << "DEC $" << std::hex << ir.operand << "\n";
                out << "  dec byte [mem+" << std::dec << ir.operand << "]\n";
                out << "  mov r8b, [mem+" << ir.operand << "]\n";
                out << "  mov dl, r8b\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            // Arithmetic/Logic operations
            case IRKind::ADC_IMM:
                out << "ADC #$" << std::hex << ir.operand << "\n";
                out << "  movzx r8, al        ; A register\n";
                out << "  movzx r9, r9b       ; Carry flag\n";
                out << "  add r8, r9          ; Add carry\n";
                out << "  add r8, " << std::dec << ir.operand << "\n";
                out << "  setc r9b            ; Set new carry flag\n";
                out << "  mov al, r8b         ; Store result back to A\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::SBC_IMM:
                out << "SBC #$" << std::hex << ir.operand << "\n";
                out << "  movzx r8, al        ; A register\n";
                out << "  movzx r9, r9b       ; Carry flag\n";
                out << "  sub r8, " << std::dec << ir.operand << "\n";
                out << "  sub r8, r9          ; Subtract !carry\n";
                out << "  setc r9b            ; Set new carry flag\n";
                out << "  xor r9b, 1          ; Invert carry for SBC\n";
                out << "  mov al, r8b         ; Store result back to A\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::AND_IMM:
                out << "AND #$" << std::hex << ir.operand << "\n";
                out << "  and al, " << std::dec << ir.operand << "\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::ORA_IMM:
                out << "ORA #$" << std::hex << ir.operand << "\n";
                out << "  or al, " << std::dec << ir.operand << "\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::EOR_IMM:
                out << "EOR #$" << std::hex << ir.operand << "\n";
                out << "  xor al, " << std::dec << ir.operand << "\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            // Shift operations
            case IRKind::ASL_ACC:
                out << "ASL A\n";
                out << "  shl al, 1\n";
                out << "  setc r9b            ; Set C flag from bit 7\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::LSR_ACC:
                out << "LSR A\n";
                out << "  shr al, 1\n";
                out << "  setc r9b            ; Set C flag from bit 0\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag (always 0)\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::ROL_ACC:
                out << "ROL A\n";
                out << "  mov r8b, r9b        ; Get old carry\n";
                out << "  shl al, 1\n";
                out << "  or al, r8b          ; OR with old carry\n";
                out << "  setc r9b            ; Set new carry\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            case IRKind::ROR_ACC:
                out << "ROR A\n";
                out << "  mov r8b, r9b        ; Get old carry\n";
                out << "  shl r8b, 7          ; Position for bit 7\n";
                out << "  shr al, 1\n";
                out << "  or al, r8b          ; OR with old carry in bit 7\n";
                out << "  setc r9b            ; Set new carry\n";
                out << "  mov dl, al\n";
                out << "  and dl, 0x80        ; Set N flag\n";
                out << "  setz dh             ; Set Z flag\n";
                break;
                
            // Status flag operations
            case IRKind::CLC:
                out << "CLC\n";
                out << "  xor r9b, r9b        ; Clear carry flag\n";
                break;
                
            case IRKind::SEC:
                out << "SEC\n";
                out << "  mov r9b, 1          ; Set carry flag\n";
                break;
                
            case IRKind::CLI:
                out << "CLI\n";
                out << "  and r10b, 0xFB      ; Clear interrupt disable flag\n";
                break;
                
            case IRKind::SEI:
                out << "SEI\n";
                out << "  or r10b, 0x04       ; Set interrupt disable flag\n";
                break;
                
            case IRKind::CLV:
                out << "CLV\n";
                out << "  and r10b, 0xBF      ; Clear overflow flag\n";
                break;
                
            default:
                out << "Unimplemented opcode\n";
                out << "  nop                 ; Not implemented yet\n";
                break;
        }
    }
    
    // Add a dynamic jump handler for RTS
    out << "\nlabel_r8:\n";
    out << "  ; Dynamic jump based on r8 value (for RTS)\n";
    
    // Generate jump table for all possible return addresses
    std::set<dword> allAddresses;
    for (const auto& ir : irs) {
        allAddresses.insert(ir.address);
    }
    
    for (dword addr : allAddresses) {
        out << "  cmp r8, " << std::dec << addr << "\n";
        out << "  je label_" << std::hex << addr << "\n";
    }
    
    // If no match, exit
    out << "  jmp exit_program  ; No valid return address found\n";
    
    emitEpilogue(out);
    
    // Add the data section
    out << "\nsection .bss\n";
    out << "mem: resb 0x10000  ; 64KB of SNES memory\n";
    out << "stack: resb 256    ; Stack area (256 bytes)\n";
    out << "stack_end: resb 0  ; End of stack area\n";
}

bool recompileRom(const std::string &in, const std::string &outPath) {
    auto rom = loadROM(in);
    if (rom.empty()) {
        std::cerr << "Failed to load ROM or ROM is empty" << std::endl;
        return false;
    }
    
    std::cout << "ROM loaded: " << rom.size() << " bytes" << std::endl;
    
    auto irs = disassemble(rom);
    if (irs.empty()) {
        std::cerr << "Disassembly produced no instructions" << std::endl;
        return false;
    }
    
    std::cout << "Disassembled " << irs.size() << " instructions" << std::endl;
    
    std::ofstream out(outPath);
    if (!out) {
        std::cerr << "Failed to open output file: " << outPath << std::endl;
        return false;
    }
    
    translate(irs, out);
    std::cout << "Assembly written to: " << outPath << std::endl;
    
    return true;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        std::cerr << "Usage: recompiler <input.rom> <output.asm>\n";
        return 1;
    }
    
    return recompileRom(argv[1], argv[2]) ? 0 : 1;
}