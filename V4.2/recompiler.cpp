#include "recompiler.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <set>
#include <queue> // Added for worklist
#include <string>
#include <algorithm>
#include <iomanip>
#include <map> // Added for sorting IR by address

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
    // Add BRK, COP, etc. if needed
};

struct IR {
    IRKind kind;
    dword operand;
    dword address; // Store the original address

    // Add a comparison operator for sorting
    bool operator<(const IR& other) const {
        return address < other.address;
    }
};

// Extended opcode map for 65816 processor (Keep this updated)
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
// TODO: This needs proper bank handling for addresses outside 0x8000-0xFFFF and > 32KB ROMs
static size_t mapSNEStoPC(dword address, const std::vector<byte>& rom) {
    // Basic LoROM mapping for bank 0x00 (addresses 0x0000-0xFFFF)
    // Needs expansion for full SNES memory map (banks, RAM, I/O)
    if (address >= 0x8000 && address <= 0xFFFF) {
        // Maps bank 0 $8000-$FFFF to the first 32KB of the ROM file
        size_t romOffset = address - 0x8000;
        if (romOffset < rom.size()) {
            return romOffset;
        }
    }
    // Other addresses (like $0000-$7FFF) might be RAM or I/O - map carefully
    // Returning address % rom.size() is likely incorrect for real mapping
    // For now, just return offset within the file size if it's below 0x8000
    // This simplistic mapping will break for code/data outside the first 32KB
    if (address < rom.size()) {
       return address;
    }

    // Indicate an invalid mapping for addresses clearly outside the current simple scope
    std::cerr << "Warning: mapSNEStoPC cannot map address 0x" << std::hex << address << std::dec << ". Needs proper bank handling." << std::endl;
    return rom.size(); // Return an invalid offset
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
        std::cout << "ROM size after header removal: " << rom.size() << " bytes" << std::endl;
    }

    // Print the first bytes of the ROM for debugging
    printROMHeader(rom);

    return rom;
}

// Simplified ROM header analysis to find reset vector
static dword findResetVector(const std::vector<byte>& rom) {
    // In standard SNES ROMs, the reset vector is located at specific offsets
    // For LoROM, it's at 0x7FFC-0x7FFD relative to the start of the ROM data
    // The SNES reads $FFFC-$FFFD from the memory map
    size_t resetVectorRomOffset = 0x7FFC; // Offset within the first 32KB block for LoROM
    if (resetVectorRomOffset + 1 < rom.size()) {
         // The value stored here is the *address* the CPU should jump to
        word resetAddress = rom[resetVectorRomOffset] | (rom[resetVectorRomOffset + 1] << 8);
        std::cout << "Reset vector found in ROM at 0x7FFC points to address 0x" << std::hex << resetAddress << std::dec << std::endl;
        // We assume this address is within the mapped ROM space (e.g., $8000 or higher)
        // TODO: Verify the reset address is reasonable (e.g., >= 0x8000)
        return resetAddress;
    }


    // Default to 0x8000 if we can't determine the reset vector
    std::cout << "Could not read reset vector from ROM offset 0x7FFC, defaulting to 0x8000" << std::endl;
    return 0x8000;
}

// Disassemble ROM using iterative approach
static std::vector<IR> disassemble(const std::vector<byte>& rom) {
    std::map<dword, IR> irMap; // Use map to store IR by address, helps keep sorted
    std::set<dword> processedAddresses; // Tracks addresses already disassembled
    std::queue<dword> worklist; // Addresses pending disassembly

    // Try to find the reset vector as starting point
    dword startAddress = findResetVector(rom);
    if (startAddress != 0) { // Check if reset vector is valid
         worklist.push(startAddress);
    } else {
        std::cerr << "Error: Could not determine a valid start address." << std::endl;
        return {};
    }

    std::cout << "Starting disassembly..." << std::endl;

    while (!worklist.empty()) {
        dword currentPC = worklist.front();
        worklist.pop();

        // Skip if already processed or clearly invalid (e.g., RAM address without proper mapping)
        // Basic check: assume code is >= 0x8000 for now
        if (processedAddresses.count(currentPC) || currentPC < 0x8000) {
             // If it's RAM/IO, we might need different handling later
             if (!processedAddresses.count(currentPC) && currentPC < 0x8000) {
                 // std::cout << "Skipping disassembly of potential RAM/IO address 0x" << std::hex << currentPC << std::dec << std::endl;
                 processedAddresses.insert(currentPC); // Mark as processed to avoid re-queueing
             }
            continue;
        }

        // Disassemble block starting from currentPC
        while (true) {
            if (processedAddresses.count(currentPC)) {
                // We've hit an address that's already been processed (start of another block or loop)
                break;
            }

            size_t offset = mapSNEStoPC(currentPC, rom);
            if (offset >= rom.size()) {
                std::cerr << "Warning: Address 0x" << std::hex << currentPC << " maps out of ROM bounds (offset " << offset << ")" << std::dec << std::endl;
                 processedAddresses.insert(currentPC); // Mark as processed to prevent loop
                break; // Stop processing this path
            }

            processedAddresses.insert(currentPC); // Mark current address as processed

            byte opcode = rom[offset];
            dword instructionAddress = currentPC;
            dword nextPC = currentPC + 1; // PC after opcode fetch

            auto it = opcodeMap.find(opcode);
            if (it == opcodeMap.end()) {
                std::cerr << "Warning: Unknown opcode 0x" << std::hex << static_cast<int>(opcode)
                          << " at address 0x" << instructionAddress << " (offset 0x" << offset << ")" << std::dec << std::endl;
                // Insert a NOP and continue processing linearly (might be wrong)
                 IR inst{IRKind::NOP, 0, instructionAddress};
                 irMap[instructionAddress] = inst;
                 currentPC = nextPC; // Move to next byte
                 continue; // Try next byte
            }

            IRKind kind = it->second.first;
            byte operandSize = it->second.second;
            IR inst{kind, 0, instructionAddress};
            dword operandValue = 0;

            // Fetch operands
            switch (operandSize) {
                case 1:
                    if (offset + 1 < rom.size()) {
                        operandValue = rom[offset + 1];
                        nextPC += 1;
                    } else {
                        std::cerr << "Warning: Opcode 0x" << std::hex << (int)opcode << " at 0x" << instructionAddress << " requires 1-byte operand but hit ROM end." << std::dec << std::endl;
                        kind = IRKind::NOP; // Treat as NOP if operand fetch fails
                        operandSize = 0;
                    }
                    break;
                case 2:
                    if (offset + 2 < rom.size()) {
                        operandValue = rom[offset + 1] | (rom[offset + 2] << 8);
                        nextPC += 2;
                    } else {
                        std::cerr << "Warning: Opcode 0x" << std::hex << (int)opcode << " at 0x" << instructionAddress << " requires 2-byte operand but hit ROM end." << std::dec << std::endl;
                        kind = IRKind::NOP; // Treat as NOP
                        operandSize = 0;
                     }
                    break;
                default: // 0 bytes
                    break;
            }

             inst.kind = kind; // Update kind in case it changed to NOP
             inst.operand = operandValue; // Set operand


            bool stopProcessingBlock = false;
            dword branchTarget = 0;
            bool hasBranchTarget = false;

            // Handle jumps, branches, and subroutine calls to add targets to worklist
            switch (kind) {
                case IRKind::JMP:
                case IRKind::JSR:
                     branchTarget = inst.operand; // Absolute address
                     hasBranchTarget = true;
                     stopProcessingBlock = true; // JMP/JSR stops linear flow
                     break;

                case IRKind::BRA:
                case IRKind::BEQ:
                case IRKind::BNE:
                case IRKind::BMI:
                case IRKind::BPL:
                case IRKind::BCS:
                case IRKind::BCC:
                    {
                        // Convert relative branch to absolute address
                        int8_t relativeOffset = static_cast<int8_t>(inst.operand);
                        branchTarget = nextPC + relativeOffset; // Branch is relative to the *next* instruction
                        inst.operand = branchTarget; // Store absolute target in IR
                        hasBranchTarget = true;
                        // Conditional branches might fall through, BRA does not
                        stopProcessingBlock = (kind == IRKind::BRA);
                    }
                    break;

                case IRKind::RTS:
                    stopProcessingBlock = true; // RTS stops linear flow of this block
                    break;

                 // TODO: Handle other flow control like RTI, BRK, COP if needed

                default:
                    break; // Continue linear disassembly
            }

            // Store the disassembled instruction
            irMap[instructionAddress] = inst;

            // Add branch target to worklist if it hasn't been processed
            if (hasBranchTarget && !processedAddresses.count(branchTarget)) {
                // Basic check: Only add potential code addresses to worklist
                 if (branchTarget >= 0x8000) { // Assuming code is >= 0x8000
                    worklist.push(branchTarget);
                 } else {
                    // std::cout << "Note: Branch target 0x" << std::hex << branchTarget << " appears to be RAM/IO, not adding to disassembly worklist." << std::dec << std::endl;
                 }
            }

            // Move to the next instruction address
            currentPC = nextPC;

            // If flow control stops linear execution, break inner loop
            if (stopProcessingBlock) {
                break;
            }
        } // end while(true) for linear block
    } // end while(!worklist.empty())

    // Convert map to vector for return
    std::vector<IR> irs;
    for (const auto& pair : irMap) {
        irs.push_back(pair.second);
    }

    // Although map keeps elements sorted, explicitly sort just in case.
    std::sort(irs.begin(), irs.end());

    std::cout << "Disassembled " << irs.size() << " instructions." << std::endl;
    return irs;
}


// Emit assembly prologue
static void emitPrologue(std::ostream &out) {
    out << "; SNES to x86_64 Recompiled Code\n";
    out << "bits 64\n";
    out << "default rel\n\n";
    out << "section .text\n";
    out << "global _start\n\n";

    // --- Register Mapping ---
    // RAX (AL) = 65816 A Register (Accumulator)
    // RBX (BL) = 65816 X Register
    // RCX (CL) = 65816 Y Register
    // RDX (DL/DH)= 65816 Status Flags (Partial mapping for now)
    //   DL bit 7 = N flag (Sign)
    //   DH bit 0 = Z flag (Zero)
    // R9B       = C flag (Carry)
    // R10B      = Other flags (I, V) - partial/placeholder
    // RSI       = Temp address calculation / Stack Pointer Low Byte (emulated)
    // RDI       = Temp address calculation
    // R8        = Temp calculation / Return address for RTS
    // RSP       = x86_64 native stack pointer (used for PHA/PLA etc.)

    out << "_start:\n";
    out << "  ; Initialize simulated 65816 registers\n";
    out << "  xor rax, rax    ; Clear A\n";
    out << "  xor rbx, rbx    ; Clear X\n";
    out << "  xor rcx, rcx    ; Clear Y\n";
    out << "  xor rdx, rdx    ; Clear N, Z flags\n";
    out << "  xor r9, r9      ; Clear C flag (r9b)\n";
    out << "  xor r10, r10    ; Clear I, V flags (r10b)\n";
    // out << "  mov si, 0x01FF  ; Initialize 65816 Stack Pointer (e.g., $01FF)\n"; // Emulated SP low byte
    // Initialize x86 stack pointer for PHA/PLA
    out << "  mov rsp, stack_top ; Use dedicated x86 stack area\n";
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
            // Instructions whose operand holds an absolute target address
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
                break; // Other instructions don't directly define code labels
        }
    }
     std::cout << "Found " << targets.size() << " unique jump/branch targets." << std::endl;
    return targets;
}

// Helper to format operand for output
static std::string formatOperand(dword operand, byte size, bool isHex = true) {
    std::stringstream ss;
    if (isHex) {
        ss << "$";
        if (size == 1) ss << std::hex << std::setw(2) << std::setfill('0') << (operand & 0xFF);
        else if (size == 2) ss << std::hex << std::setw(4) << std::setfill('0') << (operand & 0xFFFF);
        else ss << std::hex << operand; // Default case
    } else {
        ss << std::dec << operand;
    }
    return ss.str();
}


// Translate IR to x86_64 assembly
static void translate(const std::vector<IR>& irs, std::ostream &out) {
    emitPrologue(out);

    // Find all jump targets first (should now be complete)
    std::set<dword> jumpTargets = findJumpTargets(irs);

    // Generate assembly code
    for (const auto& ir : irs) {
        // If this instruction's address is a jump target, add a label
        if (jumpTargets.count(ir.address)) {
            out << "label_" << std::hex << ir.address << ":\n";
        }

        // Convert IR to x86_64 instructions with comments showing original SNES instruction
        out << "  ; 0x" << std::hex << ir.address << ": ";

        // --- Flag updates reminder ---
        // N flag = DL bit 7
        // Z flag = DH bit 0
        // C flag = R9B bit 0
        // I flag = R10B bit 2 (placeholder)
        // V flag = R10B bit 6 (placeholder)

        switch (ir.kind) {
            // No-operation
            case IRKind::NOP:
                out << "NOP\n";
                out << "  nop\n";
                break;

            // Load operations
            case IRKind::LDA_IMM:
                out << "LDA #" << formatOperand(ir.operand, 1) << "\n";
                out << "  mov al, " << formatOperand(ir.operand, 1, false) << "\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";       // Test AL for zero and sign
                out << "  setnz dh            ; Set Z flag (inverted: 0 if zero)\n";
                out << "  xor dh, 1           ; Invert to get correct Z flag (1 if zero)\n";
                out << "  sets dl             ; Set N flag (DL bit 7 = sign bit of AL)\n";
                break;

            case IRKind::LDA_ABS:
                out << "LDA " << formatOperand(ir.operand, 2) << "\n";
                out << "  mov al, [mem+" << formatOperand(ir.operand, 2, false) << "]\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::LDA_ABSX:
                out << "LDA " << formatOperand(ir.operand, 2) << ",X\n";
                out << "  movzx rsi, bl       ; Load X register (BL)\n";
                out << "  add rsi, " << formatOperand(ir.operand, 2, false) << " ; Add base address\n";
                out << "  and rsi, 0xFFFF     ; Mask to 16-bit (basic simulation)\n";
                out << "  mov al, [mem+rsi]\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::LDX_IMM:
                out << "LDX #" << formatOperand(ir.operand, 1) << "\n";
                out << "  mov bl, " << formatOperand(ir.operand, 1, false) << "\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, bl\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::LDY_IMM:
                out << "LDY #" << formatOperand(ir.operand, 1) << "\n";
                out << "  mov cl, " << formatOperand(ir.operand, 1, false) << "\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, cl\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            // Store operations
            case IRKind::STA_ABS:
                out << "STA " << formatOperand(ir.operand, 2) << "\n";
                out << "  mov [mem+" << formatOperand(ir.operand, 2, false) << "], al\n";
                break;

            case IRKind::STA_ABSX:
                out << "STA " << formatOperand(ir.operand, 2) << ",X\n";
                out << "  movzx rsi, bl       ; X register\n";
                out << "  add rsi, " << formatOperand(ir.operand, 2, false) << "\n";
                out << "  and rsi, 0xFFFF     ; 16-bit address space\n";
                out << "  mov [mem+rsi], al\n";
                break;

            case IRKind::STX_ABS:
                out << "STX " << formatOperand(ir.operand, 2) << "\n";
                out << "  mov [mem+" << formatOperand(ir.operand, 2, false) << "], bl\n";
                break;

            case IRKind::STY_ABS:
                out << "STY " << formatOperand(ir.operand, 2) << "\n";
                out << "  mov [mem+" << formatOperand(ir.operand, 2, false) << "], cl\n";
                break;

            // Register transfer operations
            case IRKind::TAX:
                out << "TAX\n";
                out << "  mov bl, al\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, bl\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::TXA:
                out << "TXA\n";
                out << "  mov al, bl\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::TAY:
                out << "TAY\n";
                out << "  mov cl, al\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, cl\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::TYA:
                out << "TYA\n";
                out << "  mov al, cl\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::TXS: // Transfer X to Stack Pointer (low byte)
                out << "TXS\n";
                // For now, just copy to SI (emulated SP low byte)
                // Proper emulation needs full 16-bit SP and bank handling
                out << "  mov sil, bl         ; Emulated SP low byte = X\n";
                break;

            case IRKind::TSX: // Transfer Stack Pointer (low byte) to X
                out << "TSX\n";
                // For now, just copy from SI
                out << "  mov bl, sil         ; X = Emulated SP low byte\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, bl\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            // Stack operations (using x86 stack)
            case IRKind::PHA:
                out << "PHA\n";
                out << "  push ax             ; Push A (using x86 stack)\n";
                break;

            case IRKind::PLA:
                out << "PLA\n";
                out << "  pop ax              ; Pop into A (using x86 stack)\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::PHP: // Push Processor Status
                out << "PHP\n";
                out << "  ; Combine flags into a byte (approximated)\n";
                out << "  mov r8b, dl         ; N flag in bit 7\n";
                out << "  shl dh, 1           ; Z flag now in bit 1 (needs adjustment)\n";
                 out << "  or r8b, dh          ; Combine N, Z(approx)\n";
                out << "  mov r11b, r9b       ; C flag\n";
                out << "  or r8b, r11b        ; Combine C\n";
                // Combine I, V etc. from r10b if implemented
                out << "  push r8             ; Push combined flags\n";
                break;

            case IRKind::PLP: // Pull Processor Status
                out << "PLP\n";
                out << "  pop r8              ; Pop flags into R8\n";
                out << "  ; Distribute flags (approximated)\n";
                out << "  mov dl, r8b         ; N flag from bit 7\n";
                out << "  mov dh, r8b\n";
                out << "  shr dh, 1           ; Z flag from bit 1 (approx)\n";
                 out << "  and dh, 1\n";
                out << "  mov r9b, r8b        ; C flag from bit 0\n";
                out << "  and r9b, 1\n";
                // Distribute I, V etc. to r10b if implemented
                break;

            // Jump/Branch operations
            case IRKind::JMP:
                out << "JMP " << formatOperand(ir.operand, 2) << "\n";
                out << "  jmp label_" << std::hex << ir.operand << "\n";
                break;

            case IRKind::JSR:
                out << "JSR " << formatOperand(ir.operand, 2) << "\n";
                out << "  ; Calculate return address - 1 (address of last byte of JSR instruction)\n";
                out << "  mov r8, " << std::dec << (ir.address + 2) << " ; Address of last byte\n";
                 out << "  push r8w            ; Push 16-bit return address onto x86 stack\n";
                out << "  jmp label_" << std::hex << ir.operand << "\n";
                break;

            case IRKind::RTS:
                out << "RTS\n";
                out << "  ; Pop return address and add 1\n";
                out << "  pop r8w             ; Pop 16-bit return address\n";
                out << "  inc r8              ; Increment to get address *after* JSR\n";
                out << "  ; !!! Basic Dynamic Jump using r8 !!!\n";
                out << "  ; This assumes r8 contains a valid SNES address that has a corresponding label_xxxx.\n";
                out << "  ; A robust implementation needs a way to map ANY potential return address\n";
                out << "  ; in r8 to the correct recompiled code block, possibly via a hash table or dispatcher.\n";
                 out << "  ; For now, attempting a direct jump based on label convention.\n";
                 out << "  ; Generate lookup and jump (less efficient but safer than direct register jump)\n";
                 out << "  ; This still requires the target label to exist!\n";
                 out << "  mov rax, r8         ; Use RAX for jump target address\n";
                 out << "  ; Example: This part needs to map rax (SNES addr) to an actual code address\n";
                 out << "  ; We cannot directly jump to 'label_rax' in NASM.\n";
                 out << "  ; Placeholder: Jump to exit - REPLACE with proper dynamic dispatch\n";
                 out << "  jmp exit_program\n";
                 break;


            case IRKind::BRA: // Branch Always
                out << "BRA " << formatOperand(ir.operand, 2) << "\n";
                out << "  jmp label_" << std::hex << ir.operand << "\n";
                break;

            case IRKind::BEQ: // Branch if Equal (Z=1)
                out << "BEQ " << formatOperand(ir.operand, 2) << "\n";
                out << "  test dh, 1          ; Test Z flag (DH bit 0)\n";
                out << "  jnz label_" << std::hex << ir.operand << " ; Jump if Z is set (Not Zero result)\n";
                break;

            case IRKind::BNE: // Branch if Not Equal (Z=0)
                out << "BNE " << formatOperand(ir.operand, 2) << "\n";
                out << "  test dh, 1          ; Test Z flag (DH bit 0)\n";
                out << "  jz label_" << std::hex << ir.operand << "  ; Jump if Z is clear (Zero result)\n";
                break;

            case IRKind::BMI: // Branch if Minus (N=1)
                out << "BMI " << formatOperand(ir.operand, 2) << "\n";
                out << "  test dl, 0x80       ; Test N flag (DL bit 7)\n";
                out << "  jnz label_" << std::hex << ir.operand << " ; Jump if N is set\n";
                break;

            case IRKind::BPL: // Branch if Plus (N=0)
                out << "BPL " << formatOperand(ir.operand, 2) << "\n";
                out << "  test dl, 0x80       ; Test N flag (DL bit 7)\n";
                out << "  jz label_" << std::hex << ir.operand << "  ; Jump if N is clear\n";
                break;

            case IRKind::BCS: // Branch if Carry Set (C=1)
                out << "BCS " << formatOperand(ir.operand, 2) << "\n";
                out << "  test r9b, 1         ; Test C flag (R9B bit 0)\n";
                out << "  jnz label_" << std::hex << ir.operand << " ; Jump if C is set\n";
                break;

            case IRKind::BCC: // Branch if Carry Clear (C=0)
                out << "BCC " << formatOperand(ir.operand, 2) << "\n";
                out << "  test r9b, 1         ; Test C flag (R9B bit 0)\n";
                out << "  jz label_" << std::hex << ir.operand << "  ; Jump if C is clear\n";
                break;

            // Compare operations
            case IRKind::CMP_IMM:
                out << "CMP #" << formatOperand(ir.operand, 1) << "\n";
                out << "  cmp al, " << formatOperand(ir.operand, 1, false) << "\n";
                out << "  ; Update Flags (N, Z, C)\n";
                out << "  setae r9b           ; Set C if A >= imm (unsigned)\n";
                out << "  setz dh             ; Set Z if A == imm\n";
                out << "  mov dl, al\n";
                out << "  sub dl, " << formatOperand(ir.operand, 1, false) << " ; Calculate difference for N\n";
                out << "  sets dl             ; Set N based on result sign\n";
                break;

            case IRKind::CPX_IMM:
                out << "CPX #" << formatOperand(ir.operand, 1) << "\n";
                out << "  cmp bl, " << formatOperand(ir.operand, 1, false) << "\n";
                out << "  ; Update Flags (N, Z, C)\n";
                out << "  setae r9b           ; Set C if X >= imm\n";
                out << "  setz dh             ; Set Z if X == imm\n";
                out << "  mov dl, bl\n";
                out << "  sub dl, " << formatOperand(ir.operand, 1, false) << "\n";
                out << "  sets dl             ; Set N based on result sign\n";
                break;

            case IRKind::CPY_IMM:
                out << "CPY #" << formatOperand(ir.operand, 1) << "\n";
                out << "  cmp cl, " << formatOperand(ir.operand, 1, false) << "\n";
                out << "  ; Update Flags (N, Z, C)\n";
                out << "  setae r9b           ; Set C if Y >= imm\n";
                out << "  setz dh             ; Set Z if Y == imm\n";
                out << "  mov dl, cl\n";
                out << "  sub dl, " << formatOperand(ir.operand, 1, false) << "\n";
                out << "  sets dl             ; Set N based on result sign\n";
                break;

            // Increment/Decrement operations
            case IRKind::INX:
                out << "INX\n";
                out << "  inc bl\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, bl\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::INY:
                out << "INY\n";
                out << "  inc cl\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, cl\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::DEX:
                out << "DEX\n";
                out << "  dec bl\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, bl\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::DEY:
                out << "DEY\n";
                out << "  dec cl\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, cl\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::INC_ABS:
                out << "INC " << formatOperand(ir.operand, 2) << "\n";
                out << "  inc byte [mem+" << formatOperand(ir.operand, 2, false) << "]\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, [mem+" << formatOperand(ir.operand, 2, false) << "]\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::DEC_ABS:
                out << "DEC " << formatOperand(ir.operand, 2) << "\n";
                out << "  dec byte [mem+" << formatOperand(ir.operand, 2, false) << "]\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, [mem+" << formatOperand(ir.operand, 2, false) << "]\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            // Arithmetic/Logic operations (Simplified - V flag not implemented)
            case IRKind::ADC_IMM:
                out << "ADC #" << formatOperand(ir.operand, 1) << "\n";
                out << "  mov r8b, r9b        ; Move old carry into r8b\n";
                out << "  adc al, " << formatOperand(ir.operand, 1, false) << " ; Add with carry (uses x86 carry)\n";
                out << "  setc r9b            ; Set new C flag\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                // V flag needs more complex check
                break;

            case IRKind::SBC_IMM:
                out << "SBC #" << formatOperand(ir.operand, 1) << "\n";
                out << "  mov r8b, r9b        ; Move old carry into r8b\n";
                out << "  sbb al, " << formatOperand(ir.operand, 1, false) << " ; Subtract with borrow (uses x86 carry)\n";
                out << "  setc r9b            ; Set new C flag (borrow)\n";
                 out << "  xor r9b, 1          ; Invert for 6502 SBC carry logic\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                // V flag needs more complex check
                break;

            case IRKind::AND_IMM:
                out << "AND #" << formatOperand(ir.operand, 1) << "\n";
                out << "  and al, " << formatOperand(ir.operand, 1, false) << "\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::ORA_IMM:
                out << "ORA #" << formatOperand(ir.operand, 1) << "\n";
                out << "  or al, " << formatOperand(ir.operand, 1, false) << "\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::EOR_IMM:
                out << "EOR #" << formatOperand(ir.operand, 1) << "\n";
                out << "  xor al, " << formatOperand(ir.operand, 1, false) << "\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            // Shift operations
            case IRKind::ASL_ACC:
                out << "ASL A\n";
                out << "  shl al, 1\n";
                out << "  setc r9b            ; Set C flag from high bit shifted out\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::LSR_ACC:
                out << "LSR A\n";
                out << "  shr al, 1\n";
                out << "  setc r9b            ; Set C flag from low bit shifted out\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl             ; N flag is always 0 after LSR\n";
                break;

            case IRKind::ROL_ACC:
                out << "ROL A\n";
                out << "  rcl al, 1           ; Rotate left through carry (uses x86 carry)\n";
                out << "  setc r9b            ; Set new C flag\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            case IRKind::ROR_ACC:
                out << "ROR A\n";
                out << "  rcr al, 1           ; Rotate right through carry (uses x86 carry)\n";
                out << "  setc r9b            ; Set new C flag\n";
                out << "  ; Update flags (N, Z)\n";
                out << "  mov dl, al\n";
                out << "  test dl, dl\n";
                out << "  setnz dh\n";
                out << "  xor dh, 1\n";
                out << "  sets dl\n";
                break;

            // Status flag operations
            case IRKind::CLC:
                out << "CLC\n";
                out << "  clc                 ; Clear x86 carry flag\n";
                out << "  mov r9b, 0          ; Clear C flag register\n";
                break;

            case IRKind::SEC:
                out << "SEC\n";
                out << "  stc                 ; Set x86 carry flag\n";
                out << "  mov r9b, 1          ; Set C flag register\n";
                break;

            case IRKind::CLI: // Clear Interrupt Disable
                out << "CLI\n";
                out << "  ; TODO: Implement interrupt handling logic if needed\n";
                out << "  and r10b, ~(1 << 2) ; Clear I flag (bit 2) in R10B (placeholder)\n";
                out << "  sti                 ; Enable x86 interrupts (if used)\n";
                break;

            case IRKind::SEI: // Set Interrupt Disable
                out << "SEI\n";
                out << "  ; TODO: Implement interrupt handling logic if needed\n";
                out << "  or r10b, (1 << 2)   ; Set I flag (bit 2) in R10B (placeholder)\n";
                out << "  cli                 ; Disable x86 interrupts (if used)\n";
                break;

            case IRKind::CLV: // Clear Overflow Flag
                out << "CLV\n";
                out << "  ; V flag not fully implemented yet\n";
                 out << "  and r10b, ~(1 << 6) ; Clear V flag (bit 6) in R10B (placeholder)\n";
                break;

            default:
                out << "Unimplemented Opcode: 0x" << std::hex << static_cast<int>(ir.kind) << "\n";
                out << "  nop                 ; Placeholder\n";
                break;
        }
        out << std::dec; // Ensure stream is back to decimal mode
    }


    // Remove the old dynamic jump table for RTS
    // emitRtsJumpTable(irs, out); // Removed

    emitEpilogue(out);

    // Add the data section
    out << "\nsection .bss\n";
    out << "mem: resb 0x10000  ; 64KB of SNES memory (placeholder size)\n";
    // Adjust stack size as needed
    out << "stack_bottom: resb 1024 ; Reserve 1KB for x86 stack used by PHA/PLA/JSR/RTS\n";
    out << "stack_top: resb 0    ; Label for top of stack (RSP starts here)\n";
}


bool recompileRom(const std::string &in, const std::string &outPath) {
    auto rom = loadROM(in);
    if (rom.empty()) {
        std::cerr << "Failed to load ROM or ROM is empty" << std::endl;
        return false;
    }

    std::cout << "ROM loaded successfully: " << rom.size() << " bytes" << std::endl;

    auto irs = disassemble(rom);
    if (irs.empty()) {
        std::cerr << "Disassembly produced no instructions. Check ROM or start address." << std::endl;
        return false;
    }

    std::cout << "Disassembly complete: " << irs.size() << " instructions generated." << std::endl;

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
