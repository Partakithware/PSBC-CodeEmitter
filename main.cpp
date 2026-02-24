#include "emitter.h"
#include <iostream>
#include <iomanip>

void printUsage(const char* progName) {
    std::cout << "Usage: " << progName << " <input.emit> <output_file>\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << progName << " hello.emit hello.bin\n";
    std::cout << "  " << progName << " program.emit a.out\n";
    std::cout << "  " << progName << " data.emit output.txt\n";
    std::cout << "\nThe emitter is format-agnostic. It will emit whatever bytes\n";
    std::cout << "you describe in your .emit file to ANY file format you specify.\n";
}

void printHexDump(const ByteStream& bytes, size_t bytesPerLine = 16) {
    std::cout << "\n=== Hex Dump ===\n";
    
    for (size_t i = 0; i < bytes.size(); i += bytesPerLine) {
        // Print offset
        std::cout << std::setfill('0') << std::setw(8) << std::hex << i << "  ";
        
        // Print hex bytes
        for (size_t j = 0; j < bytesPerLine; j++) {
            if (i + j < bytes.size()) {
                std::cout << std::setfill('0') << std::setw(2) << std::hex 
                          << static_cast<int>(bytes[i + j]) << " ";
            } else {
                std::cout << "   ";
            }
            
            if (j == 7) std::cout << " "; // Extra space in the middle
        }
        
        std::cout << " |";
        
        // Print ASCII representation
        for (size_t j = 0; j < bytesPerLine && i + j < bytes.size(); j++) {
            char c = bytes[i + j];
            if (c >= 32 && c <= 126) {
                std::cout << c;
            } else {
                std::cout << ".";
            }
        }
        
        std::cout << "|\n";
    }
    
    std::cout << std::dec << "\nTotal bytes: " << bytes.size() << "\n";
}

int main(int argc, char* argv[]) {
    std::cout << "╔═══════════════════════════════════════╗\n";
    std::cout << "║   Binary Emitter IDE - Core Engine   ║\n";
    std::cout << "║   Format-Agnostic Byte Composer      ║\n";
    std::cout << "╚═══════════════════════════════════════╝\n\n";
    
    if (argc != 3) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string inputFile = argv[1];
    std::string outputFile = argv[2];
    
    std::cout << "Input:  " << inputFile << "\n";
    std::cout << "Output: " << outputFile << "\n\n";
    
    // Create emitter instance
    Emitter emitter;
    
    // Load source
    std::cout << "[1/3] Loading source file...\n";
    if (!emitter.loadSource(inputFile)) {
        std::cerr << "Failed to load source: " << emitter.getError() << "\n";
        return 1;
    }
    std::cout << "      ✓ Source loaded\n\n";
    
    // Parse and emit
    std::cout << "[2/3] Parsing and emitting bytes...\n";
    if (!emitter.parseAndEmit()) {
        std::cerr << "Failed to emit: " << emitter.getError() << "\n";
        return 1;
    }
    std::cout << "      ✓ " << emitter.getCurrentOffset() << " bytes emitted\n\n";
    
    // Write output
    std::cout << "[3/3] Writing output file...\n";
    if (!emitter.writeOutput(outputFile)) {
        std::cerr << "Failed to write output: " << emitter.getError() << "\n";
        return 1;
    }
    std::cout << "      ✓ Output written\n";
    
    // Print hex dump
    printHexDump(emitter.getByteStream());
    
    std::cout << "\n✓ Success! File '" << outputFile << "' created.\n";
    
    return 0;
}