// ============================================================
//  emit_dictionary.h
//  The Emit Language Standard Dictionary
//
//  Usage in your .emit file:
//      #include "emit_dictionary.h"
//
//  Every definition here is a multi-token macro that expands
//  to real EMIT statements.  Use them like named building blocks:
//
//      JPEG_SOI           // Emits FF D8
//      JPEG_EOI           // Emits FF D9
//      ELF_MAGIC          // Emits 7F 45 4C 46 ...
//      PNG_MAGIC          // Emits 89 50 4E 47 ...
//      PE_DOS_MAGIC       // Emits 4D 5A
//      UTF8_BOM           // Emits EF BB BF
//
//  You can add your own presets in the USER PRESETS section
//  at the bottom, or create your own dictionary file and
//  #include it alongside this one.
// ============================================================

#ifndef EMIT_DICTIONARY_H
#define EMIT_DICTIONARY_H

// ============================================================
//  COMMON SIZES & CONSTANTS
//  Use these in #define math expressions.
// ============================================================

#define KB          1024
#define MB          (1024 * 1024)
#define GB          (1024 * 1024 * 1024)

#define PAGE_SIZE   4096
#define PAGE_ALIGN  4096

#define NULL_BYTE   0x00
#define FILL_BYTE   0xFF

// ============================================================
//  JPEG / JFIF Markers
//  Reference: ISO/IEC 10918-1
// ============================================================

// Start / End of Image
#define JPEG_SOI    EMIT u8 0xFF 0xD8
#define JPEG_EOI    EMIT u8 0xFF 0xD9

// JFIF APP0 application marker (minimal, 16-byte segment, 72 DPI)
#define JPEG_APP0   EMIT u8 0xFF 0xE0 0x00 0x10
#define JFIF_ID     EMIT_STR "JFIF"
#define JFIF_VER    EMIT u8 0x01 0x01
#define JFIF_72DPI  EMIT u8 0x01 0x00 0x48 0x00 0x48 0x00 0x00

// DQT — Define Quantization Table marker
#define JPEG_DQT    EMIT u8 0xFF 0xDB

// DHT — Define Huffman Table marker
#define JPEG_DHT    EMIT u8 0xFF 0xC4

// SOF0 — Start of Frame (Baseline DCT)
#define JPEG_SOF0   EMIT u8 0xFF 0xC0

// SOS — Start of Scan
#define JPEG_SOS    EMIT u8 0xFF 0xDA

// Standard minimal grayscale DC Huffman table body (27 bytes)
#define JPEG_DHT_GRAY_DC  EMIT u8 0x00 0x01 0x05 0x01 0x01 0x01 0x01 0x01 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0A 0x0B

// Standard SOS scan header body (grayscale, 1 component)
#define JPEG_SOS_GRAY   EMIT u8 0x00 0x08 0x01 0x01 0x00 0x00 0x3F 0x00

// ============================================================
//  PNG Magic
//  Reference: RFC 2083
// ============================================================

// PNG signature — always the first 8 bytes of any PNG file
#define PNG_MAGIC   EMIT u8 0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A

// PNG chunk type codes (as raw 4-byte ASCII)
#define PNG_IHDR    EMIT u8 0x49 0x48 0x44 0x52
#define PNG_IDAT    EMIT u8 0x49 0x44 0x41 0x54
#define PNG_IEND    EMIT u8 0x49 0x45 0x4E 0x44
#define PNG_PLTE    EMIT u8 0x50 0x4C 0x54 0x45
#define PNG_TEXT    EMIT u8 0x74 0x45 0x58 0x74

// IEND chunk (always 12 bytes: 4-len=0, IEND, CRC)
#define PNG_IEND_CHUNK EMIT u8 0x00 0x00 0x00 0x00 0x49 0x45 0x4E 0x44 0xAE 0x42 0x60 0x82

// ============================================================
//  ELF Headers
//  Reference: System V ABI
// ============================================================

// ELF magic + class + data + version + OS/ABI + padding
#define ELF_MAGIC       EMIT u8 0x7F 0x45 0x4C 0x46
#define ELF64_IDENT     EMIT u8 0x7F 0x45 0x4C 0x46 0x02 0x01 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00

// ELF e_type values
#define ELF_ET_EXEC     EMIT u16 0x0002
#define ELF_ET_DYN      EMIT u16 0x0003
#define ELF_ET_REL      EMIT u16 0x0001

// ELF e_machine: x86-64
#define ELF_EM_X86_64   EMIT u16 0x003E
// ELF e_machine: ARM 64
#define ELF_EM_AARCH64  EMIT u16 0x00B7
// ELF e_machine: RISC-V
#define ELF_EM_RISCV    EMIT u16 0x00F3

// ELF e_version (current = 1)
#define ELF_EV_CURRENT  EMIT u32 0x00000001

// Program Header: PT_LOAD with flags RX (executable segment)
#define ELF_PHDR_LOAD_RX EMIT u32 0x00000001 0x00000005

// Program Header: PT_LOAD with flags RW (data segment)
#define ELF_PHDR_LOAD_RW EMIT u32 0x00000001 0x00000006

// Common ELF e_ehsize for 64-bit ELF
#define ELF64_EHSIZE    EMIT u16 0x0040
// Common e_phentsize for 64-bit ELF
#define ELF64_PHENTSIZE EMIT u16 0x0038

// ============================================================
//  PE / Windows Portable Executable
//  Reference: Microsoft PE/COFF Specification
// ============================================================

// MZ DOS header signature
#define PE_DOS_MAGIC    EMIT u8 0x4D 0x5A

// PE signature ("PE\0\0")
#define PE_SIGNATURE    EMIT u8 0x50 0x45 0x00 0x00

// PE optional header magic: PE32+ (64-bit)
#define PE_OPT_PE32PLUS EMIT u16 0x020B
// PE optional header magic: PE32 (32-bit)
#define PE_OPT_PE32     EMIT u16 0x010B

// Machine types
#define PE_MACHINE_X64  EMIT u16 0x8664
#define PE_MACHINE_X86  EMIT u16 0x014C
#define PE_MACHINE_ARM64 EMIT u16 0xAA64

// Section characteristics flags (useful in EMIT u32)
#define PE_SCN_CNT_CODE         0x00000020
#define PE_SCN_CNT_INIT_DATA    0x00000040
#define PE_SCN_MEM_EXECUTE      0x20000000
#define PE_SCN_MEM_READ         0x40000000
#define PE_SCN_MEM_WRITE        0x80000000

// Common section flags
#define PE_TEXT_FLAGS   EMIT u32 (PE_SCN_CNT_CODE | PE_SCN_MEM_EXECUTE | PE_SCN_MEM_READ)
#define PE_DATA_FLAGS   EMIT u32 (PE_SCN_CNT_INIT_DATA | PE_SCN_MEM_READ | PE_SCN_MEM_WRITE)

// ============================================================
//  WASM (WebAssembly)
//  Reference: https://webassembly.github.io/spec/
// ============================================================

// WASM magic + version
#define WASM_MAGIC      EMIT u8 0x00 0x61 0x73 0x6D
#define WASM_VERSION    EMIT u8 0x01 0x00 0x00 0x00
#define WASM_HEADER     EMIT u8 0x00 0x61 0x73 0x6D 0x01 0x00 0x00 0x00

// Section IDs
#define WASM_SEC_TYPE     EMIT u8 0x01
#define WASM_SEC_IMPORT   EMIT u8 0x02
#define WASM_SEC_FUNC     EMIT u8 0x03
#define WASM_SEC_TABLE    EMIT u8 0x04
#define WASM_SEC_MEMORY   EMIT u8 0x05
#define WASM_SEC_GLOBAL   EMIT u8 0x06
#define WASM_SEC_EXPORT   EMIT u8 0x07
#define WASM_SEC_CODE     EMIT u8 0x0A
#define WASM_SEC_DATA     EMIT u8 0x0B

// Value types
#define WASM_I32    0x7F
#define WASM_I64    0x7E
#define WASM_F32    0x7D
#define WASM_F64    0x7C
#define WASM_FUNCREF 0x70

// ============================================================
//  GIF (Graphics Interchange Format)
//  Reference: GIF89a Specification
// ============================================================

// GIF87a header
#define GIF87_HEADER    EMIT_STR "GIF87a"
// GIF89a header
#define GIF89_HEADER    EMIT_STR "GIF89a"
// GIF trailer byte
#define GIF_TRAILER     EMIT u8 0x3B

// GIF Image Descriptor marker
#define GIF_IMG_DESC    EMIT u8 0x2C
// GIF Extension Introducer
#define GIF_EXT_INTRO   EMIT u8 0x21
// GIF Graphic Control Extension label
#define GIF_GCE_LABEL   EMIT u8 0xF9

// ============================================================
//  ZIP Archive
//  Reference: PKWARE APPNOTE
// ============================================================

// Local file header signature
#define ZIP_LOCAL_SIG   EMIT u8 0x50 0x4B 0x03 0x04
// Central directory header signature
#define ZIP_CDIR_SIG    EMIT u8 0x50 0x4B 0x01 0x02
// End of central directory signature
#define ZIP_ECDIR_SIG   EMIT u8 0x50 0x4B 0x05 0x06

// ============================================================
//  BMP (Windows Bitmap)
//  Reference: Microsoft BITMAPFILEHEADER
// ============================================================

// BMP file signature
#define BMP_MAGIC       EMIT u8 0x42 0x4D

// DIB header size for BITMAPINFOHEADER (40 bytes)
#define BMP_DIB_V3      EMIT u32 40

// ============================================================
//  x86-64 Common Opcodes
//  Handy raw byte presets for hand-rolled shellcode / stubs.
// ============================================================

// System call
#define X64_SYSCALL     EMIT u8 0x0F 0x05
// Return
#define X64_RET         EMIT u8 0xC3
// NOP
#define X64_NOP         EMIT u8 0x90
// NOP sled (16 NOPs)
#define X64_NOP16       EMIT u8[16] 0x90
// INT3 (software breakpoint)
#define X64_INT3        EMIT u8 0xCC
// HLTC
#define X64_HLT         EMIT u8 0xF4

// ---------------------------------------------------------------------------
//  OPCODE PREFIX MACROS  (emit only the opcode bytes)
//  ⚠  MUST be followed by  EMIT u64 <value>  or  EMIT u32 <value>
//
//  MOV rax/rdi/rsi/rdx, imm64  — REX.W + B8+r  (10 bytes total)
//  Usage:  X64_MOV_RAX  followed by  EMIT u64 0x0000000000000001
// ---------------------------------------------------------------------------
#define X64_MOV_RAX     EMIT u8 0x48 0xB8
#define X64_MOV_RDI     EMIT u8 0x48 0xBF
#define X64_MOV_RSI     EMIT u8 0x48 0xBE
#define X64_MOV_RDX     EMIT u8 0x48 0xBA

// ---------------------------------------------------------------------------
//  OPCODE PREFIX MACROS  (emit only the opcode bytes)
//  ⚠  MUST be followed by  EMIT u32 <value>  (imm32 sign-extends to 64-bit)
//
//  MOV rax/rdi/rsi/rdx, imm32  — REX.W + C7 /r  (7 bytes total)
//  Usage:  X64_MOV_RAX32  followed by  EMIT u32 0x00000001
// ---------------------------------------------------------------------------
#define X64_MOV_RAX32   EMIT u8 0x48 0xC7 0xC0
#define X64_MOV_RDI32   EMIT u8 0x48 0xC7 0xC7
#define X64_MOV_RSI32   EMIT u8 0x48 0xC7 0xC6
#define X64_MOV_RDX32   EMIT u8 0x48 0xC7 0xC2

// ---------------------------------------------------------------------------
//  COMPLETE INSTRUCTION MACROS  (self-contained, no follow-up needed)
//  Named as:  X64_MOV_<REG>_<VALUE>
//  These are the safe, can't-get-wrong versions for common immediate values.
// ---------------------------------------------------------------------------

// MOV RAX, imm  (7-byte, imm32 form)
#define X64_RAX_0       EMIT u8 0x48 0xC7 0xC0 0x00 0x00 0x00 0x00
#define X64_RAX_1       EMIT u8 0x48 0xC7 0xC0 0x01 0x00 0x00 0x00
#define X64_RAX_2       EMIT u8 0x48 0xC7 0xC0 0x02 0x00 0x00 0x00
#define X64_RAX_3       EMIT u8 0x48 0xC7 0xC0 0x03 0x00 0x00 0x00
#define X64_RAX_60      EMIT u8 0x48 0xC7 0xC0 0x3C 0x00 0x00 0x00
#define X64_RAX_231     EMIT u8 0x48 0xC7 0xC0 0xE7 0x00 0x00 0x00

// MOV RDI, imm  (7-byte, imm32 form)
#define X64_RDI_0       EMIT u8 0x48 0xC7 0xC7 0x00 0x00 0x00 0x00
#define X64_RDI_1       EMIT u8 0x48 0xC7 0xC7 0x01 0x00 0x00 0x00
#define X64_RDI_2       EMIT u8 0x48 0xC7 0xC7 0x02 0x00 0x00 0x00

// MOV RSI, imm  (7-byte, imm32 form)
#define X64_RSI_0       EMIT u8 0x48 0xC7 0xC6 0x00 0x00 0x00 0x00
#define X64_RSI_1       EMIT u8 0x48 0xC7 0xC6 0x01 0x00 0x00 0x00

// MOV RDX, imm  (7-byte, imm32 form) — for lengths up to 0xFF
#define X64_RDX_0       EMIT u8 0x48 0xC7 0xC2 0x00 0x00 0x00 0x00
#define X64_RDX_1       EMIT u8 0x48 0xC7 0xC2 0x01 0x00 0x00 0x00

// ---------------------------------------------------------------------------
//  Common zero / clear operations  (2-3 bytes each)
// ---------------------------------------------------------------------------
#define X64_XOR_RAX     EMIT u8 0x48 0x31 0xC0   // xor rax, rax
#define X64_XOR_RDI     EMIT u8 0x48 0x31 0xFF   // xor rdi, rdi
#define X64_XOR_RSI     EMIT u8 0x48 0x31 0xF6   // xor rsi, rsi
#define X64_XOR_RDX     EMIT u8 0x48 0x31 0xD2   // xor rdx, rdx

// ---------------------------------------------------------------------------
//  Stack frame helpers
// ---------------------------------------------------------------------------
#define X64_PUSH_RBP    EMIT u8 0x55
#define X64_POP_RBP     EMIT u8 0x5D
#define X64_MOV_RBP_RSP EMIT u8 0x48 0x89 0xE5   // mov rbp, rsp
#define X64_SUB_RSP     EMIT u8 0x48 0x83 0xEC   // sub rsp, imm8  — follow with EMIT u8 <n>
#define X64_ADD_RSP     EMIT u8 0x48 0x83 0xC4   // add rsp, imm8  — follow with EMIT u8 <n>

// ---------------------------------------------------------------------------
//  Linux x86-64 syscall numbers
// ---------------------------------------------------------------------------
#define SYS_READ        0
#define SYS_WRITE       1
#define SYS_OPEN        2
#define SYS_CLOSE       3
#define SYS_STAT        4
#define SYS_MMAP        9
#define SYS_MUNMAP      11
#define SYS_BRK         12
#define SYS_EXIT        60
#define SYS_EXIT_GROUP  231
#define SYS_GETPID      39
#define SYS_FORK        57
#define SYS_EXECVE      59

// ---------------------------------------------------------------------------
//  Common complete Linux syscall sequences
//  These expand to the full byte sequence for a specific call.
// ---------------------------------------------------------------------------

// write(1, rsi=already set via LEA, rdx=already set)
#define X64_WRITE_1     EMIT u8 0x48 0xC7 0xC0 0x01 0x00 0x00 0x00 0x48 0xC7 0xC7 0x01 0x00 0x00 0x00

// exit(0)
#define X64_EXIT_0      EMIT u8 0x48 0xC7 0xC0 0x3C 0x00 0x00 0x00 0x48 0x31 0xFF 0x0F 0x05

// ============================================================
//  Text / Encoding Markers
// ============================================================

// UTF-8 Byte Order Mark (BOM)
#define UTF8_BOM        EMIT u8 0xEF 0xBB 0xBF
// UTF-16 LE BOM
#define UTF16_LE_BOM    EMIT u8 0xFF 0xFE
// UTF-16 BE BOM
#define UTF16_BE_BOM    EMIT u8 0xFE 0xFF
// UTF-32 LE BOM
#define UTF32_LE_BOM    EMIT u8 0xFF 0xFE 0x00 0x00

// Common control characters
#define CRLF            EMIT u8 0x0D 0x0A
#define LF              EMIT u8 0x0A
#define CR              EMIT u8 0x0D
#define TAB             EMIT u8 0x09
#define NULL_TERM       EMIT u8 0x00

// ============================================================
//  RIFF (Resource Interchange File Format)
//  Used by WAV, AVI, WebP, etc.
// ============================================================

// RIFF chunk header
#define RIFF_MAGIC      EMIT u8 0x52 0x49 0x46 0x46
// WAVE format ID
#define WAVE_FMT_ID     EMIT u8 0x57 0x41 0x56 0x45
// WAV fmt sub-chunk marker
#define WAV_FMT_CHUNK   EMIT u8 0x66 0x6D 0x74 0x20
// WAV data sub-chunk marker
#define WAV_DATA_CHUNK  EMIT u8 0x64 0x61 0x74 0x61
// PCM audio format code
#define WAV_PCM         EMIT u16 0x0001

// ============================================================
//  DEX (Android Dalvik Executable)
// ============================================================

// DEX magic: "dex\n035\0"
#define DEX_MAGIC       EMIT u8 0x64 0x65 0x78 0x0A 0x30 0x33 0x35 0x00

// ============================================================
//  Mach-O (macOS / iOS executables)
// ============================================================

// Mach-O magic: 64-bit little-endian
#define MACHO_MAGIC64   EMIT u32 0xFEEDFACF
// Mach-O magic: 64-bit big-endian
#define MACHO_CIGAM64   EMIT u32 0xCFFAEDFE
// CPU type: x86-64
#define MACHO_CPU_X86_64  EMIT u32 0x01000007
// CPU type: ARM64
#define MACHO_CPU_ARM64   EMIT u32 0x0100000C

// ============================================================
//  Padding / Fill Utilities
// ============================================================

// Named zero-fill patterns
#define ZERO_4          EMIT u8[4]  0x00
#define ZERO_8          EMIT u8[8]  0x00
#define ZERO_16         EMIT u8[16] 0x00
#define ZERO_32         EMIT u8[32] 0x00
#define ZERO_64         EMIT u8[64] 0x00
#define ZERO_128        EMIT u8[128] 0x00
#define ZERO_256        EMIT u8[256] 0x00

// Named FF-fill patterns
#define FF_4            EMIT u8[4]  0xFF
#define FF_8            EMIT u8[8]  0xFF
#define FF_16           EMIT u8[16] 0xFF

// Typical x64 alignment padding (NOP sled aligned to 8 bytes)
#define PAD_TO_8        ALIGN 8 0x90
#define PAD_TO_16       ALIGN 16 0x90
#define PAD_TO_64       ALIGN 64 0x90
#define PAD_TO_PAGE     ALIGN 4096 0x00




// ============================================================
//  USER PRESETS — Add your own named sequences below!
//  Example:
//
//  #define MY_HEADER   EMIT u8 0xDE 0xAD 0xBE 0xEF
//
// ============================================================

#endif // EMIT_DICTIONARY_H