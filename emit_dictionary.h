// ============================================================
//  emit_dictionary.h  —  The Emit Code Dictionary  v3.0
//
//  Replace every raw hex byte and opcode with a named macro.
//  #include "emit_dictionary.h"  in your .emit file.
//
//  SECTIONS
//  §01  Sizes, numeric constants, IEEE 754 specials
//  §02  Padding & alignment
//  §03  Text / encoding markers & ANSI escapes
//  §04  ELF executable format (full field coverage)
//  §05  PE/COFF Windows executable format
//  §06  Mach-O macOS/iOS executable format
//  §07  WebAssembly (all opcodes + section types)
//  §08  JVM .class bytecode (all opcodes)
//  §09  x86-64 instructions — complete coverage
//       · Prefix-only macros (⚠ need operand follow-up)
//       · Complete self-contained macros
//       · All GPR push/pop, xor-zero, moves
//       · Arithmetic, logic, shifts, rotate, bit ops
//       · Conditionals: Jcc, CMOVcc, SETcc
//       · String ops + REP/REPNE
//       · Atomics: LOCK, XCHG, CMPXCHG, XADD
//       · Memory fences, system/privileged
//       · SSE2 / AVX2 common instructions
//       · Complete Linux syscall sequences
//  §10  x86-32 instructions
//  §11  ARM64 / AArch64 instructions
//  §12  RISC-V 64-bit instructions (RV64I + C)
//  §13  Linux syscalls — x86-64  (all ~340)
//  §14  Linux syscalls — AArch64
//  §15  Linux syscalls — RISC-V 64
//  §16  macOS/BSD syscalls — x86-64
//  §17  Windows NT native API syscall numbers
//  §18  Calling convention constants (SysV, Win64, ARM64)
//  §19  Network: Ethernet, ARP, IP, TCP, UDP, ICMP, DNS, TLS, HTTP, DHCP
//  §20  Filesystem: FAT32, ext4, NTFS, MBR, GPT
//  §21  UEFI / ACPI / firmware
//  §22  USB descriptors & PCI config space
//  §23  Cryptography (SHA, MD5, AES, ChaCha20, ASN.1, OIDs)
//  §24  CRC polynomials & hash magic constants
//  §25  User presets
// ============================================================

#ifndef EMIT_DICTIONARY_H
#define EMIT_DICTIONARY_H

////////////////////////////////////////////////////////////////
// §01  SIZES, NUMERIC CONSTANTS, IEEE 754 SPECIALS
////////////////////////////////////////////////////////////////

#define KB                                   1024
#define MB                                   (1024 * 1024)
#define GB                                   (1024 * 1024 * 1024)
#define PAGE_SIZE                            4096
#define HUGE_PAGE                            (2 * 1024 * 1024)
#define SECTOR_SIZE                          512
#define CACHE_LINE                           64

// ────────────────────────────────────────────────────────
//  Bit masks
// ────────────────────────────────────────────────────────
#define MASK_U8                              0xFF
#define MASK_U16                             0xFFFF
#define MASK_U32                             0xFFFFFFFF
#define MASK_LO32                            0x00000000FFFFFFFF
#define MASK_HI32                            0xFFFFFFFF00000000
#define MASK_7BIT                            0x7F
#define MASK_LO4                             0x0F
#define MASK_HI4                             0xF0

// ────────────────────────────────────────────────────────
//  Sentinel / debug-fill values
// ────────────────────────────────────────────────────────
#define DEAD_BEEF                            0xDEADBEEF
#define DEAD_C0DE                            0xDEADC0DE
#define CAFEBABE                             0xCAFEBABE
#define CAFED00D                             0xCAFED00D
#define FEEDFACE                             0xFEEDFACE
#define BAADF00D                             0xBAADF00D
#define CCCCCCCC                             0xCCCCCCCC   // MSVC uninitialised stack fill
#define CDCDCDCD                             0xCDCDCDCD   // MSVC uninitialised heap fill
#define FDFDFDFD                             0xFDFDFDFD   // MSVC guard byte (no-man's land)
#define ABABABAB                             0xABABABAB   // MSVC freed heap fill

// ────────────────────────────────────────────────────────
//  IEEE 754 float32 specials (use as raw u32 constants)
// ────────────────────────────────────────────────────────
#define F32_POS_ZERO                         0x00000000
#define F32_NEG_ZERO                         0x80000000
#define F32_POS_INF                          0x7F800000
#define F32_NEG_INF                          0xFF800000
#define F32_QNAN                             0x7FC00000
#define F32_SNAN                             0x7F800001
#define F32_ONE                              0x3F800000   // 1.0f
#define F32_NEG_ONE                          0xBF800000   // -1.0f
#define F32_HALF                             0x3F000000   // 0.5f
#define F32_TWO                              0x40000000   // 2.0f
#define F32_TEN                              0x41200000   // 10.0f
#define F32_PI                               0x40490FDB   // 3.14159265f
#define F32_TAU                              0x40C90FDB   // 6.28318530f  (2*pi)
#define F32_E                                0x402DF854   // 2.71828182f
#define F32_SQRT2                            0x3FB504F3   // 1.41421356f
#define F32_LN2                              0x3F317218   // 0.69314718f
#define F32_LOG2E                            0x3FB8AA3B   // 1.44269504f
#define F32_LOG10E                           0x3EDE5BD9   // 0.43429448f
#define F32_MAX                              0x7F7FFFFF
#define F32_MIN_NORMAL                       0x00800000
#define F32_EPSILON                          0x34000000   // ~1.19e-7  (ulp of 1.0)

// ────────────────────────────────────────────────────────
//  IEEE 754 float64 specials (use as raw u64 constants)
// ────────────────────────────────────────────────────────
#define F64_POS_ZERO                         0x0000000000000000
#define F64_NEG_ZERO                         0x8000000000000000
#define F64_POS_INF                          0x7FF0000000000000
#define F64_NEG_INF                          0xFFF0000000000000
#define F64_QNAN                             0x7FF8000000000000
#define F64_ONE                              0x3FF0000000000000   // 1.0
#define F64_NEG_ONE                          0xBFF0000000000000   // -1.0
#define F64_HALF                             0x3FE0000000000000   // 0.5
#define F64_PI                               0x400921FB54442D18
#define F64_TAU                              0x401921FB54442D18   // 2*pi
#define F64_E                                0x4005BF0A8B145769
#define F64_SQRT2                            0x3FF6A09E667F3BCD
#define F64_LN2                              0x3FE62E42FEFA39EF
#define F64_LOG2E                            0x3FF71547652B82FE
#define F64_MAX                              0x7FEFFFFFFFFFFFFF
#define F64_EPSILON                          0x3CB0000000000000   // ~2.22e-16

////////////////////////////////////////////////////////////////
// §02  PADDING & ALIGNMENT
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  Zero fills (exact byte counts)
// ────────────────────────────────────────────────────────
#define ZERO_1                               EMIT u8[1] 0x00
#define ZERO_2                               EMIT u8[2] 0x00
#define ZERO_3                               EMIT u8[3] 0x00
#define ZERO_4                               EMIT u8[4] 0x00
#define ZERO_6                               EMIT u8[6] 0x00
#define ZERO_8                               EMIT u8[8] 0x00
#define ZERO_10                              EMIT u8[10] 0x00
#define ZERO_12                              EMIT u8[12] 0x00
#define ZERO_14                              EMIT u8[14] 0x00
#define ZERO_16                              EMIT u8[16] 0x00
#define ZERO_20                              EMIT u8[20] 0x00
#define ZERO_24                              EMIT u8[24] 0x00
#define ZERO_28                              EMIT u8[28] 0x00
#define ZERO_32                              EMIT u8[32] 0x00
#define ZERO_48                              EMIT u8[48] 0x00
#define ZERO_64                              EMIT u8[64] 0x00
#define ZERO_128                             EMIT u8[128] 0x00
#define ZERO_256                             EMIT u8[256] 0x00
#define ZERO_512                             EMIT u8[512] 0x00

// ────────────────────────────────────────────────────────
//  0xFF fills
// ────────────────────────────────────────────────────────
#define FF_1                                 EMIT u8[1] 0xFF
#define FF_2                                 EMIT u8[2] 0xFF
#define FF_4                                 EMIT u8[4] 0xFF
#define FF_8                                 EMIT u8[8] 0xFF
#define FF_16                                EMIT u8[16] 0xFF
#define FF_32                                EMIT u8[32] 0xFF
#define FF_64                                EMIT u8[64] 0xFF
#define FF_128                               EMIT u8[128] 0xFF
#define FF_256                               EMIT u8[256] 0xFF

// ────────────────────────────────────────────────────────
//  0x90 NOP fills (code sections)
// ────────────────────────────────────────────────────────
#define NOP_4                                EMIT u8[4] 0x90
#define NOP_8                                EMIT u8[8] 0x90
#define NOP_16                               EMIT u8[16] 0x90
#define NOP_32                               EMIT u8[32] 0x90
#define NOP_64                               EMIT u8[64] 0x90

// ────────────────────────────────────────────────────────
//  0xCC INT3 fills (guard / uninitialised code)
// ────────────────────────────────────────────────────────
#define CC_4                                 EMIT u8[4] 0xCC
#define CC_8                                 EMIT u8[8] 0xCC
#define CC_16                                EMIT u8[16] 0xCC
#define CC_32                                EMIT u8[32] 0xCC

// ────────────────────────────────────────────────────────
//  Align-to-boundary with zero fill
// ────────────────────────────────────────────────────────
#define PAD_TO_2                             ALIGN 2 0x00
#define PAD_TO_4                             ALIGN 4 0x00
#define PAD_TO_8                             ALIGN 8 0x00
#define PAD_TO_16                            ALIGN 16 0x00
#define PAD_TO_32                            ALIGN 32 0x00
#define PAD_TO_64                            ALIGN 64 0x00
#define PAD_TO_128                           ALIGN 128 0x00
#define PAD_TO_256                           ALIGN 256 0x00
#define PAD_TO_512                           ALIGN 512 0x00
#define PAD_TO_PAGE                          ALIGN 4096 0x00
#define PAD_TO_SECTOR                        ALIGN 512  0x00
#define PAD_TO_CACHELN                       ALIGN 64   0x00

// ────────────────────────────────────────────────────────
//  Align-to-boundary with NOP fill (code sections)
// ────────────────────────────────────────────────────────
#define CODE_ALIGN_4                         ALIGN 4 0x90
#define CODE_ALIGN_8                         ALIGN 8 0x90
#define CODE_ALIGN_16                        ALIGN 16 0x90
#define CODE_ALIGN_32                        ALIGN 32 0x90
#define CODE_ALIGN_64                        ALIGN 64 0x90

////////////////////////////////////////////////////////////////
// §03  TEXT / ENCODING MARKERS & ANSI ESCAPES
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  Byte Order Marks
// ────────────────────────────────────────────────────────
#define UTF8_BOM                             EMIT u8 0xEF 0xBB 0xBF
#define UTF16_LE_BOM                         EMIT u8 0xFF 0xFE
#define UTF16_BE_BOM                         EMIT u8 0xFE 0xFF
#define UTF32_LE_BOM                         EMIT u8 0xFF 0xFE 0x00 0x00
#define UTF32_BE_BOM                         EMIT u8 0x00 0x00 0xFE 0xFF

// ────────────────────────────────────────────────────────
//  Line endings & common control chars
// ────────────────────────────────────────────────────────
#define CRLF                                 EMIT u8 0x0D 0x0A   // Windows
#define LF                                   EMIT u8 0x0A   // Unix
#define CR                                   EMIT u8 0x0D   // old Mac
#define TAB                                  EMIT u8 0x09
#define NULL_TERM                            EMIT u8 0x00
#define ASCII_BEL                            EMIT u8 0x07
#define ASCII_BS                             EMIT u8 0x08
#define ASCII_ESC                            EMIT u8 0x1B
#define ASCII_DEL                            EMIT u8 0x7F
#define ASCII_SPACE                          EMIT u8 0x20

// ────────────────────────────────────────────────────────
//  ANSI VT100 / VT220 escape sequences
// ────────────────────────────────────────────────────────
#define ANSI_RESET                           EMIT u8 0x1B 0x5B 0x30 0x6D
#define ANSI_BOLD                            EMIT u8 0x1B 0x5B 0x31 0x6D
#define ANSI_DIM                             EMIT u8 0x1B 0x5B 0x32 0x6D
#define ANSI_ITALIC                          EMIT u8 0x1B 0x5B 0x33 0x6D
#define ANSI_UNDERLINE                       EMIT u8 0x1B 0x5B 0x34 0x6D
#define ANSI_BLINK                           EMIT u8 0x1B 0x5B 0x35 0x6D
#define ANSI_REVERSE                         EMIT u8 0x1B 0x5B 0x37 0x6D
#define ANSI_STRIKE                          EMIT u8 0x1B 0x5B 0x39 0x6D
#define ANSI_BLACK                           EMIT u8 0x1B 0x5B 0x33 0x30 0x6D
#define ANSI_RED                             EMIT u8 0x1B 0x5B 0x33 0x31 0x6D
#define ANSI_GREEN                           EMIT u8 0x1B 0x5B 0x33 0x32 0x6D
#define ANSI_YELLOW                          EMIT u8 0x1B 0x5B 0x33 0x33 0x6D
#define ANSI_BLUE                            EMIT u8 0x1B 0x5B 0x33 0x34 0x6D
#define ANSI_MAGENTA                         EMIT u8 0x1B 0x5B 0x33 0x35 0x6D
#define ANSI_CYAN                            EMIT u8 0x1B 0x5B 0x33 0x36 0x6D
#define ANSI_WHITE                           EMIT u8 0x1B 0x5B 0x33 0x37 0x6D
#define ANSI_DEFAULT                         EMIT u8 0x1B 0x5B 0x33 0x39 0x6D
#define ANSI_BG_BLACK                        EMIT u8 0x1B 0x5B 0x34 0x30 0x6D
#define ANSI_BG_RED                          EMIT u8 0x1B 0x5B 0x34 0x31 0x6D
#define ANSI_BG_GREEN                        EMIT u8 0x1B 0x5B 0x34 0x32 0x6D
#define ANSI_BG_YELLOW                       EMIT u8 0x1B 0x5B 0x34 0x33 0x6D
#define ANSI_BG_BLUE                         EMIT u8 0x1B 0x5B 0x34 0x34 0x6D
#define ANSI_BG_MAGENTA                      EMIT u8 0x1B 0x5B 0x34 0x35 0x6D
#define ANSI_BG_CYAN                         EMIT u8 0x1B 0x5B 0x34 0x36 0x6D
#define ANSI_BG_WHITE                        EMIT u8 0x1B 0x5B 0x34 0x37 0x6D
#define ANSI_CLR_SCREEN                      EMIT u8 0x1B 0x5B 0x32 0x4A
#define ANSI_CLR_LINE                        EMIT u8 0x1B 0x5B 0x32 0x4B
#define ANSI_HOME                            EMIT u8 0x1B 0x5B 0x48
#define ANSI_CURSOR_UP                       EMIT u8 0x1B 0x5B 0x41
#define ANSI_CURSOR_DN                       EMIT u8 0x1B 0x5B 0x42
#define ANSI_CURSOR_RT                       EMIT u8 0x1B 0x5B 0x43
#define ANSI_CURSOR_LT                       EMIT u8 0x1B 0x5B 0x44
#define ANSI_SAVE_CUR                        EMIT u8 0x1B 0x5B 0x73
#define ANSI_REST_CUR                        EMIT u8 0x1B 0x5B 0x75
#define ANSI_HIDE_CUR                        EMIT u8 0x1B 0x5B 0x3F 0x32 0x35 0x6C
#define ANSI_SHOW_CUR                        EMIT u8 0x1B 0x5B 0x3F 0x32 0x35 0x68

////////////////////////////////////////////////////////////////
// §04  ELF — Executable and Linkable Format
//     Reference: System V ABI + linux/elf.h
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  e_ident (16-byte identification block)
// ────────────────────────────────────────────────────────
#define ELF_MAGIC                            EMIT u8 0x7F 0x45 0x4C 0x46   // \x7FELF
#define ELF64_IDENT                          EMIT u8 0x7F 0x45 0x4C 0x46 0x02 0x01 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00   // 64-bit LE Linux
#define ELF32_IDENT                          EMIT u8 0x7F 0x45 0x4C 0x46 0x01 0x01 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00   // 32-bit LE Linux
#define ELF64_IDENT_BSD                      EMIT u8 0x7F 0x45 0x4C 0x46 0x02 0x01 0x01 0x09 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00   // 64-bit LE FreeBSD
#define ELF64_IDENT_BE                       EMIT u8 0x7F 0x45 0x4C 0x46 0x02 0x02 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00   // 64-bit BE

// ────────────────────────────────────────────────────────
//  EI_CLASS
// ────────────────────────────────────────────────────────
#define ELFCLASS32                           0x01
#define ELFCLASS64                           0x02
// ────────────────────────────────────────────────────────
//  EI_DATA
// ────────────────────────────────────────────────────────
#define ELFDATA2LSB                          0x01   // little-endian
#define ELFDATA2MSB                          0x02   // big-endian
// ────────────────────────────────────────────────────────
//  EI_OSABI
// ────────────────────────────────────────────────────────
#define ELFOSABI_NONE                        0x00
#define ELFOSABI_HPUX                        0x01
#define ELFOSABI_NETBSD                      0x02
#define ELFOSABI_LINUX                       0x03
#define ELFOSABI_SOLARIS                     0x06
#define ELFOSABI_AIX                         0x07
#define ELFOSABI_IRIX                        0x08
#define ELFOSABI_FREEBSD                     0x09
#define ELFOSABI_TRU64                       0x0A
#define ELFOSABI_OPENBSD                     0x0C
#define ELFOSABI_ARM                         0x61
#define ELFOSABI_STANDALONE                  0xFF

// ────────────────────────────────────────────────────────
//  e_type
// ────────────────────────────────────────────────────────
#define ELF_ET_NONE                          EMIT u16 0x0000
#define ELF_ET_REL                           EMIT u16 0x0001
#define ELF_ET_EXEC                          EMIT u16 0x0002
#define ELF_ET_DYN                           EMIT u16 0x0003
#define ELF_ET_CORE                          EMIT u16 0x0004

// ────────────────────────────────────────────────────────
//  e_machine
// ────────────────────────────────────────────────────────
#define ELF_EM_NONE                          EMIT u16 0x0000
#define ELF_EM_M32                           EMIT u16 0x0001
#define ELF_EM_SPARC                         EMIT u16 0x0002
#define ELF_EM_386                           EMIT u16 0x0003
#define ELF_EM_68K                           EMIT u16 0x0004
#define ELF_EM_MIPS                          EMIT u16 0x0008
#define ELF_EM_MIPS_RS3_LE                   EMIT u16 0x000A
#define ELF_EM_PPC                           EMIT u16 0x0014
#define ELF_EM_PPC64                         EMIT u16 0x0015
#define ELF_EM_S390                          EMIT u16 0x0016
#define ELF_EM_ARM                           EMIT u16 0x0028
#define ELF_EM_SH                            EMIT u16 0x002A
#define ELF_EM_SPARCV9                       EMIT u16 0x002B
#define ELF_EM_IA64                          EMIT u16 0x0032
#define ELF_EM_X86_64                        EMIT u16 0x003E
#define ELF_EM_VAX                           EMIT u16 0x004B
#define ELF_EM_AVR                           EMIT u16 0x0053
#define ELF_EM_AARCH64                       EMIT u16 0x00B7
#define ELF_EM_RISCV                         EMIT u16 0x00F3
#define ELF_EM_BPF                           EMIT u16 0x00F7
#define ELF_EM_LOONGARCH                     EMIT u16 0x0102

// ────────────────────────────────────────────────────────
//  e_version
// ────────────────────────────────────────────────────────
#define ELF_EV_CURRENT                       EMIT u32 0x00000001

// ────────────────────────────────────────────────────────
//  Header sizes (u16)
// ────────────────────────────────────────────────────────
#define ELF64_EHSIZE                         EMIT u16 64   // sizeof(Elf64_Ehdr)
#define ELF64_PHENTSIZE                      EMIT u16 56   // sizeof(Elf64_Phdr)
#define ELF64_SHENTSIZE                      EMIT u16 64   // sizeof(Elf64_Shdr)
#define ELF32_EHSIZE                         EMIT u16 52
#define ELF32_PHENTSIZE                      EMIT u16 32
#define ELF32_SHENTSIZE                      EMIT u16 40

// ────────────────────────────────────────────────────────
//  p_type values
// ────────────────────────────────────────────────────────
#define PT_NULL                              0x00000000
#define PT_LOAD                              0x00000001
#define PT_DYNAMIC                           0x00000002
#define PT_INTERP                            0x00000003
#define PT_NOTE                              0x00000004
#define PT_SHLIB                             0x00000005
#define PT_PHDR                              0x00000006
#define PT_TLS                               0x00000007
#define PT_GNU_EH_FRAME                      0x6474E550
#define PT_GNU_STACK                         0x6474E551
#define PT_GNU_RELRO                         0x6474E552
#define PT_GNU_PROPERTY                      0x6474E553

// ────────────────────────────────────────────────────────
//  p_flags  (combine with |)
// ────────────────────────────────────────────────────────
#define PF_X                                 0x00000001   // execute
#define PF_W                                 0x00000002   // write
#define PF_R                                 0x00000004   // read

// ────────────────────────────────────────────────────────
//  Complete PT_LOAD program header prefix  (p_type u32 + p_flags u32)
// ────────────────────────────────────────────────────────
#define ELF_PHDR_LOAD_RX                     EMIT u32 0x00000001 0x00000005   // code segment
#define ELF_PHDR_LOAD_RW                     EMIT u32 0x00000001 0x00000006   // data segment
#define ELF_PHDR_LOAD_R                      EMIT u32 0x00000001 0x00000004   // read-only data
#define ELF_PHDR_LOAD_RWX                    EMIT u32 0x00000001 0x00000007   // rwx (avoid in production)

// ────────────────────────────────────────────────────────
//  sh_type values
// ────────────────────────────────────────────────────────
#define SHT_NULL                             0x00000000
#define SHT_PROGBITS                         0x00000001
#define SHT_SYMTAB                           0x00000002
#define SHT_STRTAB                           0x00000003
#define SHT_RELA                             0x00000004
#define SHT_HASH                             0x00000005
#define SHT_DYNAMIC                          0x00000006
#define SHT_NOTE                             0x00000007
#define SHT_NOBITS                           0x00000008
#define SHT_REL                              0x00000009
#define SHT_SHLIB                            0x0000000A
#define SHT_DYNSYM                           0x0000000B
#define SHT_INIT_ARRAY                       0x0000000E
#define SHT_FINI_ARRAY                       0x0000000F
#define SHT_PREINIT_ARRAY                    0x00000010
#define SHT_GROUP                            0x00000011
#define SHT_SYMTAB_SHNDX                     0x00000012

// ────────────────────────────────────────────────────────
//  sh_flags  (combine with |)
// ────────────────────────────────────────────────────────
#define SHF_WRITE                            0x00000001   // writable
#define SHF_ALLOC                            0x00000002   // occupies memory
#define SHF_EXECINSTR                        0x00000004   // executable
#define SHF_MERGE                            0x00000010   // mergeable
#define SHF_STRINGS                          0x00000020   // string table
#define SHF_INFO_LINK                        0x00000040   // sh_info is link
#define SHF_LINK_ORDER                       0x00000080   // order after link
#define SHF_TLS                              0x00000400   // thread-local
#define SHF_AX                               0x00000006   // ALLOC+EXECINSTR (.text)
#define SHF_WA                               0x00000003   // WRITE+ALLOC (.data)
#define SHF_A                                0x00000002   // ALLOC only (.rodata)

// ────────────────────────────────────────────────────────
//  d_tag values (dynamic section)
// ────────────────────────────────────────────────────────
#define DT_NULL                              0x00000000
#define DT_NEEDED                            0x00000001
#define DT_PLTRELSZ                          0x00000002
#define DT_PLTGOT                            0x00000003
#define DT_HASH                              0x00000004
#define DT_STRTAB                            0x00000005
#define DT_SYMTAB                            0x00000006
#define DT_RELA                              0x00000007
#define DT_RELASZ                            0x00000008
#define DT_RELAENT                           0x00000009
#define DT_STRSZ                             0x0000000A
#define DT_SYMENT                            0x0000000B
#define DT_INIT                              0x0000000C
#define DT_FINI                              0x0000000D
#define DT_SONAME                            0x0000000E
#define DT_RPATH                             0x0000000F
#define DT_SYMBOLIC                          0x00000010
#define DT_REL                               0x00000011
#define DT_RELSZ                             0x00000012
#define DT_RELENT                            0x00000013
#define DT_PLTREL                            0x00000014
#define DT_DEBUG                             0x00000015
#define DT_TEXTREL                           0x00000016
#define DT_JMPREL                            0x00000017
#define DT_BIND_NOW                          0x00000018
#define DT_INIT_ARRAY                        0x00000019
#define DT_FINI_ARRAY                        0x0000001A
#define DT_INIT_ARRAYSZ                      0x0000001B
#define DT_FINI_ARRAYSZ                      0x0000001C
#define DT_RUNPATH                           0x0000001D
#define DT_FLAGS                             0x0000001E
#define DT_PREINIT_ARRAY                     0x00000020
#define DT_PREINIT_ARRAYSZ                   0x00000021
#define DT_FLAGS_1                           0x6FFFFFFB
#define DT_VERSYM                            0x6FFFFFF0
#define DT_VERDEF                            0x6FFFFFFC
#define DT_VERDEFNUM                         0x6FFFFFFD
#define DT_VERNEED                           0x6FFFFFFE
#define DT_VERNEEDNUM                        0x6FFFFFFF

// ────────────────────────────────────────────────────────
//  Symbol binding (STB) & type (STT)
// ────────────────────────────────────────────────────────
#define STB_LOCAL                            0
#define STB_GLOBAL                           1
#define STB_WEAK                             2
#define STB_GNU_UNIQUE                       10
#define STT_NOTYPE                           0
#define STT_OBJECT                           1
#define STT_FUNC                             2
#define STT_SECTION                          3
#define STT_FILE                             4
#define STT_COMMON                           5
#define STT_TLS                              6
#define STT_GNU_IFUNC                        10

// ────────────────────────────────────────────────────────
//  x86-64 relocation types (R_X86_64_*)
// ────────────────────────────────────────────────────────
#define R_X86_64_NONE                        0
#define R_X86_64_64                          1
#define R_X86_64_PC32                        2
#define R_X86_64_GOT32                       3
#define R_X86_64_PLT32                       4
#define R_X86_64_COPY                        5
#define R_X86_64_GLOB_DAT                    6
#define R_X86_64_JUMP_SLOT                   7
#define R_X86_64_RELATIVE                    8
#define R_X86_64_GOTPCREL                    9
#define R_X86_64_32                          10
#define R_X86_64_32S                         11
#define R_X86_64_16                          12
#define R_X86_64_PC16                        13
#define R_X86_64_8                           14
#define R_X86_64_PC8                         15
#define R_X86_64_DTPMOD64                    16
#define R_X86_64_DTPOFF64                    17
#define R_X86_64_TPOFF64                     18
#define R_X86_64_TLSGD                       19
#define R_X86_64_TLSLD                       20
#define R_X86_64_DTPOFF32                    21
#define R_X86_64_GOTTPOFF                    22
#define R_X86_64_TPOFF32                     23
#define R_X86_64_PC64                        24
#define R_X86_64_GOTOFF64                    25
#define R_X86_64_GOTPC32                     26
#define R_X86_64_SIZE32                      32
#define R_X86_64_SIZE64                      33
#define R_X86_64_IRELATIVE                   37

// ────────────────────────────────────────────────────────
//  AArch64 relocation types (R_AARCH64_*)
// ────────────────────────────────────────────────────────
#define R_AARCH64_NONE                       0
#define R_AARCH64_ABS64                      257
#define R_AARCH64_ABS32                      258
#define R_AARCH64_ABS16                      259
#define R_AARCH64_PREL64                     260
#define R_AARCH64_PREL32                     261
#define R_AARCH64_PREL16                     262
#define R_AARCH64_MOVW_UABS_G0               263
#define R_AARCH64_MOVW_UABS_G1               265
#define R_AARCH64_MOVW_UABS_G2               267
#define R_AARCH64_MOVW_UABS_G3               269
#define R_AARCH64_CALL26                     283
#define R_AARCH64_JUMP26                     282
#define R_AARCH64_GLOB_DAT                   1025
#define R_AARCH64_JUMP_SLOT                  1026
#define R_AARCH64_RELATIVE                   1027
#define R_AARCH64_COPY                       1024
#define R_AARCH64_TLSDESC                    1031
#define R_AARCH64_IRELATIVE                  1032

// ────────────────────────────────────────────────────────
//  Common Linux ELF interpreter paths (null-terminated)
// ────────────────────────────────────────────────────────
#define ELF_INTERP_X64                       EMIT u8 0x2F 0x6C 0x69 0x62 0x36 0x34 0x2F 0x6C 0x64 0x2D 0x6C 0x69 0x6E 0x75 0x78 0x2D 0x78 0x38 0x36 0x2D 0x36 0x34 0x2E 0x73 0x6F 0x2E 0x32 0x00
#define ELF_INTERP_AARCH64                   EMIT u8 0x2F 0x6C 0x69 0x62 0x2F 0x6C 0x64 0x2D 0x6C 0x69 0x6E 0x75 0x78 0x2D 0x61 0x61 0x72 0x63 0x68 0x36 0x34 0x2E 0x73 0x6F 0x2E 0x31 0x00
#define ELF_INTERP_MUSL_X64                  EMIT u8 0x2F 0x6C 0x69 0x62 0x2F 0x6C 0x64 0x2D 0x6D 0x75 0x73 0x6C 0x2D 0x78 0x38 0x36 0x5F 0x36 0x34 0x2E 0x73 0x6F 0x2E 0x31 0x00

////////////////////////////////////////////////////////////////
// §05  PE/COFF — Windows Portable Executable
//     Reference: Microsoft PE/COFF Specification
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  DOS header
// ────────────────────────────────────────────────────────
#define PE_DOS_MAGIC                         EMIT u8 0x4D 0x5A   // MZ signature
#define PE_DOS_STUB                          EMIT u8 0x4D 0x5A 0x90 0x00 0x03 0x00 0x00 0x00 0x04 0x00 0x00 0x00 0xFF 0xFF 0x00 0x00 0xB8 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x40 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x40 0x00 0x00 0x00   // 64-byte MZ stub, e_lfanew=0x40
#define PE_SIGNATURE                         EMIT u8 0x50 0x45 0x00 0x00   // PE\0\0

// ────────────────────────────────────────────────────────
//  Machine types (u16 LE)
// ────────────────────────────────────────────────────────
#define PE_MACHINE_UNKNOWN                   EMIT u16 0x0000
#define PE_MACHINE_X86                       EMIT u16 0x014C
#define PE_MACHINE_ALPHA                     EMIT u16 0x0184
#define PE_MACHINE_ARM                       EMIT u16 0x01C0
#define PE_MACHINE_ARMNT                     EMIT u16 0x01C4
#define PE_MACHINE_ARM64                     EMIT u16 0xAA64
#define PE_MACHINE_EBC                       EMIT u16 0x0EBC
#define PE_MACHINE_X64                       EMIT u16 0x8664
#define PE_MACHINE_IA64                      EMIT u16 0x0200
#define PE_MACHINE_LOONGARCH32               EMIT u16 0x6232
#define PE_MACHINE_LOONGARCH64               EMIT u16 0x6264
#define PE_MACHINE_M32R                      EMIT u16 0x9041
#define PE_MACHINE_MIPS16                    EMIT u16 0x0266
#define PE_MACHINE_MIPSF41                   EMIT u16 0x0366
#define PE_MACHINE_POWERPC                   EMIT u16 0x01F0
#define PE_MACHINE_R4000                     EMIT u16 0x0166
#define PE_MACHINE_RISCV32                   EMIT u16 0x5032
#define PE_MACHINE_RISCV64                   EMIT u16 0x5064
#define PE_MACHINE_RISCV128                  EMIT u16 0x5128
#define PE_MACHINE_SH3                       EMIT u16 0x01A2
#define PE_MACHINE_SH4                       EMIT u16 0x01A6
#define PE_MACHINE_THUMB                     EMIT u16 0x01C2
#define PE_MACHINE_WCEMIPS                   EMIT u16 0x0169

// ────────────────────────────────────────────────────────
//  COFF Characteristics flags
// ────────────────────────────────────────────────────────
#define PE_CHAR_RELOCS_STRIPPED              0x0001   // relocs removed
#define PE_CHAR_EXECUTABLE                   0x0002   // image is executable
#define PE_CHAR_LINE_NUMS_STRIPPED           0x0004
#define PE_CHAR_LOCAL_SYMS_STRIPPED          0x0008
#define PE_CHAR_AGGRESSIVE_WS_TRIM           0x0010   // obsolete
#define PE_CHAR_LARGE_ADDRESS_AWARE          0x0020   // >2GB addresses
#define PE_CHAR_BYTES_REVERSED_LO            0x0080   // obsolete
#define PE_CHAR_32BIT_MACHINE                0x0100
#define PE_CHAR_DEBUG_STRIPPED               0x0200
#define PE_CHAR_REMOVABLE_RUN_FROM_SWAP      0x0400
#define PE_CHAR_NET_RUN_FROM_SWAP            0x0800
#define PE_CHAR_SYSTEM                       0x1000   // system file
#define PE_CHAR_DLL                          0x2000   // DLL
#define PE_CHAR_UP_SYSTEM_ONLY               0x4000   // uni-processor only
#define PE_CHAR_BYTES_REVERSED_HI            0x8000   // obsolete
#define PE_CHARS_EXE64                       EMIT u16 0x0022   // typical 64-bit exe
#define PE_CHARS_EXE32                       EMIT u16 0x0102   // typical 32-bit exe
#define PE_CHARS_DLL64                       EMIT u16 0x2022   // typical 64-bit DLL

// ────────────────────────────────────────────────────────
//  Optional header magic
// ────────────────────────────────────────────────────────
#define PE_OPT_PE32                          EMIT u16 0x010B   // 32-bit image
#define PE_OPT_PE32PLUS                      EMIT u16 0x020B   // 64-bit image
#define PE_OPT_ROM                           EMIT u16 0x0107   // ROM image

// ────────────────────────────────────────────────────────
//  Subsystem values (u16)
// ────────────────────────────────────────────────────────
#define PE_SUBSYS_UNKNOWN                    EMIT u16 0x0000
#define PE_SUBSYS_NATIVE                     EMIT u16 0x0001
#define PE_SUBSYS_WINDOWS_GUI                EMIT u16 0x0002
#define PE_SUBSYS_WINDOWS_CUI                EMIT u16 0x0003
#define PE_SUBSYS_OS2_CUI                    EMIT u16 0x0005
#define PE_SUBSYS_POSIX_CUI                  EMIT u16 0x0007
#define PE_SUBSYS_NATIVE_WINDOWS             EMIT u16 0x0008
#define PE_SUBSYS_WINDOWS_CE_GUI             EMIT u16 0x0009
#define PE_SUBSYS_EFI_APPLICATION            EMIT u16 0x000A
#define PE_SUBSYS_EFI_BOOT_SERVICE_DRIVER    EMIT u16 0x000B
#define PE_SUBSYS_EFI_RUNTIME_DRIVER         EMIT u16 0x000C
#define PE_SUBSYS_EFI_ROM                    EMIT u16 0x000D
#define PE_SUBSYS_XBOX                       EMIT u16 0x000E
#define PE_SUBSYS_WINDOWS_BOOT_APPLICATION   EMIT u16 0x0010

// ────────────────────────────────────────────────────────
//  DLL Characteristics flags (u16)
// ────────────────────────────────────────────────────────
#define PE_DLLCHAR_HIGH_ENTROPY_VA           0x0020   // ASLR with 64-bit VA
#define PE_DLLCHAR_DYNAMIC_BASE              0x0040   // ASLR
#define PE_DLLCHAR_FORCE_INTEGRITY           0x0080   // code integrity checks
#define PE_DLLCHAR_NX_COMPAT                 0x0100   // DEP compatible
#define PE_DLLCHAR_NO_ISOLATION              0x0200   // do not isolate
#define PE_DLLCHAR_NO_SEH                    0x0400   // no structured exception handling
#define PE_DLLCHAR_NO_BIND                   0x0800   // do not bind
#define PE_DLLCHAR_APPCONTAINER              0x1000   // must run in appcontainer
#define PE_DLLCHAR_WDM_DRIVER                0x2000   // WDM driver
#define PE_DLLCHAR_GUARD_CF                  0x4000   // Control Flow Guard
#define PE_DLLCHAR_TERMINAL_SERVER_AWARE     0x8000
#define PE_DLLCHARS_MODERN                   EMIT u16 0x8160   // NX+ASLR+HIGH_ENTROPY+TERMINAL_AWARE

// ────────────────────────────────────────────────────────
//  Section characteristics flags
// ────────────────────────────────────────────────────────
#define PE_SCN_CNT_CODE                      0x00000020
#define PE_SCN_CNT_INIT_DATA                 0x00000040
#define PE_SCN_CNT_UNINIT_DATA               0x00000080
#define PE_SCN_LNK_INFO                      0x00000200
#define PE_SCN_LNK_REMOVE                    0x00000800
#define PE_SCN_LNK_COMDAT                    0x00001000
#define PE_SCN_GPREL                         0x00008000
#define PE_SCN_MEM_PURGEABLE                 0x00020000
#define PE_SCN_MEM_16BIT                     0x00020000
#define PE_SCN_MEM_LOCKED                    0x00040000
#define PE_SCN_MEM_PRELOAD                   0x00080000
#define PE_SCN_ALIGN_1BYTES                  0x00100000
#define PE_SCN_ALIGN_2BYTES                  0x00200000
#define PE_SCN_ALIGN_4BYTES                  0x00300000
#define PE_SCN_ALIGN_8BYTES                  0x00400000
#define PE_SCN_ALIGN_16BYTES                 0x00500000
#define PE_SCN_ALIGN_32BYTES                 0x00600000
#define PE_SCN_ALIGN_64BYTES                 0x00700000
#define PE_SCN_ALIGN_128BYTES                0x00800000
#define PE_SCN_ALIGN_256BYTES                0x00900000
#define PE_SCN_ALIGN_512BYTES                0x00A00000
#define PE_SCN_ALIGN_1024BYTES               0x00B00000
#define PE_SCN_ALIGN_2048BYTES               0x00C00000
#define PE_SCN_ALIGN_4096BYTES               0x00D00000
#define PE_SCN_ALIGN_8192BYTES               0x00E00000
#define PE_SCN_LNK_NRELOC_OVFL               0x01000000
#define PE_SCN_MEM_DISCARDABLE               0x02000000
#define PE_SCN_MEM_NOT_CACHED                0x04000000
#define PE_SCN_MEM_NOT_PAGED                 0x08000000
#define PE_SCN_MEM_SHARED                    0x10000000
#define PE_SCN_MEM_EXECUTE                   0x20000000
#define PE_SCN_MEM_READ                      0x40000000
#define PE_SCN_MEM_WRITE                     0x80000000

// ────────────────────────────────────────────────────────
//  Combined section flags (emit as u32)
// ────────────────────────────────────────────────────────
#define PE_TEXT_FLAGS                        EMIT u32 0x60000020   // .text: code+exec+read
#define PE_DATA_FLAGS                        EMIT u32 0xC0000040   // .data: init_data+read+write
#define PE_RDATA_FLAGS                       EMIT u32 0x40000040   // .rdata: init_data+read
#define PE_BSS_FLAGS                         EMIT u32 0xC0000080   // .bss: uninit+read+write
#define PE_RSRC_FLAGS                        EMIT u32 0x40000040   // .rsrc: init_data+read
#define PE_RELOC_FLAGS                       EMIT u32 0x42000040   // .reloc: discardable+init_data+read

// ────────────────────────────────────────────────────────
//  Section names (8-byte zero-padded ASCII)
// ────────────────────────────────────────────────────────
#define PE_SECTION_TEXT                      EMIT u8 0x2E 0x74 0x65 0x78 0x74 0x00 0x00 0x00
#define PE_SECTION_DATA                      EMIT u8 0x2E 0x64 0x61 0x74 0x61 0x00 0x00 0x00
#define PE_SECTION_RDATA                     EMIT u8 0x2E 0x72 0x64 0x61 0x74 0x61 0x00 0x00
#define PE_SECTION_BSS                       EMIT u8 0x2E 0x62 0x73 0x73 0x00 0x00 0x00 0x00
#define PE_SECTION_IDATA                     EMIT u8 0x2E 0x69 0x64 0x61 0x74 0x61 0x00 0x00
#define PE_SECTION_EDATA                     EMIT u8 0x2E 0x65 0x64 0x61 0x74 0x61 0x00 0x00
#define PE_SECTION_RSRC                      EMIT u8 0x2E 0x72 0x73 0x72 0x63 0x00 0x00 0x00
#define PE_SECTION_RELOC                     EMIT u8 0x2E 0x72 0x65 0x6C 0x6F 0x63 0x00 0x00
#define PE_SECTION_PDATA                     EMIT u8 0x2E 0x70 0x64 0x61 0x74 0x61 0x00 0x00
#define PE_SECTION_XDATA                     EMIT u8 0x2E 0x78 0x64 0x61 0x74 0x61 0x00 0x00
#define PE_SECTION_TLS                       EMIT u8 0x2E 0x74 0x6C 0x73 0x00 0x00 0x00 0x00
#define PE_SECTION_DEBUG                     EMIT u8 0x2E 0x64 0x65 0x62 0x75 0x67 0x00 0x00
#define PE_SECTION_DIDAT                     EMIT u8 0x2E 0x64 0x69 0x64 0x61 0x74 0x00 0x00
#define PE_SECTION_CRT                       EMIT u8 0x2E 0x43 0x52 0x54 0x00 0x00 0x00 0x00

// ────────────────────────────────────────────────────────
//  Data directory indices
// ────────────────────────────────────────────────────────
#define PE_DD_EXPORT                         0
#define PE_DD_IMPORT                         1
#define PE_DD_RESOURCE                       2
#define PE_DD_EXCEPTION                      3
#define PE_DD_SECURITY                       4
#define PE_DD_BASERELOC                      5
#define PE_DD_DEBUG                          6
#define PE_DD_COPYRIGHT                      7
#define PE_DD_GLOBALPTR                      8
#define PE_DD_TLS                            9
#define PE_DD_LOAD_CONFIG                    10
#define PE_DD_BOUND_IMPORT                   11
#define PE_DD_IAT                            12
#define PE_DD_DELAY_IMPORT                   13
#define PE_DD_COM_DESCRIPTOR                 14

// ────────────────────────────────────────────────────────
//  Base relocation types
// ────────────────────────────────────────────────────────
#define IMAGE_REL_BASED_ABSOLUTE             0
#define IMAGE_REL_BASED_HIGH                 1
#define IMAGE_REL_BASED_LOW                  2
#define IMAGE_REL_BASED_HIGHLOW              3
#define IMAGE_REL_BASED_HIGHADJ              4
#define IMAGE_REL_BASED_MIPS_JMPADDR         5
#define IMAGE_REL_BASED_ARM_MOV32            5
#define IMAGE_REL_BASED_RISCV_HIGH20         5
#define IMAGE_REL_BASED_THUMB_MOV32          7
#define IMAGE_REL_BASED_RISCV_LOW12I         7
#define IMAGE_REL_BASED_RISCV_LOW12S         8
#define IMAGE_REL_BASED_MIPS_JMPADDR16       9
#define IMAGE_REL_BASED_DIR64                10

////////////////////////////////////////////////////////////////
// §06  MACH-O — macOS / iOS / watchOS
//     Reference: <mach-o/loader.h>
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  Magic numbers
// ────────────────────────────────────────────────────────
#define MACHO_MAGIC32                        EMIT u32 0xFEEDFACE   // 32-bit LE
#define MACHO_MAGIC64                        EMIT u32 0xFEEDFACF   // 64-bit LE
#define MACHO_CIGAM32                        EMIT u32 0xCEFAEDFE   // 32-bit BE
#define MACHO_CIGAM64                        EMIT u32 0xCFFAEDFE   // 64-bit BE
#define MACHO_FAT_MAGIC                      EMIT u32 0xCAFEBABE   // universal/fat binary
#define MACHO_FAT_CIGAM                      EMIT u32 0xBEBAFECA

// ────────────────────────────────────────────────────────
//  CPU type + subtype pairs (cputype u32, cpusubtype u32)
// ────────────────────────────────────────────────────────
#define MACHO_CPU_X86                        EMIT u32 0x00000007 0x00000003
#define MACHO_CPU_X86_64                     EMIT u32 0x01000007 0x00000003
#define MACHO_CPU_ARM                        EMIT u32 0x0000000C 0x00000000
#define MACHO_CPU_ARM64                      EMIT u32 0x0100000C 0x00000000
#define MACHO_CPU_ARM64E                     EMIT u32 0x0100000C 0x80000002
#define MACHO_CPU_PPC                        EMIT u32 0x00000012 0x00000000
#define MACHO_CPU_PPC64                      EMIT u32 0x01000012 0x00000000

// ────────────────────────────────────────────────────────
//  File types (mach_header.filetype)
// ────────────────────────────────────────────────────────
#define MACHO_MH_OBJECT                      0x00000001
#define MACHO_MH_EXECUTE                     0x00000002
#define MACHO_MH_FVMLIB                      0x00000003
#define MACHO_MH_CORE                        0x00000004
#define MACHO_MH_PRELOAD                     0x00000005
#define MACHO_MH_DYLIB                       0x00000006
#define MACHO_MH_DYLINKER                    0x00000007
#define MACHO_MH_BUNDLE                      0x00000008
#define MACHO_MH_DYLIB_STUB                  0x00000009
#define MACHO_MH_DSYM                        0x0000000A
#define MACHO_MH_KEXT_BUNDLE                 0x0000000B
#define MACHO_MH_FILESET                     0x0000000C

// ────────────────────────────────────────────────────────
//  Header flags (mach_header.flags  — combine with |)
// ────────────────────────────────────────────────────────
#define MACHO_MH_NOUNDEFS                    0x00000001   // no undefined refs
#define MACHO_MH_INCRLINK                    0x00000002   // incremental link
#define MACHO_MH_DYLDLINK                    0x00000004   // input to dyld
#define MACHO_MH_BINDATLOAD                  0x00000008
#define MACHO_MH_PREBOUND                    0x00000010
#define MACHO_MH_SPLIT_SEGS                  0x00000020
#define MACHO_MH_LAZY_INIT                   0x00000040
#define MACHO_MH_TWOLEVEL                    0x00000080   // two-level namespace
#define MACHO_MH_FORCE_FLAT                  0x00000100
#define MACHO_MH_NOMULTIDEFS                 0x00000200
#define MACHO_MH_NOFIXPREBINDING             0x00000400
#define MACHO_MH_PREBINDABLE                 0x00000800
#define MACHO_MH_ALLMODSBOUND                0x00001000
#define MACHO_MH_SUBSECTIONS_VIA_SYMBOLS     0x00002000
#define MACHO_MH_CANONICAL                   0x00004000
#define MACHO_MH_WEAK_DEFINES                0x00008000
#define MACHO_MH_BINDS_TO_WEAK               0x00010000
#define MACHO_MH_ALLOW_STACK_EXECUTION       0x00020000
#define MACHO_MH_ROOT_SAFE                   0x00040000
#define MACHO_MH_SETUID_SAFE                 0x00080000
#define MACHO_MH_NO_REEXPORTED_DYLIBS        0x00100000
#define MACHO_MH_PIE                         0x00200000   // ASLR
#define MACHO_MH_DEAD_STRIPPABLE_DYLIB       0x00400000
#define MACHO_MH_HAS_TLV_DESCRIPTORS         0x00800000
#define MACHO_MH_NO_HEAP_EXECUTION           0x01000000
#define MACHO_FLAGS_EXE_PIE                  0x00200085   // typical PIE executable
#define MACHO_FLAGS_DYLIB                    0x00000085   // typical dylib

// ────────────────────────────────────────────────────────
//  Load command types (LC_*)
// ────────────────────────────────────────────────────────
#define LC_SEGMENT                           0x00000001
#define LC_SYMTAB                            0x00000002
#define LC_SYMSEG                            0x00000003
#define LC_THREAD                            0x00000004
#define LC_UNIXTHREAD                        0x00000005
#define LC_LOADFVMLIB                        0x00000006
#define LC_IDFVMLIB                          0x00000007
#define LC_IDENT                             0x00000008
#define LC_FVMFILE                           0x00000009
#define LC_PREPAGE                           0x0000000A
#define LC_DYSYMTAB                          0x0000000B
#define LC_LOAD_DYLIB                        0x0000000C
#define LC_ID_DYLIB                          0x0000000D
#define LC_LOAD_DYLINKER                     0x0000000E
#define LC_ID_DYLINKER                       0x0000000F
#define LC_PREBOUND_DYLIB                    0x00000010
#define LC_ROUTINES                          0x00000011
#define LC_SUB_FRAMEWORK                     0x00000012
#define LC_SUB_UMBRELLA                      0x00000013
#define LC_SUB_CLIENT                        0x00000014
#define LC_SUB_LIBRARY                       0x00000015
#define LC_TWOLEVEL_HINTS                    0x00000016
#define LC_PREBIND_CKSUM                     0x00000017
#define LC_SEGMENT_64                        0x00000019
#define LC_ROUTINES_64                       0x0000001A
#define LC_UUID                              0x0000001B
#define LC_RPATH                             0x8000001C
#define LC_CODE_SIGNATURE                    0x0000001D
#define LC_SEGMENT_SPLIT_INFO                0x0000001E
#define LC_REEXPORT_DYLIB                    0x8000001F
#define LC_LAZY_LOAD_DYLIB                   0x00000020
#define LC_ENCRYPTION_INFO                   0x00000021
#define LC_DYLD_INFO                         0x00000022
#define LC_DYLD_INFO_ONLY                    0x80000022
#define LC_LOAD_UPWARD_DYLIB                 0x80000023
#define LC_VERSION_MIN_MACOSX                0x00000024
#define LC_VERSION_MIN_IPHONEOS              0x00000025
#define LC_FUNCTION_STARTS                   0x00000026
#define LC_DYLD_ENVIRONMENT                  0x00000027
#define LC_MAIN                              0x80000028
#define LC_DATA_IN_CODE                      0x00000029
#define LC_SOURCE_VERSION                    0x0000002A
#define LC_DYLIB_CODE_SIGN_DRS               0x0000002B
#define LC_ENCRYPTION_INFO_64                0x0000002C
#define LC_LINKER_OPTION                     0x0000002D
#define LC_LINKER_OPTIMIZATION_HINT          0x0000002E
#define LC_VERSION_MIN_TVOS                  0x0000002F
#define LC_VERSION_MIN_WATCHOS               0x00000030
#define LC_NOTE                              0x00000031
#define LC_BUILD_VERSION                     0x00000032
#define LC_DYLD_EXPORTS_TRIE                 0x80000033
#define LC_DYLD_CHAINED_FIXUPS               0x80000034
#define LC_FILESET_ENTRY                     0x80000035

// ────────────────────────────────────────────────────────
//  VM protection flags (vm_prot_t — combine with |)
// ────────────────────────────────────────────────────────
#define VM_PROT_NONE                         0x00
#define VM_PROT_READ                         0x01
#define VM_PROT_WRITE                        0x02
#define VM_PROT_EXEC                         0x04
#define VM_PROT_RX                           0x05
#define VM_PROT_RW                           0x03
#define VM_PROT_RWX                          0x07

// ────────────────────────────────────────────────────────
//  Common segment names (16-byte zero-padded ASCII)
// ────────────────────────────────────────────────────────
#define MACHO_SEG_TEXT                       EMIT u8 0x5F 0x5F 0x54 0x45 0x58 0x54 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
#define MACHO_SEG_DATA                       EMIT u8 0x5F 0x5F 0x44 0x41 0x54 0x41 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
#define MACHO_SEG_DATA_CONST                 EMIT u8 0x5F 0x5F 0x44 0x41 0x54 0x41 0x5F 0x43 0x4F 0x4E 0x53 0x54 0x00 0x00 0x00 0x00
#define MACHO_SEG_LINKEDIT                   EMIT u8 0x5F 0x5F 0x4C 0x49 0x4E 0x4B 0x45 0x44 0x49 0x54 0x00 0x00 0x00 0x00 0x00 0x00
#define MACHO_SEG_PAGEZERO                   EMIT u8 0x5F 0x5F 0x50 0x41 0x47 0x45 0x5A 0x45 0x52 0x4F 0x00 0x00 0x00 0x00 0x00 0x00

// ────────────────────────────────────────────────────────
//  Common section names (16-byte zero-padded ASCII)
// ────────────────────────────────────────────────────────
#define MACHO_SECT_TEXT                      EMIT u8 0x5F 0x5F 0x74 0x65 0x78 0x74 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
#define MACHO_SECT_STUBS                     EMIT u8 0x5F 0x5F 0x73 0x74 0x75 0x62 0x73 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
#define MACHO_SECT_STUB_HELPER               EMIT u8 0x5F 0x5F 0x73 0x74 0x75 0x62 0x5F 0x68 0x65 0x6C 0x70 0x65 0x72 0x00 0x00 0x00
#define MACHO_SECT_DATA                      EMIT u8 0x5F 0x5F 0x64 0x61 0x74 0x61 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
#define MACHO_SECT_BSS                       EMIT u8 0x5F 0x5F 0x62 0x73 0x73 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
#define MACHO_SECT_CONST                     EMIT u8 0x5F 0x5F 0x63 0x6F 0x6E 0x73 0x74 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
#define MACHO_SECT_CSTRING                   EMIT u8 0x5F 0x5F 0x63 0x73 0x74 0x72 0x69 0x6E 0x67 0x00 0x00 0x00 0x00 0x00 0x00 0x00
#define MACHO_SECT_OBJC_METHNAMES            EMIT u8 0x5F 0x5F 0x6F 0x62 0x6A 0x63 0x5F 0x6D 0x65 0x74 0x68 0x6E 0x61 0x6D 0x65 0x73
#define MACHO_SECT_UNWIND_INFO               EMIT u8 0x5F 0x5F 0x75 0x6E 0x77 0x69 0x6E 0x64 0x5F 0x69 0x6E 0x66 0x6F 0x00 0x00 0x00
#define MACHO_SECT_EH_FRAME                  EMIT u8 0x5F 0x5F 0x65 0x68 0x5F 0x66 0x72 0x61 0x6D 0x65 0x00 0x00 0x00 0x00 0x00 0x00
#define MACHO_SECT_CFSTRING                  EMIT u8 0x5F 0x5F 0x63 0x66 0x73 0x74 0x72 0x69 0x6E 0x67 0x00 0x00 0x00 0x00 0x00 0x00
#define MACHO_SECT_GOT                       EMIT u8 0x5F 0x5F 0x67 0x6F 0x74 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
#define MACHO_SECT_LA_SYMBOL_PTR             EMIT u8 0x5F 0x5F 0x6C 0x61 0x5F 0x73 0x79 0x6D 0x62 0x6F 0x6C 0x5F 0x70 0x74 0x72 0x00
#define MACHO_SECT_NL_SYMBOL_PTR             EMIT u8 0x5F 0x5F 0x6E 0x6C 0x5F 0x73 0x79 0x6D 0x62 0x6F 0x6C 0x5F 0x70 0x74 0x72 0x00

////////////////////////////////////////////////////////////////
// §07  WEBASSEMBLY — All opcodes, section IDs, value types
//     Reference: WebAssembly Core Specification 2.0
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  Module header
// ────────────────────────────────────────────────────────
#define WASM_MAGIC                           EMIT u8 0x00 0x61 0x73 0x6D   // \0asm
#define WASM_VERSION                         EMIT u8 0x01 0x00 0x00 0x00
#define WASM_HEADER                          EMIT u8 0x00 0x61 0x73 0x6D 0x01 0x00 0x00 0x00

// ────────────────────────────────────────────────────────
//  Section IDs
// ────────────────────────────────────────────────────────
#define WASM_SEC_CUSTOM                      EMIT u8 0x00
#define WASM_SEC_TYPE                        EMIT u8 0x01
#define WASM_SEC_IMPORT                      EMIT u8 0x02
#define WASM_SEC_FUNCTION                    EMIT u8 0x03
#define WASM_SEC_TABLE                       EMIT u8 0x04
#define WASM_SEC_MEMORY                      EMIT u8 0x05
#define WASM_SEC_GLOBAL                      EMIT u8 0x06
#define WASM_SEC_EXPORT                      EMIT u8 0x07
#define WASM_SEC_START                       EMIT u8 0x08
#define WASM_SEC_ELEMENT                     EMIT u8 0x09
#define WASM_SEC_CODE                        EMIT u8 0x0A
#define WASM_SEC_DATA                        EMIT u8 0x0B
#define WASM_SEC_DATA_COUNT                  EMIT u8 0x0C
#define WASM_SEC_TAG                         EMIT u8 0x0D

// ────────────────────────────────────────────────────────
//  Value types (LEB128-encoded)
// ────────────────────────────────────────────────────────
#define WASM_I32                             0x7F
#define WASM_I64                             0x7E
#define WASM_F32                             0x7D
#define WASM_F64                             0x7C
#define WASM_V128                            0x7B
#define WASM_FUNCREF                         0x70
#define WASM_EXTERNREF                       0x6F
#define WASM_VOID                            0x40   // block type: empty

// ────────────────────────────────────────────────────────
//  Import/export external kinds
// ────────────────────────────────────────────────────────
#define WASM_EXT_FUNC                        0x00
#define WASM_EXT_TABLE                       0x01
#define WASM_EXT_MEM                         0x02
#define WASM_EXT_GLOBAL                      0x03
#define WASM_EXT_TAG                         0x04

// ────────────────────────────────────────────────────────
//  Global mutability
// ────────────────────────────────────────────────────────
#define WASM_CONST                           0x00
#define WASM_MUT                             0x01

// ────────────────────────────────────────────────────────
//  Numeric opcodes (single byte)
// ────────────────────────────────────────────────────────
#define WASM_UNREACHABLE                     EMIT u8 0x00
#define WASM_NOP                             EMIT u8 0x01
#define WASM_BLOCK                           EMIT u8 0x02
#define WASM_LOOP                            EMIT u8 0x03
#define WASM_IF                              EMIT u8 0x04
#define WASM_ELSE                            EMIT u8 0x05
#define WASM_TRY                             EMIT u8 0x06
#define WASM_CATCH                           EMIT u8 0x07
#define WASM_THROW                           EMIT u8 0x08
#define WASM_RETHROW                         EMIT u8 0x09
#define WASM_END                             EMIT u8 0x0B
#define WASM_BR                              EMIT u8 0x0C
#define WASM_BR_IF                           EMIT u8 0x0D
#define WASM_BR_TABLE                        EMIT u8 0x0E
#define WASM_RETURN                          EMIT u8 0x0F
#define WASM_CALL                            EMIT u8 0x10
#define WASM_CALL_INDIRECT                   EMIT u8 0x11
#define WASM_RETURN_CALL                     EMIT u8 0x12
#define WASM_RETURN_CALL_INDIRECT            EMIT u8 0x13
#define WASM_CALL_REF                        EMIT u8 0x14
#define WASM_RETURN_CALL_REF                 EMIT u8 0x15
#define WASM_DROP                            EMIT u8 0x1A
#define WASM_SELECT                          EMIT u8 0x1B
#define WASM_SELECT_T                        EMIT u8 0x1C
#define WASM_LOCAL_GET                       EMIT u8 0x20
#define WASM_LOCAL_SET                       EMIT u8 0x21
#define WASM_LOCAL_TEE                       EMIT u8 0x22
#define WASM_GLOBAL_GET                      EMIT u8 0x23
#define WASM_GLOBAL_SET                      EMIT u8 0x24
#define WASM_TABLE_GET                       EMIT u8 0x25
#define WASM_TABLE_SET                       EMIT u8 0x26
#define WASM_I32_LOAD                        EMIT u8 0x28
#define WASM_I64_LOAD                        EMIT u8 0x29
#define WASM_F32_LOAD                        EMIT u8 0x2A
#define WASM_F64_LOAD                        EMIT u8 0x2B
#define WASM_I32_LOAD8_S                     EMIT u8 0x2C
#define WASM_I32_LOAD8_U                     EMIT u8 0x2D
#define WASM_I32_LOAD16_S                    EMIT u8 0x2E
#define WASM_I32_LOAD16_U                    EMIT u8 0x2F
#define WASM_I64_LOAD8_S                     EMIT u8 0x30
#define WASM_I64_LOAD8_U                     EMIT u8 0x31
#define WASM_I64_LOAD16_S                    EMIT u8 0x32
#define WASM_I64_LOAD16_U                    EMIT u8 0x33
#define WASM_I64_LOAD32_S                    EMIT u8 0x34
#define WASM_I64_LOAD32_U                    EMIT u8 0x35
#define WASM_I32_STORE                       EMIT u8 0x36
#define WASM_I64_STORE                       EMIT u8 0x37
#define WASM_F32_STORE                       EMIT u8 0x38
#define WASM_F64_STORE                       EMIT u8 0x39
#define WASM_I32_STORE8                      EMIT u8 0x3A
#define WASM_I32_STORE16                     EMIT u8 0x3B
#define WASM_I64_STORE8                      EMIT u8 0x3C
#define WASM_I64_STORE16                     EMIT u8 0x3D
#define WASM_I64_STORE32                     EMIT u8 0x3E
#define WASM_MEMORY_SIZE                     EMIT u8 0x3F
#define WASM_MEMORY_GROW                     EMIT u8 0x40
#define WASM_I32_CONST                       EMIT u8 0x41
#define WASM_I64_CONST                       EMIT u8 0x42
#define WASM_F32_CONST                       EMIT u8 0x43
#define WASM_F64_CONST                       EMIT u8 0x44
#define WASM_I32_EQZ                         EMIT u8 0x45
#define WASM_I32_EQ                          EMIT u8 0x46
#define WASM_I32_NE                          EMIT u8 0x47
#define WASM_I32_LT_S                        EMIT u8 0x48
#define WASM_I32_LT_U                        EMIT u8 0x49
#define WASM_I32_GT_S                        EMIT u8 0x4A
#define WASM_I32_GT_U                        EMIT u8 0x4B
#define WASM_I32_LE_S                        EMIT u8 0x4C
#define WASM_I32_LE_U                        EMIT u8 0x4D
#define WASM_I32_GE_S                        EMIT u8 0x4E
#define WASM_I32_GE_U                        EMIT u8 0x4F
#define WASM_I64_EQZ                         EMIT u8 0x50
#define WASM_I64_EQ                          EMIT u8 0x51
#define WASM_I64_NE                          EMIT u8 0x52
#define WASM_I64_LT_S                        EMIT u8 0x53
#define WASM_I64_LT_U                        EMIT u8 0x54
#define WASM_I64_GT_S                        EMIT u8 0x55
#define WASM_I64_GT_U                        EMIT u8 0x56
#define WASM_I64_LE_S                        EMIT u8 0x57
#define WASM_I64_LE_U                        EMIT u8 0x58
#define WASM_I64_GE_S                        EMIT u8 0x59
#define WASM_I64_GE_U                        EMIT u8 0x5A
#define WASM_F32_EQ                          EMIT u8 0x5B
#define WASM_F32_NE                          EMIT u8 0x5C
#define WASM_F32_LT                          EMIT u8 0x5D
#define WASM_F32_GT                          EMIT u8 0x5E
#define WASM_F32_LE                          EMIT u8 0x5F
#define WASM_F32_GE                          EMIT u8 0x60
#define WASM_F64_EQ                          EMIT u8 0x61
#define WASM_F64_NE                          EMIT u8 0x62
#define WASM_F64_LT                          EMIT u8 0x63
#define WASM_F64_GT                          EMIT u8 0x64
#define WASM_F64_LE                          EMIT u8 0x65
#define WASM_F64_GE                          EMIT u8 0x66
#define WASM_I32_CLZ                         EMIT u8 0x67
#define WASM_I32_CTZ                         EMIT u8 0x68
#define WASM_I32_POPCNT                      EMIT u8 0x69
#define WASM_I32_ADD                         EMIT u8 0x6A
#define WASM_I32_SUB                         EMIT u8 0x6B
#define WASM_I32_MUL                         EMIT u8 0x6C
#define WASM_I32_DIV_S                       EMIT u8 0x6D
#define WASM_I32_DIV_U                       EMIT u8 0x6E
#define WASM_I32_REM_S                       EMIT u8 0x6F
#define WASM_I32_REM_U                       EMIT u8 0x70
#define WASM_I32_AND                         EMIT u8 0x71
#define WASM_I32_OR                          EMIT u8 0x72
#define WASM_I32_XOR                         EMIT u8 0x73
#define WASM_I32_SHL                         EMIT u8 0x74
#define WASM_I32_SHR_S                       EMIT u8 0x75
#define WASM_I32_SHR_U                       EMIT u8 0x76
#define WASM_I32_ROTL                        EMIT u8 0x77
#define WASM_I32_ROTR                        EMIT u8 0x78
#define WASM_I64_CLZ                         EMIT u8 0x79
#define WASM_I64_CTZ                         EMIT u8 0x7A
#define WASM_I64_POPCNT                      EMIT u8 0x7B
#define WASM_I64_ADD                         EMIT u8 0x7C
#define WASM_I64_SUB                         EMIT u8 0x7D
#define WASM_I64_MUL                         EMIT u8 0x7E
#define WASM_I64_DIV_S                       EMIT u8 0x7F
#define WASM_I64_DIV_U                       EMIT u8 0x80
#define WASM_I64_REM_S                       EMIT u8 0x81
#define WASM_I64_REM_U                       EMIT u8 0x82
#define WASM_I64_AND                         EMIT u8 0x83
#define WASM_I64_OR                          EMIT u8 0x84
#define WASM_I64_XOR                         EMIT u8 0x85
#define WASM_I64_SHL                         EMIT u8 0x86
#define WASM_I64_SHR_S                       EMIT u8 0x87
#define WASM_I64_SHR_U                       EMIT u8 0x88
#define WASM_I64_ROTL                        EMIT u8 0x89
#define WASM_I64_ROTR                        EMIT u8 0x8A
#define WASM_F32_ABS                         EMIT u8 0x8B
#define WASM_F32_NEG                         EMIT u8 0x8C
#define WASM_F32_CEIL                        EMIT u8 0x8D
#define WASM_F32_FLOOR                       EMIT u8 0x8E
#define WASM_F32_TRUNC                       EMIT u8 0x8F
#define WASM_F32_NEAREST                     EMIT u8 0x90
#define WASM_F32_SQRT                        EMIT u8 0x91
#define WASM_F32_ADD                         EMIT u8 0x92
#define WASM_F32_SUB                         EMIT u8 0x93
#define WASM_F32_MUL                         EMIT u8 0x94
#define WASM_F32_DIV                         EMIT u8 0x95
#define WASM_F32_MIN                         EMIT u8 0x96
#define WASM_F32_MAX                         EMIT u8 0x97
#define WASM_F32_COPYSIGN                    EMIT u8 0x98
#define WASM_F64_ABS                         EMIT u8 0x99
#define WASM_F64_NEG                         EMIT u8 0x9A
#define WASM_F64_CEIL                        EMIT u8 0x9B
#define WASM_F64_FLOOR                       EMIT u8 0x9C
#define WASM_F64_TRUNC                       EMIT u8 0x9D
#define WASM_F64_NEAREST                     EMIT u8 0x9E
#define WASM_F64_SQRT                        EMIT u8 0x9F
#define WASM_F64_ADD                         EMIT u8 0xA0
#define WASM_F64_SUB                         EMIT u8 0xA1
#define WASM_F64_MUL                         EMIT u8 0xA2
#define WASM_F64_DIV                         EMIT u8 0xA3
#define WASM_F64_MIN                         EMIT u8 0xA4
#define WASM_F64_MAX                         EMIT u8 0xA5
#define WASM_F64_COPYSIGN                    EMIT u8 0xA6
#define WASM_I32_WRAP_I64                    EMIT u8 0xA7
#define WASM_I32_TRUNC_F32_S                 EMIT u8 0xA8
#define WASM_I32_TRUNC_F32_U                 EMIT u8 0xA9
#define WASM_I32_TRUNC_F64_S                 EMIT u8 0xAA
#define WASM_I32_TRUNC_F64_U                 EMIT u8 0xAB
#define WASM_I64_EXTEND_I32_S                EMIT u8 0xAC
#define WASM_I64_EXTEND_I32_U                EMIT u8 0xAD
#define WASM_I64_TRUNC_F32_S                 EMIT u8 0xAE
#define WASM_I64_TRUNC_F32_U                 EMIT u8 0xAF
#define WASM_I64_TRUNC_F64_S                 EMIT u8 0xB0
#define WASM_I64_TRUNC_F64_U                 EMIT u8 0xB1
#define WASM_F32_CONVERT_I32_S               EMIT u8 0xB2
#define WASM_F32_CONVERT_I32_U               EMIT u8 0xB3
#define WASM_F32_CONVERT_I64_S               EMIT u8 0xB4
#define WASM_F32_CONVERT_I64_U               EMIT u8 0xB5
#define WASM_F32_DEMOTE_F64                  EMIT u8 0xB6
#define WASM_F64_CONVERT_I32_S               EMIT u8 0xB7
#define WASM_F64_CONVERT_I32_U               EMIT u8 0xB8
#define WASM_F64_CONVERT_I64_S               EMIT u8 0xB9
#define WASM_F64_CONVERT_I64_U               EMIT u8 0xBA
#define WASM_F64_PROMOTE_F32                 EMIT u8 0xBB
#define WASM_I32_REINTERPRET_F32             EMIT u8 0xBC
#define WASM_I64_REINTERPRET_F64             EMIT u8 0xBD
#define WASM_F32_REINTERPRET_I32             EMIT u8 0xBE
#define WASM_F64_REINTERPRET_I64             EMIT u8 0xBF
#define WASM_I32_EXTEND8_S                   EMIT u8 0xC0
#define WASM_I32_EXTEND16_S                  EMIT u8 0xC1
#define WASM_I64_EXTEND8_S                   EMIT u8 0xC2
#define WASM_I64_EXTEND16_S                  EMIT u8 0xC3
#define WASM_I64_EXTEND32_S                  EMIT u8 0xC4
#define WASM_REF_NULL                        EMIT u8 0xD0
#define WASM_REF_IS_NULL                     EMIT u8 0xD1
#define WASM_REF_FUNC                        EMIT u8 0xD2
#define WASM_REF_EQ                          EMIT u8 0xD3
#define WASM_REF_AS_NON_NULL                 EMIT u8 0xD4
#define WASM_BR_ON_NULL                      EMIT u8 0xD5
#define WASM_BR_ON_NON_NULL                  EMIT u8 0xD6

////////////////////////////////////////////////////////////////
// §08  JVM .class BYTECODE — All opcodes
//     Reference: JVM Specification SE 21
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  class file magic
// ────────────────────────────────────────────────────────
#define CLASS_MAGIC                          EMIT u8 0xCA 0xFE 0xBA 0xBE
#define CLASS_VER_JAVA8                      EMIT u16 0x0034
#define CLASS_VER_JAVA11                     EMIT u16 0x0037
#define CLASS_VER_JAVA17                     EMIT u16 0x003D
#define CLASS_VER_JAVA21                     EMIT u16 0x0041
#define CLASS_MINOR_0                        EMIT u16 0x0000
#define CLASS_MINOR_PREVIEW                  EMIT u16 0xFFFF

// ────────────────────────────────────────────────────────
//  Constant pool tags
// ────────────────────────────────────────────────────────
#define CP_UTF8                              1
#define CP_INTEGER                           3
#define CP_FLOAT                             4
#define CP_LONG                              5
#define CP_DOUBLE                            6
#define CP_CLASS                             7
#define CP_STRING                            8
#define CP_FIELDREF                          9
#define CP_METHODREF                         10
#define CP_INTERFACE_METHODREF               11
#define CP_NAME_AND_TYPE                     12
#define CP_METHOD_HANDLE                     15
#define CP_METHOD_TYPE                       16
#define CP_DYNAMIC                           17
#define CP_INVOKE_DYNAMIC                    18
#define CP_MODULE                            19
#define CP_PACKAGE                           20

// ────────────────────────────────────────────────────────
//  Access flags (class, field, method)
// ────────────────────────────────────────────────────────
#define ACC_PUBLIC                           0x0001
#define ACC_PRIVATE                          0x0002
#define ACC_PROTECTED                        0x0004
#define ACC_STATIC                           0x0008
#define ACC_FINAL                            0x0010
#define ACC_SUPER                            0x0020
#define ACC_SYNCHRONIZED                     0x0020
#define ACC_VOLATILE                         0x0040
#define ACC_BRIDGE                           0x0040
#define ACC_TRANSIENT                        0x0080
#define ACC_VARARGS                          0x0080
#define ACC_NATIVE                           0x0100
#define ACC_INTERFACE                        0x0200
#define ACC_ABSTRACT                         0x0400
#define ACC_STRICT                           0x0800
#define ACC_SYNTHETIC                        0x1000
#define ACC_ANNOTATION                       0x2000
#define ACC_ENUM                             0x4000
#define ACC_MODULE                           0x8000

// ────────────────────────────────────────────────────────
//  JVM opcodes (all 202)
// ────────────────────────────────────────────────────────
#define JVM_NOP                              EMIT u8 0x00
#define JVM_ACONST_NULL                      EMIT u8 0x01
#define JVM_ICONST_M1                        EMIT u8 0x02
#define JVM_ICONST_0                         EMIT u8 0x03
#define JVM_ICONST_1                         EMIT u8 0x04
#define JVM_ICONST_2                         EMIT u8 0x05
#define JVM_ICONST_3                         EMIT u8 0x06
#define JVM_ICONST_4                         EMIT u8 0x07
#define JVM_ICONST_5                         EMIT u8 0x08
#define JVM_LCONST_0                         EMIT u8 0x09
#define JVM_LCONST_1                         EMIT u8 0x0A
#define JVM_FCONST_0                         EMIT u8 0x0B
#define JVM_FCONST_1                         EMIT u8 0x0C
#define JVM_FCONST_2                         EMIT u8 0x0D
#define JVM_DCONST_0                         EMIT u8 0x0E
#define JVM_DCONST_1                         EMIT u8 0x0F
#define JVM_BIPUSH                           EMIT u8 0x10
#define JVM_SIPUSH                           EMIT u8 0x11
#define JVM_LDC                              EMIT u8 0x12
#define JVM_LDC_W                            EMIT u8 0x13
#define JVM_LDC2_W                           EMIT u8 0x14
#define JVM_ILOAD                            EMIT u8 0x15
#define JVM_LLOAD                            EMIT u8 0x16
#define JVM_FLOAD                            EMIT u8 0x17
#define JVM_DLOAD                            EMIT u8 0x18
#define JVM_ALOAD                            EMIT u8 0x19
#define JVM_ILOAD_0                          EMIT u8 0x1A
#define JVM_ILOAD_1                          EMIT u8 0x1B
#define JVM_ILOAD_2                          EMIT u8 0x1C
#define JVM_ILOAD_3                          EMIT u8 0x1D
#define JVM_LLOAD_0                          EMIT u8 0x1E
#define JVM_LLOAD_1                          EMIT u8 0x1F
#define JVM_LLOAD_2                          EMIT u8 0x20
#define JVM_LLOAD_3                          EMIT u8 0x21
#define JVM_FLOAD_0                          EMIT u8 0x22
#define JVM_FLOAD_1                          EMIT u8 0x23
#define JVM_FLOAD_2                          EMIT u8 0x24
#define JVM_FLOAD_3                          EMIT u8 0x25
#define JVM_DLOAD_0                          EMIT u8 0x26
#define JVM_DLOAD_1                          EMIT u8 0x27
#define JVM_DLOAD_2                          EMIT u8 0x28
#define JVM_DLOAD_3                          EMIT u8 0x29
#define JVM_ALOAD_0                          EMIT u8 0x2A
#define JVM_ALOAD_1                          EMIT u8 0x2B
#define JVM_ALOAD_2                          EMIT u8 0x2C
#define JVM_ALOAD_3                          EMIT u8 0x2D
#define JVM_IALOAD                           EMIT u8 0x2E
#define JVM_LALOAD                           EMIT u8 0x2F
#define JVM_FALOAD                           EMIT u8 0x30
#define JVM_DALOAD                           EMIT u8 0x31
#define JVM_AALOAD                           EMIT u8 0x32
#define JVM_BALOAD                           EMIT u8 0x33
#define JVM_CALOAD                           EMIT u8 0x34
#define JVM_SALOAD                           EMIT u8 0x35
#define JVM_ISTORE                           EMIT u8 0x36
#define JVM_LSTORE                           EMIT u8 0x37
#define JVM_FSTORE                           EMIT u8 0x38
#define JVM_DSTORE                           EMIT u8 0x39
#define JVM_ASTORE                           EMIT u8 0x3A
#define JVM_ISTORE_0                         EMIT u8 0x3B
#define JVM_ISTORE_1                         EMIT u8 0x3C
#define JVM_ISTORE_2                         EMIT u8 0x3D
#define JVM_ISTORE_3                         EMIT u8 0x3E
#define JVM_LSTORE_0                         EMIT u8 0x3F
#define JVM_LSTORE_1                         EMIT u8 0x40
#define JVM_LSTORE_2                         EMIT u8 0x41
#define JVM_LSTORE_3                         EMIT u8 0x42
#define JVM_FSTORE_0                         EMIT u8 0x43
#define JVM_FSTORE_1                         EMIT u8 0x44
#define JVM_FSTORE_2                         EMIT u8 0x45
#define JVM_FSTORE_3                         EMIT u8 0x46
#define JVM_DSTORE_0                         EMIT u8 0x47
#define JVM_DSTORE_1                         EMIT u8 0x48
#define JVM_DSTORE_2                         EMIT u8 0x49
#define JVM_DSTORE_3                         EMIT u8 0x4A
#define JVM_ASTORE_0                         EMIT u8 0x4B
#define JVM_ASTORE_1                         EMIT u8 0x4C
#define JVM_ASTORE_2                         EMIT u8 0x4D
#define JVM_ASTORE_3                         EMIT u8 0x4E
#define JVM_IASTORE                          EMIT u8 0x4F
#define JVM_LASTORE                          EMIT u8 0x50
#define JVM_FASTORE                          EMIT u8 0x51
#define JVM_DASTORE                          EMIT u8 0x52
#define JVM_AASTORE                          EMIT u8 0x53
#define JVM_BASTORE                          EMIT u8 0x54
#define JVM_CASTORE                          EMIT u8 0x55
#define JVM_SASTORE                          EMIT u8 0x56
#define JVM_POP                              EMIT u8 0x57
#define JVM_POP2                             EMIT u8 0x58
#define JVM_DUP                              EMIT u8 0x59
#define JVM_DUP_X1                           EMIT u8 0x5A
#define JVM_DUP_X2                           EMIT u8 0x5B
#define JVM_DUP2                             EMIT u8 0x5C
#define JVM_DUP2_X1                          EMIT u8 0x5D
#define JVM_DUP2_X2                          EMIT u8 0x5E
#define JVM_SWAP                             EMIT u8 0x5F
#define JVM_IADD                             EMIT u8 0x60
#define JVM_LADD                             EMIT u8 0x61
#define JVM_FADD                             EMIT u8 0x62
#define JVM_DADD                             EMIT u8 0x63
#define JVM_ISUB                             EMIT u8 0x64
#define JVM_LSUB                             EMIT u8 0x65
#define JVM_FSUB                             EMIT u8 0x66
#define JVM_DSUB                             EMIT u8 0x67
#define JVM_IMUL                             EMIT u8 0x68
#define JVM_LMUL                             EMIT u8 0x69
#define JVM_FMUL                             EMIT u8 0x6A
#define JVM_DMUL                             EMIT u8 0x6B
#define JVM_IDIV                             EMIT u8 0x6C
#define JVM_LDIV                             EMIT u8 0x6D
#define JVM_FDIV                             EMIT u8 0x6E
#define JVM_DDIV                             EMIT u8 0x6F
#define JVM_IREM                             EMIT u8 0x70
#define JVM_LREM                             EMIT u8 0x71
#define JVM_FREM                             EMIT u8 0x72
#define JVM_DREM                             EMIT u8 0x73
#define JVM_INEG                             EMIT u8 0x74
#define JVM_LNEG                             EMIT u8 0x75
#define JVM_FNEG                             EMIT u8 0x76
#define JVM_DNEG                             EMIT u8 0x77
#define JVM_ISHL                             EMIT u8 0x78
#define JVM_LSHL                             EMIT u8 0x79
#define JVM_ISHR                             EMIT u8 0x7A
#define JVM_LSHR                             EMIT u8 0x7B
#define JVM_IUSHR                            EMIT u8 0x7C
#define JVM_LUSHR                            EMIT u8 0x7D
#define JVM_IAND                             EMIT u8 0x7E
#define JVM_LAND                             EMIT u8 0x7F
#define JVM_IOR                              EMIT u8 0x80
#define JVM_LOR                              EMIT u8 0x81
#define JVM_IXOR                             EMIT u8 0x82
#define JVM_LXOR                             EMIT u8 0x83
#define JVM_IINC                             EMIT u8 0x84
#define JVM_I2L                              EMIT u8 0x85
#define JVM_I2F                              EMIT u8 0x86
#define JVM_I2D                              EMIT u8 0x87
#define JVM_L2I                              EMIT u8 0x88
#define JVM_L2F                              EMIT u8 0x89
#define JVM_L2D                              EMIT u8 0x8A
#define JVM_F2I                              EMIT u8 0x8B
#define JVM_F2L                              EMIT u8 0x8C
#define JVM_F2D                              EMIT u8 0x8D
#define JVM_D2I                              EMIT u8 0x8E
#define JVM_D2L                              EMIT u8 0x8F
#define JVM_D2F                              EMIT u8 0x90
#define JVM_I2B                              EMIT u8 0x91
#define JVM_I2C                              EMIT u8 0x92
#define JVM_I2S                              EMIT u8 0x93
#define JVM_LCMP                             EMIT u8 0x94
#define JVM_FCMPL                            EMIT u8 0x95
#define JVM_FCMPG                            EMIT u8 0x96
#define JVM_DCMPL                            EMIT u8 0x97
#define JVM_DCMPG                            EMIT u8 0x98
#define JVM_IFEQ                             EMIT u8 0x99
#define JVM_IFNE                             EMIT u8 0x9A
#define JVM_IFLT                             EMIT u8 0x9B
#define JVM_IFGE                             EMIT u8 0x9C
#define JVM_IFGT                             EMIT u8 0x9D
#define JVM_IFLE                             EMIT u8 0x9E
#define JVM_IF_ICMPEQ                        EMIT u8 0x9F
#define JVM_IF_ICMPNE                        EMIT u8 0xA0
#define JVM_IF_ICMPLT                        EMIT u8 0xA1
#define JVM_IF_ICMPGE                        EMIT u8 0xA2
#define JVM_IF_ICMPGT                        EMIT u8 0xA3
#define JVM_IF_ICMPLE                        EMIT u8 0xA4
#define JVM_IF_ACMPEQ                        EMIT u8 0xA5
#define JVM_IF_ACMPNE                        EMIT u8 0xA6
#define JVM_GOTO                             EMIT u8 0xA7
#define JVM_JSR                              EMIT u8 0xA8
#define JVM_RET                              EMIT u8 0xA9
#define JVM_TABLESWITCH                      EMIT u8 0xAA
#define JVM_LOOKUPSWITCH                     EMIT u8 0xAB
#define JVM_IRETURN                          EMIT u8 0xAC
#define JVM_LRETURN                          EMIT u8 0xAD
#define JVM_FRETURN                          EMIT u8 0xAE
#define JVM_DRETURN                          EMIT u8 0xAF
#define JVM_ARETURN                          EMIT u8 0xB0
#define JVM_RETURN                           EMIT u8 0xB1
#define JVM_GETSTATIC                        EMIT u8 0xB2
#define JVM_PUTSTATIC                        EMIT u8 0xB3
#define JVM_GETFIELD                         EMIT u8 0xB4
#define JVM_PUTFIELD                         EMIT u8 0xB5
#define JVM_INVOKEVIRTUAL                    EMIT u8 0xB6
#define JVM_INVOKESPECIAL                    EMIT u8 0xB7
#define JVM_INVOKESTATIC                     EMIT u8 0xB8
#define JVM_INVOKEINTERFACE                  EMIT u8 0xB9
#define JVM_INVOKEDYNAMIC                    EMIT u8 0xBA
#define JVM_NEW                              EMIT u8 0xBB
#define JVM_NEWARRAY                         EMIT u8 0xBC
#define JVM_ANEWARRAY                        EMIT u8 0xBD
#define JVM_ARRAYLENGTH                      EMIT u8 0xBE
#define JVM_ATHROW                           EMIT u8 0xBF
#define JVM_CHECKCAST                        EMIT u8 0xC0
#define JVM_INSTANCEOF                       EMIT u8 0xC1
#define JVM_MONITORENTER                     EMIT u8 0xC2
#define JVM_MONITOREXIT                      EMIT u8 0xC3
#define JVM_WIDE                             EMIT u8 0xC4
#define JVM_MULTIANEWARRAY                   EMIT u8 0xC5
#define JVM_IFNULL                           EMIT u8 0xC6
#define JVM_IFNONNULL                        EMIT u8 0xC7
#define JVM_GOTO_W                           EMIT u8 0xC8
#define JVM_JSR_W                            EMIT u8 0xC9

// ────────────────────────────────────────────────────────
//  newarray type codes (used with NEWARRAY opcode)
// ────────────────────────────────────────────────────────
#define JVM_ATYPE_BOOLEAN                    4
#define JVM_ATYPE_CHAR                       5
#define JVM_ATYPE_FLOAT                      6
#define JVM_ATYPE_DOUBLE                     7
#define JVM_ATYPE_BYTE                       8
#define JVM_ATYPE_SHORT                      9
#define JVM_ATYPE_INT                        10
#define JVM_ATYPE_LONG                       11

////////////////////////////////////////////////////////////////
// §09  x86-64 INSTRUCTIONS — COMPLETE COVERAGE
//
//  Two families of macros:
//    PREFIX  macros — emit opcode bytes only
//                    ⚠ MUST be followed by the operand emit
//    COMPLETE macros — self-contained, correct instruction
//
//  Register encoding:
//    RAX=0  RCX=1  RDX=2  RBX=3  RSP=4  RBP=5  RSI=6  RDI=7
//    R8=8   R9=9   R10=10 R11=11 R12=12 R13=13 R14=14 R15=15
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  Simple / single-byte instructions
// ────────────────────────────────────────────────────────
#define X64_NOP                              EMIT u8 0x90   // no operation
#define X64_RET                              EMIT u8 0xC3   // near return
#define X64_RET_FAR                          EMIT u8 0xCB   // far return
#define X64_INT3                             EMIT u8 0xCC   // breakpoint
#define X64_INT1                             EMIT u8 0xF1   // ICEBP
#define X64_HLT                              EMIT u8 0xF4   // halt — CPL 0 only
#define X64_CLI                              EMIT u8 0xFA   // clear interrupt flag
#define X64_STI                              EMIT u8 0xFB   // set interrupt flag
#define X64_CLD                              EMIT u8 0xFC   // clear direction flag
#define X64_STD                              EMIT u8 0xFD   // set direction flag
#define X64_CLC                              EMIT u8 0xF8   // clear carry
#define X64_STC                              EMIT u8 0xF9   // set carry
#define X64_CMC                              EMIT u8 0xF5   // complement carry
#define X64_LAHF                             EMIT u8 0x9F   // load AH ← flags
#define X64_SAHF                             EMIT u8 0x9E   // store AH → flags
#define X64_PUSHFQ                           EMIT u8 0x9C   // push RFLAGS
#define X64_POPFQ                            EMIT u8 0x9D   // pop RFLAGS
#define X64_LEAVE                            EMIT u8 0xC9   // mov rsp,rbp; pop rbp
#define X64_CLTS                             EMIT u8 0x0F 0x06   // clear TS flag in CR0
#define X64_INVD                             EMIT u8 0x0F 0x08   // invalidate caches
#define X64_WBINVD                           EMIT u8 0x0F 0x09   // writeback+invalidate
#define X64_UD2                              EMIT u8 0x0F 0x0B   // guaranteed illegal instruction
#define X64_CDQE                             EMIT u8 0x48 0x98   // sign-extend EAX→RAX
#define X64_CQO                              EMIT u8 0x48 0x99   // sign-extend RAX into RDX:RAX
#define X64_IRETQ                            EMIT u8 0x48 0xCF   // interrupt return (64-bit)
#define X64_SYSCALL                          EMIT u8 0x0F 0x05   // fast user→kernel call
#define X64_SYSRET                           EMIT u8 0x0F 0x07   // fast kernel→user return
#define X64_SYSENTER                         EMIT u8 0x0F 0x34   // fast system call (32-bit style)
#define X64_SYSEXIT                          EMIT u8 0x0F 0x35
#define X64_CPUID                            EMIT u8 0x0F 0xA2   // CPU identification
#define X64_RDTSC                            EMIT u8 0x0F 0x31   // read time-stamp counter → EDX:EAX
#define X64_RDTSCP                           EMIT u8 0x0F 0x01 0xF9   // read TSC + IA32_TSC_AUX → ECX
#define X64_RDMSR                            EMIT u8 0x0F 0x32   // read MSR(ECX) → EDX:EAX
#define X64_WRMSR                            EMIT u8 0x0F 0x30   // write EDX:EAX → MSR(ECX)
#define X64_RDPMC                            EMIT u8 0x0F 0x33   // read performance counter
#define X64_PAUSE                            EMIT u8 0xF3 0x90   // spin-loop hint
#define X64_LOCK                             EMIT u8 0xF0   // atomic prefix
#define X64_REP                              EMIT u8 0xF3   // repeat string prefix
#define X64_REPNE                            EMIT u8 0xF2   // repeat-not-equal prefix
#define X64_MFENCE                           EMIT u8 0x0F 0xAE 0xF0   // full memory fence
#define X64_SFENCE                           EMIT u8 0x0F 0xAE 0xF8   // store fence
#define X64_LFENCE                           EMIT u8 0x0F 0xAE 0xE8   // load fence

// ────────────────────────────────────────────────────────
//  String / memory operations
// ────────────────────────────────────────────────────────
#define X64_MOVSB                            EMIT u8 0xA4   // mov byte [rdi]←[rsi]; rsi++; rdi++
#define X64_MOVSW                            EMIT u8 0x66 0xA5   // mov word
#define X64_MOVSD                            EMIT u8 0xA5   // mov dword
#define X64_MOVSQ                            EMIT u8 0x48 0xA5   // mov qword (REX.W)
#define X64_STOSB                            EMIT u8 0xAA   // store AL→[rdi]; rdi++
#define X64_STOSW                            EMIT u8 0x66 0xAB   // store AX
#define X64_STOSD                            EMIT u8 0xAB   // store EAX
#define X64_STOSQ                            EMIT u8 0x48 0xAB   // store RAX (REX.W)
#define X64_LODSB                            EMIT u8 0xAC   // load [rsi]→AL; rsi++
#define X64_LODSQ                            EMIT u8 0x48 0xAD   // load [rsi]→RAX
#define X64_SCASB                            EMIT u8 0xAE   // compare AL with [rdi]; rdi++
#define X64_SCASQ                            EMIT u8 0x48 0xAF   // compare RAX with [rdi]
#define X64_CMPSB                            EMIT u8 0xA6   // compare [rsi] with [rdi]
#define X64_CMPSQ                            EMIT u8 0x48 0xA7   // compare qword
#define X64_REP_MOVSB                        EMIT u8 0xF3 0xA4   // memcpy (byte)
#define X64_REP_MOVSQ                        EMIT u8 0xF3 0x48 0xA5   // memcpy (qword, RCX times)
#define X64_REP_STOSB                        EMIT u8 0xF3 0xAA   // memset (byte)
#define X64_REP_STOSQ                        EMIT u8 0xF3 0x48 0xAB   // memset (qword)
#define X64_REPNE_SCASB                      EMIT u8 0xF2 0xAE   // strlen pattern: scan for 0 in [rdi]
#define X64_REPNE_SCASQ                      EMIT u8 0xF2 0x48 0xAF   // scan qword

// ────────────────────────────────────────────────────────
//  PUSH / POP — all GPRs
// ────────────────────────────────────────────────────────
#define X64_PUSH_RAX                         EMIT u8 0x50
#define X64_PUSH_RCX                         EMIT u8 0x51
#define X64_PUSH_RDX                         EMIT u8 0x52
#define X64_PUSH_RBX                         EMIT u8 0x53
#define X64_PUSH_RSP                         EMIT u8 0x54
#define X64_PUSH_RBP                         EMIT u8 0x55
#define X64_PUSH_RSI                         EMIT u8 0x56
#define X64_PUSH_RDI                         EMIT u8 0x57
#define X64_PUSH_R8                          EMIT u8 0x41 0x50
#define X64_PUSH_R9                          EMIT u8 0x41 0x51
#define X64_PUSH_R10                         EMIT u8 0x41 0x52
#define X64_PUSH_R11                         EMIT u8 0x41 0x53
#define X64_PUSH_R12                         EMIT u8 0x41 0x54
#define X64_PUSH_R13                         EMIT u8 0x41 0x55
#define X64_PUSH_R14                         EMIT u8 0x41 0x56
#define X64_PUSH_R15                         EMIT u8 0x41 0x57
#define X64_POP_RAX                          EMIT u8 0x58
#define X64_POP_RCX                          EMIT u8 0x59
#define X64_POP_RDX                          EMIT u8 0x5A
#define X64_POP_RBX                          EMIT u8 0x5B
#define X64_POP_RSP                          EMIT u8 0x5C
#define X64_POP_RBP                          EMIT u8 0x5D
#define X64_POP_RSI                          EMIT u8 0x5E
#define X64_POP_RDI                          EMIT u8 0x5F
#define X64_POP_R8                           EMIT u8 0x41 0x58
#define X64_POP_R9                           EMIT u8 0x41 0x59
#define X64_POP_R10                          EMIT u8 0x41 0x5A
#define X64_POP_R11                          EMIT u8 0x41 0x5B
#define X64_POP_R12                          EMIT u8 0x41 0x5C
#define X64_POP_R13                          EMIT u8 0x41 0x5D
#define X64_POP_R14                          EMIT u8 0x41 0x5E
#define X64_POP_R15                          EMIT u8 0x41 0x5F

// ────────────────────────────────────────────────────────
//  MOV reg, imm64  ⚠ follow with EMIT u64 <val>  (10 bytes total)
// ────────────────────────────────────────────────────────
#define X64_MOV_RAX                          EMIT u8 0x48 0xB8
#define X64_MOV_RCX                          EMIT u8 0x48 0xB9
#define X64_MOV_RDX                          EMIT u8 0x48 0xBA
#define X64_MOV_RBX                          EMIT u8 0x48 0xBB
#define X64_MOV_RSP                          EMIT u8 0x48 0xBC
#define X64_MOV_RBP                          EMIT u8 0x48 0xBD
#define X64_MOV_RSI                          EMIT u8 0x48 0xBE
#define X64_MOV_RDI                          EMIT u8 0x48 0xBF
#define X64_MOV_R8                           EMIT u8 0x49 0xB8
#define X64_MOV_R9                           EMIT u8 0x49 0xB9
#define X64_MOV_R10                          EMIT u8 0x49 0xBA
#define X64_MOV_R11                          EMIT u8 0x49 0xBB
#define X64_MOV_R12                          EMIT u8 0x49 0xBC
#define X64_MOV_R13                          EMIT u8 0x49 0xBD
#define X64_MOV_R14                          EMIT u8 0x49 0xBE
#define X64_MOV_R15                          EMIT u8 0x49 0xBF

// ────────────────────────────────────────────────────────
//  MOV reg, imm32 sign-extended  ⚠ follow with EMIT u32 <val>  (7 bytes total)
// ────────────────────────────────────────────────────────
#define X64_MOV_RAX32                        EMIT u8 0x48 0xC7 0xC0
#define X64_MOV_RCX32                        EMIT u8 0x48 0xC7 0xC1
#define X64_MOV_RDX32                        EMIT u8 0x48 0xC7 0xC2
#define X64_MOV_RBX32                        EMIT u8 0x48 0xC7 0xC3
#define X64_MOV_RSP32                        EMIT u8 0x48 0xC7 0xC4
#define X64_MOV_RBP32                        EMIT u8 0x48 0xC7 0xC5
#define X64_MOV_RSI32                        EMIT u8 0x48 0xC7 0xC6
#define X64_MOV_RDI32                        EMIT u8 0x48 0xC7 0xC7

// ────────────────────────────────────────────────────────
//  Complete MOV reg, small_constant  (7 bytes, self-contained)
// ────────────────────────────────────────────────────────
#define X64_RAX_0                            EMIT u8 0x48 0xC7 0xC0 0x00 0x00 0x00 0x00
#define X64_RAX_1                            EMIT u8 0x48 0xC7 0xC0 0x01 0x00 0x00 0x00
#define X64_RAX_2                            EMIT u8 0x48 0xC7 0xC0 0x02 0x00 0x00 0x00
#define X64_RAX_3                            EMIT u8 0x48 0xC7 0xC0 0x03 0x00 0x00 0x00
#define X64_RAX_4                            EMIT u8 0x48 0xC7 0xC0 0x04 0x00 0x00 0x00
#define X64_RAX_5                            EMIT u8 0x48 0xC7 0xC0 0x05 0x00 0x00 0x00
#define X64_RAX_6                            EMIT u8 0x48 0xC7 0xC0 0x06 0x00 0x00 0x00
#define X64_RAX_7                            EMIT u8 0x48 0xC7 0xC0 0x07 0x00 0x00 0x00
#define X64_RAX_8                            EMIT u8 0x48 0xC7 0xC0 0x08 0x00 0x00 0x00
#define X64_RAX_9                            EMIT u8 0x48 0xC7 0xC0 0x09 0x00 0x00 0x00
#define X64_RAX_10                           EMIT u8 0x48 0xC7 0xC0 0x0A 0x00 0x00 0x00
#define X64_RAX_11                           EMIT u8 0x48 0xC7 0xC0 0x0B 0x00 0x00 0x00
#define X64_RAX_12                           EMIT u8 0x48 0xC7 0xC0 0x0C 0x00 0x00 0x00
#define X64_RAX_13                           EMIT u8 0x48 0xC7 0xC0 0x0D 0x00 0x00 0x00
#define X64_RAX_14                           EMIT u8 0x48 0xC7 0xC0 0x0E 0x00 0x00 0x00
#define X64_RAX_15                           EMIT u8 0x48 0xC7 0xC0 0x0F 0x00 0x00 0x00
#define X64_RAX_17                           EMIT u8 0x48 0xC7 0xC0 0x11 0x00 0x00 0x00
#define X64_RAX_18                           EMIT u8 0x48 0xC7 0xC0 0x12 0x00 0x00 0x00
#define X64_RAX_19                           EMIT u8 0x48 0xC7 0xC0 0x13 0x00 0x00 0x00
#define X64_RAX_20                           EMIT u8 0x48 0xC7 0xC0 0x14 0x00 0x00 0x00
#define X64_RAX_21                           EMIT u8 0x48 0xC7 0xC0 0x15 0x00 0x00 0x00
#define X64_RAX_22                           EMIT u8 0x48 0xC7 0xC0 0x16 0x00 0x00 0x00
#define X64_RAX_23                           EMIT u8 0x48 0xC7 0xC0 0x17 0x00 0x00 0x00
#define X64_RAX_24                           EMIT u8 0x48 0xC7 0xC0 0x18 0x00 0x00 0x00
#define X64_RAX_25                           EMIT u8 0x48 0xC7 0xC0 0x19 0x00 0x00 0x00
#define X64_RAX_26                           EMIT u8 0x48 0xC7 0xC0 0x1A 0x00 0x00 0x00
#define X64_RAX_27                           EMIT u8 0x48 0xC7 0xC0 0x1B 0x00 0x00 0x00
#define X64_RAX_28                           EMIT u8 0x48 0xC7 0xC0 0x1C 0x00 0x00 0x00
#define X64_RAX_29                           EMIT u8 0x48 0xC7 0xC0 0x1D 0x00 0x00 0x00
#define X64_RAX_30                           EMIT u8 0x48 0xC7 0xC0 0x1E 0x00 0x00 0x00
#define X64_RAX_31                           EMIT u8 0x48 0xC7 0xC0 0x1F 0x00 0x00 0x00
#define X64_RAX_32                           EMIT u8 0x48 0xC7 0xC0 0x20 0x00 0x00 0x00
#define X64_RAX_39                           EMIT u8 0x48 0xC7 0xC0 0x27 0x00 0x00 0x00
#define X64_RAX_40                           EMIT u8 0x48 0xC7 0xC0 0x28 0x00 0x00 0x00
#define X64_RAX_41                           EMIT u8 0x48 0xC7 0xC0 0x29 0x00 0x00 0x00
#define X64_RAX_42                           EMIT u8 0x48 0xC7 0xC0 0x2A 0x00 0x00 0x00
#define X64_RAX_43                           EMIT u8 0x48 0xC7 0xC0 0x2B 0x00 0x00 0x00
#define X64_RAX_44                           EMIT u8 0x48 0xC7 0xC0 0x2C 0x00 0x00 0x00
#define X64_RAX_56                           EMIT u8 0x48 0xC7 0xC0 0x38 0x00 0x00 0x00
#define X64_RAX_57                           EMIT u8 0x48 0xC7 0xC0 0x39 0x00 0x00 0x00
#define X64_RAX_58                           EMIT u8 0x48 0xC7 0xC0 0x3A 0x00 0x00 0x00
#define X64_RAX_59                           EMIT u8 0x48 0xC7 0xC0 0x3B 0x00 0x00 0x00
#define X64_RAX_60                           EMIT u8 0x48 0xC7 0xC0 0x3C 0x00 0x00 0x00
#define X64_RAX_61                           EMIT u8 0x48 0xC7 0xC0 0x3D 0x00 0x00 0x00
#define X64_RAX_62                           EMIT u8 0x48 0xC7 0xC0 0x3E 0x00 0x00 0x00
#define X64_RAX_100                          EMIT u8 0x48 0xC7 0xC0 0x64 0x00 0x00 0x00
#define X64_RAX_101                          EMIT u8 0x48 0xC7 0xC0 0x65 0x00 0x00 0x00
#define X64_RAX_200                          EMIT u8 0x48 0xC7 0xC0 0xC8 0x00 0x00 0x00
#define X64_RAX_201                          EMIT u8 0x48 0xC7 0xC0 0xC9 0x00 0x00 0x00
#define X64_RAX_202                          EMIT u8 0x48 0xC7 0xC0 0xCA 0x00 0x00 0x00
#define X64_RAX_231                          EMIT u8 0x48 0xC7 0xC0 0xE7 0x00 0x00 0x00
#define X64_RAX_232                          EMIT u8 0x48 0xC7 0xC0 0xE8 0x00 0x00 0x00
#define X64_RAX_233                          EMIT u8 0x48 0xC7 0xC0 0xE9 0x00 0x00 0x00
#define X64_RAX_234                          EMIT u8 0x48 0xC7 0xC0 0xEA 0x00 0x00 0x00
#define X64_RAX_235                          EMIT u8 0x48 0xC7 0xC0 0xEB 0x00 0x00 0x00
#define X64_RAX_257                          EMIT u8 0x48 0xC7 0xC0 0x01 0x01 0x00 0x00
#define X64_RAX_258                          EMIT u8 0x48 0xC7 0xC0 0x02 0x01 0x00 0x00
#define X64_RAX_259                          EMIT u8 0x48 0xC7 0xC0 0x03 0x01 0x00 0x00
#define X64_RAX_260                          EMIT u8 0x48 0xC7 0xC0 0x04 0x01 0x00 0x00
#define X64_RAX_262                          EMIT u8 0x48 0xC7 0xC0 0x06 0x01 0x00 0x00
#define X64_RAX_266                          EMIT u8 0x48 0xC7 0xC0 0x0A 0x01 0x00 0x00
#define X64_RAX_273                          EMIT u8 0x48 0xC7 0xC0 0x11 0x01 0x00 0x00
#define X64_RAX_274                          EMIT u8 0x48 0xC7 0xC0 0x12 0x01 0x00 0x00
#define X64_RAX_275                          EMIT u8 0x48 0xC7 0xC0 0x13 0x01 0x00 0x00
#define X64_RAX_281                          EMIT u8 0x48 0xC7 0xC0 0x19 0x01 0x00 0x00
#define X64_RAX_290                          EMIT u8 0x48 0xC7 0xC0 0x22 0x01 0x00 0x00
#define X64_RAX_302                          EMIT u8 0x48 0xC7 0xC0 0x2E 0x01 0x00 0x00
#define X64_RAX_303                          EMIT u8 0x48 0xC7 0xC0 0x2F 0x01 0x00 0x00
#define X64_RAX_304                          EMIT u8 0x48 0xC7 0xC0 0x30 0x01 0x00 0x00
#define X64_RAX_305                          EMIT u8 0x48 0xC7 0xC0 0x31 0x01 0x00 0x00
#define X64_RAX_306                          EMIT u8 0x48 0xC7 0xC0 0x32 0x01 0x00 0x00
#define X64_RAX_307                          EMIT u8 0x48 0xC7 0xC0 0x33 0x01 0x00 0x00
#define X64_RAX_308                          EMIT u8 0x48 0xC7 0xC0 0x34 0x01 0x00 0x00
#define X64_RAX_309                          EMIT u8 0x48 0xC7 0xC0 0x35 0x01 0x00 0x00
#define X64_RAX_310                          EMIT u8 0x48 0xC7 0xC0 0x36 0x01 0x00 0x00
#define X64_RAX_311                          EMIT u8 0x48 0xC7 0xC0 0x37 0x01 0x00 0x00
#define X64_RAX_312                          EMIT u8 0x48 0xC7 0xC0 0x38 0x01 0x00 0x00
#define X64_RAX_313                          EMIT u8 0x48 0xC7 0xC0 0x39 0x01 0x00 0x00
#define X64_RAX_314                          EMIT u8 0x48 0xC7 0xC0 0x3A 0x01 0x00 0x00
#define X64_RAX_315                          EMIT u8 0x48 0xC7 0xC0 0x3B 0x01 0x00 0x00
#define X64_RAX_316                          EMIT u8 0x48 0xC7 0xC0 0x3C 0x01 0x00 0x00
#define X64_RAX_317                          EMIT u8 0x48 0xC7 0xC0 0x3D 0x01 0x00 0x00
#define X64_RAX_318                          EMIT u8 0x48 0xC7 0xC0 0x3E 0x01 0x00 0x00
#define X64_RAX_319                          EMIT u8 0x48 0xC7 0xC0 0x3F 0x01 0x00 0x00
#define X64_RAX_320                          EMIT u8 0x48 0xC7 0xC0 0x40 0x01 0x00 0x00
#define X64_RAX_321                          EMIT u8 0x48 0xC7 0xC0 0x41 0x01 0x00 0x00
#define X64_RAX_322                          EMIT u8 0x48 0xC7 0xC0 0x42 0x01 0x00 0x00
#define X64_RAX_323                          EMIT u8 0x48 0xC7 0xC0 0x43 0x01 0x00 0x00
#define X64_RAX_324                          EMIT u8 0x48 0xC7 0xC0 0x44 0x01 0x00 0x00
#define X64_RAX_325                          EMIT u8 0x48 0xC7 0xC0 0x45 0x01 0x00 0x00
#define X64_RAX_326                          EMIT u8 0x48 0xC7 0xC0 0x46 0x01 0x00 0x00
#define X64_RAX_327                          EMIT u8 0x48 0xC7 0xC0 0x47 0x01 0x00 0x00
#define X64_RAX_328                          EMIT u8 0x48 0xC7 0xC0 0x48 0x01 0x00 0x00
#define X64_RAX_329                          EMIT u8 0x48 0xC7 0xC0 0x49 0x01 0x00 0x00
#define X64_RAX_330                          EMIT u8 0x48 0xC7 0xC0 0x4A 0x01 0x00 0x00
#define X64_RAX_331                          EMIT u8 0x48 0xC7 0xC0 0x4B 0x01 0x00 0x00
#define X64_RAX_332                          EMIT u8 0x48 0xC7 0xC0 0x4C 0x01 0x00 0x00
#define X64_RAX_333                          EMIT u8 0x48 0xC7 0xC0 0x4D 0x01 0x00 0x00
#define X64_RAX_334                          EMIT u8 0x48 0xC7 0xC0 0x4E 0x01 0x00 0x00
#define X64_RAX_335                          EMIT u8 0x48 0xC7 0xC0 0x4F 0x01 0x00 0x00
#define X64_RAX_401                          EMIT u8 0x48 0xC7 0xC0 0x91 0x01 0x00 0x00
#define X64_RAX_402                          EMIT u8 0x48 0xC7 0xC0 0x92 0x01 0x00 0x00
#define X64_RAX_403                          EMIT u8 0x48 0xC7 0xC0 0x93 0x01 0x00 0x00
#define X64_RAX_404                          EMIT u8 0x48 0xC7 0xC0 0x94 0x01 0x00 0x00
#define X64_RAX_405                          EMIT u8 0x48 0xC7 0xC0 0x95 0x01 0x00 0x00
#define X64_RAX_406                          EMIT u8 0x48 0xC7 0xC0 0x96 0x01 0x00 0x00
#define X64_RAX_407                          EMIT u8 0x48 0xC7 0xC0 0x97 0x01 0x00 0x00
#define X64_RAX_408                          EMIT u8 0x48 0xC7 0xC0 0x98 0x01 0x00 0x00
#define X64_RAX_409                          EMIT u8 0x48 0xC7 0xC0 0x99 0x01 0x00 0x00
#define X64_RAX_410                          EMIT u8 0x48 0xC7 0xC0 0x9A 0x01 0x00 0x00

#define X64_RDI_0                            EMIT u8 0x48 0xC7 0xC7 0x00 0x00 0x00 0x00
#define X64_RDI_1                            EMIT u8 0x48 0xC7 0xC7 0x01 0x00 0x00 0x00
#define X64_RDI_2                            EMIT u8 0x48 0xC7 0xC7 0x02 0x00 0x00 0x00
#define X64_RDI_3                            EMIT u8 0x48 0xC7 0xC7 0x03 0x00 0x00 0x00
#define X64_RDI_4                            EMIT u8 0x48 0xC7 0xC7 0x04 0x00 0x00 0x00
#define X64_RDI_5                            EMIT u8 0x48 0xC7 0xC7 0x05 0x00 0x00 0x00
#define X64_RDI_6                            EMIT u8 0x48 0xC7 0xC7 0x06 0x00 0x00 0x00
#define X64_RDI_7                            EMIT u8 0x48 0xC7 0xC7 0x07 0x00 0x00 0x00
#define X64_RDI_10                           EMIT u8 0x48 0xC7 0xC7 0x0A 0x00 0x00 0x00
#define X64_RDI_16                           EMIT u8 0x48 0xC7 0xC7 0x10 0x00 0x00 0x00
#define X64_RDI_17                           EMIT u8 0x48 0xC7 0xC7 0x11 0x00 0x00 0x00
#define X64_RDI_100                          EMIT u8 0x48 0xC7 0xC7 0x64 0x00 0x00 0x00
#define X64_RDI_200                          EMIT u8 0x48 0xC7 0xC7 0xC8 0x00 0x00 0x00

#define X64_RSI_0                            EMIT u8 0x48 0xC7 0xC6 0x00 0x00 0x00 0x00
#define X64_RSI_1                            EMIT u8 0x48 0xC7 0xC6 0x01 0x00 0x00 0x00
#define X64_RSI_2                            EMIT u8 0x48 0xC7 0xC6 0x02 0x00 0x00 0x00
#define X64_RSI_3                            EMIT u8 0x48 0xC7 0xC6 0x03 0x00 0x00 0x00
#define X64_RSI_4                            EMIT u8 0x48 0xC7 0xC6 0x04 0x00 0x00 0x00
#define X64_RSI_5                            EMIT u8 0x48 0xC7 0xC6 0x05 0x00 0x00 0x00
#define X64_RSI_6                            EMIT u8 0x48 0xC7 0xC6 0x06 0x00 0x00 0x00
#define X64_RSI_7                            EMIT u8 0x48 0xC7 0xC6 0x07 0x00 0x00 0x00

#define X64_RDX_0                            EMIT u8 0x48 0xC7 0xC2 0x00 0x00 0x00 0x00
#define X64_RDX_1                            EMIT u8 0x48 0xC7 0xC2 0x01 0x00 0x00 0x00
#define X64_RDX_2                            EMIT u8 0x48 0xC7 0xC2 0x02 0x00 0x00 0x00
#define X64_RDX_3                            EMIT u8 0x48 0xC7 0xC2 0x03 0x00 0x00 0x00
#define X64_RDX_4                            EMIT u8 0x48 0xC7 0xC2 0x04 0x00 0x00 0x00
#define X64_RDX_5                            EMIT u8 0x48 0xC7 0xC2 0x05 0x00 0x00 0x00
#define X64_RDX_6                            EMIT u8 0x48 0xC7 0xC2 0x06 0x00 0x00 0x00
#define X64_RDX_7                            EMIT u8 0x48 0xC7 0xC2 0x07 0x00 0x00 0x00
#define X64_RDX_16                           EMIT u8 0x48 0xC7 0xC2 0x10 0x00 0x00 0x00
#define X64_RDX_32                           EMIT u8 0x48 0xC7 0xC2 0x20 0x00 0x00 0x00
#define X64_RDX_64                           EMIT u8 0x48 0xC7 0xC2 0x40 0x00 0x00 0x00
#define X64_RDX_128                          EMIT u8 0x48 0xC7 0xC2 0x80 0x00 0x00 0x00
#define X64_RDX_256                          EMIT u8 0x48 0xC7 0xC2 0x00 0x01 0x00 0x00
#define X64_RDX_512                          EMIT u8 0x48 0xC7 0xC2 0x00 0x02 0x00 0x00
#define X64_RDX_1024                         EMIT u8 0x48 0xC7 0xC2 0x00 0x04 0x00 0x00
#define X64_RDX_4096                         EMIT u8 0x48 0xC7 0xC2 0x00 0x10 0x00 0x00

#define X64_RCX_0                            EMIT u8 0x48 0xC7 0xC1 0x00 0x00 0x00 0x00
#define X64_RCX_1                            EMIT u8 0x48 0xC7 0xC1 0x01 0x00 0x00 0x00
#define X64_RCX_2                            EMIT u8 0x48 0xC7 0xC1 0x02 0x00 0x00 0x00
#define X64_RCX_3                            EMIT u8 0x48 0xC7 0xC1 0x03 0x00 0x00 0x00
#define X64_RCX_4                            EMIT u8 0x48 0xC7 0xC1 0x04 0x00 0x00 0x00
#define X64_RCX_5                            EMIT u8 0x48 0xC7 0xC1 0x05 0x00 0x00 0x00
#define X64_RCX_6                            EMIT u8 0x48 0xC7 0xC1 0x06 0x00 0x00 0x00
#define X64_RCX_7                            EMIT u8 0x48 0xC7 0xC1 0x07 0x00 0x00 0x00

// ────────────────────────────────────────────────────────
//  XOR to zero register  (use 32-bit form = 2 bytes, implicitly zeroes 64-bit)
// ────────────────────────────────────────────────────────
#define X64_XOR_EAX                          EMIT u8 0x31 0xC0   // zeroes RAX
#define X64_XOR_ECX                          EMIT u8 0x31 0xC9   // zeroes RCX
#define X64_XOR_EDX                          EMIT u8 0x31 0xD2   // zeroes RDX
#define X64_XOR_EBX                          EMIT u8 0x31 0xDB   // zeroes RBX
#define X64_XOR_ESI                          EMIT u8 0x31 0xF6   // zeroes RSI
#define X64_XOR_EDI                          EMIT u8 0x31 0xFF   // zeroes RDI
#define X64_XOR_RAX                          EMIT u8 0x48 0x31 0xC0   // REX.W form (3 bytes)
#define X64_XOR_RCX                          EMIT u8 0x48 0x31 0xC9   // REX.W form (3 bytes)
#define X64_XOR_RDX                          EMIT u8 0x48 0x31 0xD2   // REX.W form (3 bytes)
#define X64_XOR_RBX                          EMIT u8 0x48 0x31 0xDB   // REX.W form (3 bytes)
#define X64_XOR_RSI                          EMIT u8 0x48 0x31 0xF6   // REX.W form (3 bytes)
#define X64_XOR_RDI                          EMIT u8 0x48 0x31 0xFF   // REX.W form (3 bytes)
#define X64_XOR_R8                           EMIT u8 0x4D 0x31 0xC0   // REX.W form (3 bytes)
#define X64_XOR_R9                           EMIT u8 0x4D 0x31 0xC9   // REX.W form (3 bytes)
#define X64_XOR_R10                          EMIT u8 0x4D 0x31 0xD2   // REX.W form (3 bytes)
#define X64_XOR_R11                          EMIT u8 0x4D 0x31 0xDB   // REX.W form (3 bytes)
#define X64_XOR_R12                          EMIT u8 0x4D 0x31 0xE4   // REX.W form (3 bytes)
#define X64_XOR_R13                          EMIT u8 0x4D 0x31 0xED   // REX.W form (3 bytes)
#define X64_XOR_R14                          EMIT u8 0x4D 0x31 0xF6   // REX.W form (3 bytes)
#define X64_XOR_R15                          EMIT u8 0x4D 0x31 0xFF   // REX.W form (3 bytes)

// ────────────────────────────────────────────────────────
//  Register-to-register MOV  (REX.W 89 /r, 3 bytes)
// ────────────────────────────────────────────────────────
#define X64_MOV_RAX_RCX                      EMIT u8 0x48 0x89 0xC8
#define X64_MOV_RAX_RDX                      EMIT u8 0x48 0x89 0xD0
#define X64_MOV_RAX_RBX                      EMIT u8 0x48 0x89 0xD8
#define X64_MOV_RAX_RSI                      EMIT u8 0x48 0x89 0xF0
#define X64_MOV_RAX_RDI                      EMIT u8 0x48 0x89 0xF8
#define X64_MOV_RCX_RAX                      EMIT u8 0x48 0x89 0xC1
#define X64_MOV_RCX_RDX                      EMIT u8 0x48 0x89 0xD1
#define X64_MOV_RCX_RBX                      EMIT u8 0x48 0x89 0xD9
#define X64_MOV_RDX_RAX                      EMIT u8 0x48 0x89 0xC2
#define X64_MOV_RDX_RCX                      EMIT u8 0x48 0x89 0xCA
#define X64_MOV_RDX_RBX                      EMIT u8 0x48 0x89 0xDA
#define X64_MOV_RBX_RAX                      EMIT u8 0x48 0x89 0xC3
#define X64_MOV_RBX_RCX                      EMIT u8 0x48 0x89 0xCB
#define X64_MOV_RBX_RDX                      EMIT u8 0x48 0x89 0xD3
#define X64_MOV_RSI_RAX                      EMIT u8 0x48 0x89 0xC6
#define X64_MOV_RSI_RCX                      EMIT u8 0x48 0x89 0xCE
#define X64_MOV_RSI_RDX                      EMIT u8 0x48 0x89 0xD6
#define X64_MOV_RDI_RAX                      EMIT u8 0x48 0x89 0xC7
#define X64_MOV_RDI_RCX                      EMIT u8 0x48 0x89 0xCF
#define X64_MOV_RDI_RDX                      EMIT u8 0x48 0x89 0xD7
#define X64_MOV_RDI_RSI                      EMIT u8 0x48 0x89 0xF7
#define X64_MOV_RSI_RDI                      EMIT u8 0x48 0x89 0xFE
#define X64_MOV_RBP_RSP                      EMIT u8 0x48 0x89 0xE5
#define X64_MOV_RSP_RBP                      EMIT u8 0x48 0x89 0xEC
#define X64_MOV_RDX_RCX                      EMIT u8 0x48 0x89 0xD1
#define X64_MOV_RCX_RDX                      EMIT u8 0x48 0x89 0xCA

// ────────────────────────────────────────────────────────
//  Stack frame helpers
// ────────────────────────────────────────────────────────
#define X64_FRAME_ENTER                      EMIT u8 0x55 0x48 0x89 0xE5   // push rbp; mov rbp, rsp
#define X64_FRAME_LEAVE                      EMIT u8 0x5D 0xC3   // pop rbp; ret
#define X64_LEAVE_ONLY                       EMIT u8 0xC9   // leave  (mov rsp,rbp; pop rbp)
#define X64_SUB_RSP_IMM8                     EMIT u8 0x48 0x83 0xEC   // ⚠ follow with EMIT u8 <n>
#define X64_ADD_RSP_IMM8                     EMIT u8 0x48 0x83 0xC4   // ⚠ follow with EMIT u8 <n>
#define X64_SUB_RSP_IMM32                    EMIT u8 0x48 0x81 0xEC   // ⚠ follow with EMIT u32 <n>
#define X64_ADD_RSP_IMM32                    EMIT u8 0x48 0x81 0xC4   // ⚠ follow with EMIT u32 <n>
#define X64_SHADOW_32                        EMIT u8 0x48 0x83 0xEC 0x20   // sub rsp,32  (Win64 shadow space)
#define X64_SHADOW_32_RET                    EMIT u8 0x48 0x83 0xC4 0x20   // add rsp,32
#define X64_ALIGN16                          EMIT u8 0x48 0x83 0xE4 0xF0   // and rsp,-16  (16-byte align)

// ────────────────────────────────────────────────────────
//  Arithmetic — reg/reg (3 bytes each)
// ────────────────────────────────────────────────────────
#define X64_ADD_RAX_RCX                      EMIT u8 0x48 0x01 0xC8
#define X64_ADD_RAX_RDX                      EMIT u8 0x48 0x01 0xD0
#define X64_ADD_RAX_RBX                      EMIT u8 0x48 0x01 0xD8
#define X64_ADD_RAX_RSI                      EMIT u8 0x48 0x01 0xF0
#define X64_ADD_RAX_RDI                      EMIT u8 0x48 0x01 0xF8
#define X64_ADD_RCX_RDX                      EMIT u8 0x48 0x01 0xD1
#define X64_ADD_RDX_RCX                      EMIT u8 0x48 0x01 0xCA
#define X64_SUB_RAX_RCX                      EMIT u8 0x48 0x29 0xC8
#define X64_SUB_RAX_RDX                      EMIT u8 0x48 0x29 0xD0
#define X64_SUB_RAX_RBX                      EMIT u8 0x48 0x29 0xD8
#define X64_SUB_RCX_RDX                      EMIT u8 0x48 0x29 0xD1
#define X64_SUB_RDX_RCX                      EMIT u8 0x48 0x29 0xCA
#define X64_AND_RAX_RCX                      EMIT u8 0x48 0x21 0xC8
#define X64_AND_RAX_RDX                      EMIT u8 0x48 0x21 0xD0
#define X64_AND_RCX_RDX                      EMIT u8 0x48 0x21 0xD1
#define X64_OR_RAX_RCX                       EMIT u8 0x48 0x09 0xC8
#define X64_OR_RAX_RDX                       EMIT u8 0x48 0x09 0xD0
#define X64_OR_RCX_RDX                       EMIT u8 0x48 0x09 0xD1
#define X64_XOR_RAX_RCX                      EMIT u8 0x48 0x31 0xC8
#define X64_XOR_RAX_RDX                      EMIT u8 0x48 0x31 0xD0
#define X64_XOR_RCX_RDX                      EMIT u8 0x48 0x31 0xD1
#define X64_NEG_RAX                          EMIT u8 0x48 0xF7 0xD8
#define X64_NEG_RCX                          EMIT u8 0x48 0xF7 0xD9
#define X64_NEG_RDX                          EMIT u8 0x48 0xF7 0xDA
#define X64_NEG_RBX                          EMIT u8 0x48 0xF7 0xDB
#define X64_NOT_RAX                          EMIT u8 0x48 0xF7 0xD0
#define X64_NOT_RCX                          EMIT u8 0x48 0xF7 0xD1
#define X64_INC_RAX                          EMIT u8 0x48 0xFF 0xC0
#define X64_INC_RCX                          EMIT u8 0x48 0xFF 0xC1
#define X64_INC_RDX                          EMIT u8 0x48 0xFF 0xC2
#define X64_INC_RBX                          EMIT u8 0x48 0xFF 0xC3
#define X64_INC_RSI                          EMIT u8 0x48 0xFF 0xC6
#define X64_INC_RDI                          EMIT u8 0x48 0xFF 0xC7
#define X64_DEC_RAX                          EMIT u8 0x48 0xFF 0xC8
#define X64_DEC_RCX                          EMIT u8 0x48 0xFF 0xC9
#define X64_DEC_RDX                          EMIT u8 0x48 0xFF 0xCA
#define X64_DEC_RBX                          EMIT u8 0x48 0xFF 0xCB
#define X64_DEC_RSI                          EMIT u8 0x48 0xFF 0xCE
#define X64_DEC_RDI                          EMIT u8 0x48 0xFF 0xCF
#define X64_IMUL_RAX_RCX                     EMIT u8 0x48 0x0F 0xAF 0xC1
#define X64_IMUL_RAX_RDX                     EMIT u8 0x48 0x0F 0xAF 0xC2
#define X64_IMUL_RAX_RBX                     EMIT u8 0x48 0x0F 0xAF 0xC3
#define X64_IMUL_RCX_RDX                     EMIT u8 0x48 0x0F 0xAF 0xCA
#define X64_IMUL_RDX_RCX                     EMIT u8 0x48 0x0F 0xAF 0xD1
#define X64_MUL_RCX                          EMIT u8 0x48 0xF7 0xE1
#define X64_MUL_RBX                          EMIT u8 0x48 0xF7 0xE3
#define X64_DIV_RCX                          EMIT u8 0x48 0xF7 0xF1
#define X64_DIV_RBX                          EMIT u8 0x48 0xF7 0xF3
#define X64_IDIV_RCX                         EMIT u8 0x48 0xF7 0xF9
#define X64_IDIV_RBX                         EMIT u8 0x48 0xF7 0xFB

// ────────────────────────────────────────────────────────
//  Arithmetic with imm8  ⚠ follow with EMIT u8 <n>
// ────────────────────────────────────────────────────────
#define X64_ADD_RAX_IMM8                     EMIT u8 0x48 0x83 0xC0
#define X64_ADD_RCX_IMM8                     EMIT u8 0x48 0x83 0xC1
#define X64_ADD_RDX_IMM8                     EMIT u8 0x48 0x83 0xC2
#define X64_ADD_RBX_IMM8                     EMIT u8 0x48 0x83 0xC3
#define X64_ADD_RSI_IMM8                     EMIT u8 0x48 0x83 0xC6
#define X64_ADD_RDI_IMM8                     EMIT u8 0x48 0x83 0xC7
#define X64_SUB_RAX_IMM8                     EMIT u8 0x48 0x83 0xE8
#define X64_SUB_RCX_IMM8                     EMIT u8 0x48 0x83 0xE9
#define X64_SUB_RDX_IMM8                     EMIT u8 0x48 0x83 0xEA
#define X64_SUB_RBX_IMM8                     EMIT u8 0x48 0x83 0xEB
#define X64_AND_RAX_IMM8                     EMIT u8 0x48 0x83 0xE0
#define X64_AND_RCX_IMM8                     EMIT u8 0x48 0x83 0xE1
#define X64_OR_RAX_IMM8                      EMIT u8 0x48 0x83 0xC8
#define X64_OR_RCX_IMM8                      EMIT u8 0x48 0x83 0xC9
#define X64_XOR_RAX_IMM8                     EMIT u8 0x48 0x83 0xF0
#define X64_XOR_RCX_IMM8                     EMIT u8 0x48 0x83 0xF1
#define X64_CMP_RAX_IMM8                     EMIT u8 0x48 0x83 0xF8
#define X64_CMP_RCX_IMM8                     EMIT u8 0x48 0x83 0xF9
#define X64_CMP_RDX_IMM8                     EMIT u8 0x48 0x83 0xFA
#define X64_CMP_RBX_IMM8                     EMIT u8 0x48 0x83 0xFB
#define X64_CMP_RSI_IMM8                     EMIT u8 0x48 0x83 0xFE
#define X64_CMP_RDI_IMM8                     EMIT u8 0x48 0x83 0xFF

// ────────────────────────────────────────────────────────
//  TEST / CMP reg-reg
// ────────────────────────────────────────────────────────
#define X64_TEST_RAX_RAX                     EMIT u8 0x48 0x85 0xC0
#define X64_TEST_RCX_RCX                     EMIT u8 0x48 0x85 0xC9
#define X64_TEST_RDX_RDX                     EMIT u8 0x48 0x85 0xD2
#define X64_TEST_RBX_RBX                     EMIT u8 0x48 0x85 0xDB
#define X64_TEST_RSI_RSI                     EMIT u8 0x48 0x85 0xF6
#define X64_TEST_RDI_RDI                     EMIT u8 0x48 0x85 0xFF
#define X64_TEST_RAX_RCX                     EMIT u8 0x48 0x85 0xC1
#define X64_TEST_RAX_RDX                     EMIT u8 0x48 0x85 0xC2
#define X64_TEST_AL_AL                       EMIT u8 0x84 0xC0
#define X64_CMP_RAX_RCX                      EMIT u8 0x48 0x39 0xC8
#define X64_CMP_RAX_RDX                      EMIT u8 0x48 0x39 0xD0
#define X64_CMP_RAX_RBX                      EMIT u8 0x48 0x39 0xD8
#define X64_CMP_RAX_RSI                      EMIT u8 0x48 0x39 0xF0
#define X64_CMP_RAX_RDI                      EMIT u8 0x48 0x39 0xF8
#define X64_CMP_RCX_RDX                      EMIT u8 0x48 0x39 0xD1
#define X64_CMP_RCX_RBX                      EMIT u8 0x48 0x39 0xD9
#define X64_CMP_RDX_RBX                      EMIT u8 0x48 0x39 0xDA
#define X64_CMP_RDX_RSI                      EMIT u8 0x48 0x39 0xF2

// ────────────────────────────────────────────────────────
//  Shift / rotate  ⚠ follow with EMIT u8 <count>
// ────────────────────────────────────────────────────────
#define X64_SHL_RAX_IMM                      EMIT u8 0x48 0xC1 0xE0
#define X64_SHR_RAX_IMM                      EMIT u8 0x48 0xC1 0xE8
#define X64_SAR_RAX_IMM                      EMIT u8 0x48 0xC1 0xF8
#define X64_ROL_RAX_IMM                      EMIT u8 0x48 0xC1 0xC0
#define X64_ROR_RAX_IMM                      EMIT u8 0x48 0xC1 0xC8
#define X64_RCL_RAX_IMM                      EMIT u8 0x48 0xC1 0xD0
#define X64_RCR_RAX_IMM                      EMIT u8 0x48 0xC1 0xD8
#define X64_SHL_RCX_IMM                      EMIT u8 0x48 0xC1 0xE1
#define X64_SHR_RCX_IMM                      EMIT u8 0x48 0xC1 0xE9
#define X64_SAR_RCX_IMM                      EMIT u8 0x48 0xC1 0xF9
#define X64_SHL_RDX_IMM                      EMIT u8 0x48 0xC1 0xE2
#define X64_SHR_RDX_IMM                      EMIT u8 0x48 0xC1 0xEA
#define X64_SAR_RDX_IMM                      EMIT u8 0x48 0xC1 0xFA
#define X64_SHL_RBX_IMM                      EMIT u8 0x48 0xC1 0xE3
#define X64_SHR_RBX_IMM                      EMIT u8 0x48 0xC1 0xEB

// ────────────────────────────────────────────────────────
//  Shift by CL
// ────────────────────────────────────────────────────────
#define X64_SHL_RAX_CL                       EMIT u8 0x48 0xD3 0xE0
#define X64_SHR_RAX_CL                       EMIT u8 0x48 0xD3 0xE8
#define X64_SAR_RAX_CL                       EMIT u8 0x48 0xD3 0xF8
#define X64_ROL_RAX_CL                       EMIT u8 0x48 0xD3 0xC0
#define X64_ROR_RAX_CL                       EMIT u8 0x48 0xD3 0xC8
#define X64_SHL_RCX_CL                       EMIT u8 0x48 0xD3 0xE1
#define X64_SHR_RCX_CL                       EMIT u8 0x48 0xD3 0xE9
#define X64_SHL_RDX_CL                       EMIT u8 0x48 0xD3 0xE2
#define X64_SHR_RDX_CL                       EMIT u8 0x48 0xD3 0xEA

// ────────────────────────────────────────────────────────
//  Bit operations
// ────────────────────────────────────────────────────────
#define X64_BT_RAX_RCX                       EMIT u8 0x48 0x0F 0xA3 0xC8   // bit test
#define X64_BTS_RAX_RCX                      EMIT u8 0x48 0x0F 0xAB 0xC8   // bit test and set
#define X64_BTR_RAX_RCX                      EMIT u8 0x48 0x0F 0xB3 0xC8   // bit test and reset
#define X64_BTC_RAX_RCX                      EMIT u8 0x48 0x0F 0xBB 0xC8   // bit test and complement
#define X64_BSF_RAX_RCX                      EMIT u8 0x48 0x0F 0xBC 0xC1   // bit scan forward
#define X64_BSR_RAX_RCX                      EMIT u8 0x48 0x0F 0xBD 0xC1   // bit scan reverse
#define X64_LZCNT_RAX_RCX                    EMIT u8 0xF3 0x48 0x0F 0xBD 0xC1   // leading zeros
#define X64_TZCNT_RAX_RCX                    EMIT u8 0xF3 0x48 0x0F 0xBC 0xC1   // trailing zeros
#define X64_POPCNT_RAX_RCX                   EMIT u8 0xF3 0x48 0x0F 0xB8 0xC1   // population count
#define X64_ANDN_RAX_RCX_RDX                 EMIT u8 0xC4 0xE2 0xB0 0xF2 0xC2   // ~RCX & RDX → RAX (BMI1)
#define X64_BLSI_RCX_RAX                     EMIT u8 0xC4 0xE2 0xB8 0xF3 0xC8   // extract lowest set bit
#define X64_BLSMSK_RCX_RAX                   EMIT u8 0xC4 0xE2 0xB8 0xF3 0xD0   // mask up to lowest set bit
#define X64_BLSR_RCX_RAX                     EMIT u8 0xC4 0xE2 0xB8 0xF3 0xC0   // reset lowest set bit

// ────────────────────────────────────────────────────────
//  Atomic / locked operations
// ────────────────────────────────────────────────────────
#define X64_XCHG_RAX_RCX                     EMIT u8 0x48 0x87 0xC1   // exchange (implicit LOCK)
#define X64_XCHG_RAX_RDX                     EMIT u8 0x48 0x87 0xC2
#define X64_XCHG_RAX_RBX                     EMIT u8 0x48 0x87 0xC3
#define X64_LOCK_XADD_MEM_RAX                EMIT u8 0xF0 0x48 0x0F 0xC1 0x07   // LOCK XADD [RDI], RAX
#define X64_LOCK_CMPXCHG                     EMIT u8 0xF0 0x48 0x0F 0xB1 0x0F   // LOCK CMPXCHG [RDI], RCX  (cmp RAX)
#define X64_LOCK_INC_MEM                     EMIT u8 0xF0 0x48 0xFF 0x07   // LOCK INC qword [RDI]
#define X64_LOCK_DEC_MEM                     EMIT u8 0xF0 0x48 0xFF 0x0F   // LOCK DEC qword [RDI]
#define X64_LOCK_ADD_MEM_RAX                 EMIT u8 0xF0 0x48 0x01 0x07   // LOCK ADD [RDI], RAX
#define X64_LOCK_OR_MEM_RAX                  EMIT u8 0xF0 0x48 0x09 0x07   // LOCK OR  [RDI], RAX
#define X64_LOCK_AND_MEM_RAX                 EMIT u8 0xF0 0x48 0x21 0x07   // LOCK AND [RDI], RAX
#define X64_LOCK_XOR_MEM_RAX                 EMIT u8 0xF0 0x48 0x31 0x07   // LOCK XOR [RDI], RAX
#define X64_CMPXCHG8B                        EMIT u8 0x0F 0xC7 0x0F   // CMPXCHG8B [RDI]
#define X64_CMPXCHG16B                       EMIT u8 0x48 0x0F 0xC7 0x0F   // CMPXCHG16B [RDI]

// ────────────────────────────────────────────────────────
//  Conditional moves (CMOVcc rax, rcx)
// ────────────────────────────────────────────────────────
#define X64_CMOVE_RAX_RCX                    EMIT u8 0x48 0x0F 0x44 0xC1
#define X64_CMOVNE_RAX_RCX                   EMIT u8 0x48 0x0F 0x45 0xC1
#define X64_CMOVL_RAX_RCX                    EMIT u8 0x48 0x0F 0x4C 0xC1
#define X64_CMOVLE_RAX_RCX                   EMIT u8 0x48 0x0F 0x4E 0xC1
#define X64_CMOVG_RAX_RCX                    EMIT u8 0x48 0x0F 0x4F 0xC1
#define X64_CMOVGE_RAX_RCX                   EMIT u8 0x48 0x0F 0x4D 0xC1
#define X64_CMOVB_RAX_RCX                    EMIT u8 0x48 0x0F 0x42 0xC1
#define X64_CMOVBE_RAX_RCX                   EMIT u8 0x48 0x0F 0x46 0xC1
#define X64_CMOVA_RAX_RCX                    EMIT u8 0x48 0x0F 0x47 0xC1
#define X64_CMOVAE_RAX_RCX                   EMIT u8 0x48 0x0F 0x43 0xC1
#define X64_CMOVS_RAX_RCX                    EMIT u8 0x48 0x0F 0x48 0xC1
#define X64_CMOVNS_RAX_RCX                   EMIT u8 0x48 0x0F 0x49 0xC1
#define X64_CMOVO_RAX_RCX                    EMIT u8 0x48 0x0F 0x40 0xC1
#define X64_CMOVNO_RAX_RCX                   EMIT u8 0x48 0x0F 0x41 0xC1
#define X64_CMOVZ_RAX_RCX                    EMIT u8 0x48 0x0F 0x44 0xC1
#define X64_CMOVNZ_RAX_RCX                   EMIT u8 0x48 0x0F 0x45 0xC1
#define X64_CMOVC_RAX_RCX                    EMIT u8 0x48 0x0F 0x42 0xC1
#define X64_CMOVNC_RAX_RCX                   EMIT u8 0x48 0x0F 0x43 0xC1

// ────────────────────────────────────────────────────────
//  SETcc — write 0 or 1 to AL
// ────────────────────────────────────────────────────────
#define X64_SETE_AL                          EMIT u8 0x0F 0x94 0xC0
#define X64_SETNE_AL                         EMIT u8 0x0F 0x95 0xC0
#define X64_SETL_AL                          EMIT u8 0x0F 0x9C 0xC0
#define X64_SETLE_AL                         EMIT u8 0x0F 0x9E 0xC0
#define X64_SETG_AL                          EMIT u8 0x0F 0x9F 0xC0
#define X64_SETGE_AL                         EMIT u8 0x0F 0x9D 0xC0
#define X64_SETB_AL                          EMIT u8 0x0F 0x92 0xC0
#define X64_SETBE_AL                         EMIT u8 0x0F 0x96 0xC0
#define X64_SETA_AL                          EMIT u8 0x0F 0x97 0xC0
#define X64_SETAE_AL                         EMIT u8 0x0F 0x93 0xC0
#define X64_SETS_AL                          EMIT u8 0x0F 0x98 0xC0
#define X64_SETNS_AL                         EMIT u8 0x0F 0x99 0xC0
#define X64_SETO_AL                          EMIT u8 0x0F 0x90 0xC0
#define X64_SETNO_AL                         EMIT u8 0x0F 0x91 0xC0
#define X64_SETZ_AL                          EMIT u8 0x0F 0x94 0xC0
#define X64_SETNZ_AL                         EMIT u8 0x0F 0x95 0xC0
#define X64_SETC_AL                          EMIT u8 0x0F 0x92 0xC0
#define X64_SETNC_AL                         EMIT u8 0x0F 0x93 0xC0
#define X64_SETP_AL                          EMIT u8 0x0F 0x9A 0xC0
#define X64_SETNP_AL                         EMIT u8 0x0F 0x9B 0xC0

// ────────────────────────────────────────────────────────
//  Short jumps  ⚠ follow with EMIT u8 <signed rel8>
// ────────────────────────────────────────────────────────
#define X64_JMP_SHORT                        EMIT u8 0xEB
#define X64_JE_SHORT                         EMIT u8 0x74
#define X64_JNE_SHORT                        EMIT u8 0x75
#define X64_JZ_SHORT                         EMIT u8 0x74
#define X64_JNZ_SHORT                        EMIT u8 0x75
#define X64_JL_SHORT                         EMIT u8 0x7C
#define X64_JLE_SHORT                        EMIT u8 0x7E
#define X64_JG_SHORT                         EMIT u8 0x7F
#define X64_JGE_SHORT                        EMIT u8 0x7D
#define X64_JB_SHORT                         EMIT u8 0x72
#define X64_JBE_SHORT                        EMIT u8 0x76
#define X64_JA_SHORT                         EMIT u8 0x77
#define X64_JAE_SHORT                        EMIT u8 0x73
#define X64_JS_SHORT                         EMIT u8 0x78
#define X64_JNS_SHORT                        EMIT u8 0x79
#define X64_JO_SHORT                         EMIT u8 0x70
#define X64_JNO_SHORT                        EMIT u8 0x71
#define X64_JP_SHORT                         EMIT u8 0x7A
#define X64_JNP_SHORT                        EMIT u8 0x7B
#define X64_JRCXZ_SHORT                      EMIT u8 0xE3
#define X64_LOOP_SHORT                       EMIT u8 0xE2
#define X64_LOOPE_SHORT                      EMIT u8 0xE1
#define X64_LOOPNE_SHORT                     EMIT u8 0xE0

// ────────────────────────────────────────────────────────
//  Near jumps  ⚠ follow with EMIT u32 <signed rel32>
// ────────────────────────────────────────────────────────
#define X64_JMP_NEAR                         EMIT u8 0xE9
#define X64_CALL_REL32                       EMIT u8 0xE8
#define X64_JE_NEAR                          EMIT u8 0x0F 0x84
#define X64_JNE_NEAR                         EMIT u8 0x0F 0x85
#define X64_JZ_NEAR                          EMIT u8 0x0F 0x84
#define X64_JNZ_NEAR                         EMIT u8 0x0F 0x85
#define X64_JL_NEAR                          EMIT u8 0x0F 0x8C
#define X64_JLE_NEAR                         EMIT u8 0x0F 0x8E
#define X64_JG_NEAR                          EMIT u8 0x0F 0x8F
#define X64_JGE_NEAR                         EMIT u8 0x0F 0x8D
#define X64_JB_NEAR                          EMIT u8 0x0F 0x82
#define X64_JBE_NEAR                         EMIT u8 0x0F 0x86
#define X64_JA_NEAR                          EMIT u8 0x0F 0x87
#define X64_JAE_NEAR                         EMIT u8 0x0F 0x83
#define X64_JS_NEAR                          EMIT u8 0x0F 0x88
#define X64_JNS_NEAR                         EMIT u8 0x0F 0x89
#define X64_JO_NEAR                          EMIT u8 0x0F 0x80
#define X64_JNO_NEAR                         EMIT u8 0x0F 0x81
#define X64_JP_NEAR                          EMIT u8 0x0F 0x8A
#define X64_JNP_NEAR                         EMIT u8 0x0F 0x8B

// ────────────────────────────────────────────────────────
//  Indirect call / jump via register
// ────────────────────────────────────────────────────────
#define X64_CALL_RAX                         EMIT u8 0xFF 0xD0
#define X64_CALL_RCX                         EMIT u8 0xFF 0xD1
#define X64_CALL_RDX                         EMIT u8 0xFF 0xD2
#define X64_CALL_RBX                         EMIT u8 0xFF 0xD3
#define X64_CALL_RSI                         EMIT u8 0xFF 0xD6
#define X64_CALL_RDI                         EMIT u8 0xFF 0xD7
#define X64_CALL_R8                          EMIT u8 0x41 0xFF 0xD0
#define X64_CALL_R9                          EMIT u8 0x41 0xFF 0xD1
#define X64_CALL_R10                         EMIT u8 0x41 0xFF 0xD2
#define X64_CALL_R11                         EMIT u8 0x41 0xFF 0xD3
#define X64_JMP_RAX                          EMIT u8 0xFF 0xE0
#define X64_JMP_RCX                          EMIT u8 0xFF 0xE1
#define X64_JMP_RDX                          EMIT u8 0xFF 0xE2
#define X64_JMP_RBX                          EMIT u8 0xFF 0xE3
#define X64_JMP_RSI                          EMIT u8 0xFF 0xE6
#define X64_JMP_RDI                          EMIT u8 0xFF 0xE7
#define X64_JMP_R8                           EMIT u8 0x41 0xFF 0xE0
#define X64_JMP_R11                          EMIT u8 0x41 0xFF 0xE3

// ────────────────────────────────────────────────────────
//  Control register access  (CPL 0)
// ────────────────────────────────────────────────────────
#define X64_MOV_CR0_RAX                      EMIT u8 0x0F 0x22 0xC0
#define X64_MOV_CR3_RAX                      EMIT u8 0x0F 0x22 0xD8
#define X64_MOV_CR4_RAX                      EMIT u8 0x0F 0x22 0xE0
#define X64_MOV_CR8_RAX                      EMIT u8 0x0F 0x22 0xC0
#define X64_MOV_RAX_CR0                      EMIT u8 0x0F 0x20 0xC0
#define X64_MOV_RAX_CR3                      EMIT u8 0x0F 0x20 0xD8
#define X64_MOV_RAX_CR4                      EMIT u8 0x0F 0x20 0xE0

// ────────────────────────────────────────────────────────
//  SSE2 — basic XMM operations (most used)
// ────────────────────────────────────────────────────────
#define X64_MOVAPS_XMM0_XMM1                 EMIT u8 0x0F 0x28 0xC1   // aligned move
#define X64_MOVUPS_XMM0_XMM1                 EMIT u8 0x0F 0x10 0xC1   // unaligned move
#define X64_XORPS_XMM0_XMM0                  EMIT u8 0x0F 0x57 0xC0   // zero xmm0
#define X64_XORPD_XMM0_XMM0                  EMIT u8 0x66 0x0F 0x57 0xC0   // zero xmm0 double
#define X64_ADDPS_XMM0_XMM1                  EMIT u8 0x0F 0x58 0xC1   // add packed float
#define X64_ADDPD_XMM0_XMM1                  EMIT u8 0x66 0x0F 0x58 0xC1   // add packed double
#define X64_SUBPS_XMM0_XMM1                  EMIT u8 0x0F 0x5C 0xC1   // sub packed float
#define X64_MULPS_XMM0_XMM1                  EMIT u8 0x0F 0x59 0xC1   // mul packed float
#define X64_DIVPS_XMM0_XMM1                  EMIT u8 0x0F 0x5E 0xC1   // div packed float
#define X64_ADDSS_XMM0_XMM1                  EMIT u8 0xF3 0x0F 0x58 0xC1   // add scalar float
#define X64_ADDSD_XMM0_XMM1                  EMIT u8 0xF2 0x0F 0x58 0xC1   // add scalar double
#define X64_SUBSS_XMM0_XMM1                  EMIT u8 0xF3 0x0F 0x5C 0xC1   // sub scalar float
#define X64_MULSS_XMM0_XMM1                  EMIT u8 0xF3 0x0F 0x59 0xC1   // mul scalar float
#define X64_DIVSS_XMM0_XMM1                  EMIT u8 0xF3 0x0F 0x5E 0xC1   // div scalar float
#define X64_SQRTSS_XMM0_XMM1                 EMIT u8 0xF3 0x0F 0x51 0xC1   // sqrt scalar float
#define X64_SQRTSD_XMM0_XMM1                 EMIT u8 0xF2 0x0F 0x51 0xC1   // sqrt scalar double
#define X64_CVTSI2SS_XMM0_RAX                EMIT u8 0xF3 0x48 0x0F 0x2A 0xC0   // int64→float32
#define X64_CVTSI2SD_XMM0_RAX                EMIT u8 0xF2 0x48 0x0F 0x2A 0xC0   // int64→float64
#define X64_CVTSS2SI_RAX_XMM0                EMIT u8 0xF3 0x48 0x0F 0x2D 0xC0   // float32→int64
#define X64_CVTSD2SI_RAX_XMM0                EMIT u8 0xF2 0x48 0x0F 0x2D 0xC0   // float64→int64
#define X64_CVTSS2SD_XMM0_XMM1               EMIT u8 0xF3 0x0F 0x5A 0xC1   // float32→float64
#define X64_CVTSD2SS_XMM0_XMM1               EMIT u8 0xF2 0x0F 0x5A 0xC1   // float64→float32
#define X64_PXOR_XMM0_XMM0                   EMIT u8 0x66 0x0F 0xEF 0xC0   // zero xmm0 integer
#define X64_PADDB_XMM0_XMM1                  EMIT u8 0x66 0x0F 0xFC 0xC1   // add packed bytes
#define X64_PADDW_XMM0_XMM1                  EMIT u8 0x66 0x0F 0xFD 0xC1   // add packed words
#define X64_PADDD_XMM0_XMM1                  EMIT u8 0x66 0x0F 0xFE 0xC1   // add packed dwords
#define X64_PADDQ_XMM0_XMM1                  EMIT u8 0x66 0x0F 0xD4 0xC1   // add packed qwords
#define X64_PCMPEQB_XMM0_XMM1                EMIT u8 0x66 0x0F 0x74 0xC1   // compare bytes ==
#define X64_PCMPEQD_XMM0_XMM1                EMIT u8 0x66 0x0F 0x76 0xC1   // compare dwords ==
#define X64_PMOVMSKB_RAX_XMM0                EMIT u8 0x66 0x0F 0xD7 0xC0   // move byte mask → RAX

// ────────────────────────────────────────────────────────
//  Complete Linux syscall sequences  (self-contained)
// ────────────────────────────────────────────────────────
#define X64_WRITE_STDOUT                     EMIT u8 0x48 0xC7 0xC0 0x01 0x00 0x00 0x00 0x48 0xC7 0xC7 0x01 0x00 0x00 0x00   // mov rax,1; mov rdi,1  (then set rsi=ptr rdx=len + SYSCALL)
#define X64_WRITE_STDERR                     EMIT u8 0x48 0xC7 0xC0 0x01 0x00 0x00 0x00 0x48 0xC7 0xC7 0x02 0x00 0x00 0x00   // mov rax,1; mov rdi,2
#define X64_WRITE_1                          EMIT u8 0x48 0xC7 0xC0 0x01 0x00 0x00 0x00 0x48 0xC7 0xC7 0x01 0x00 0x00 0x00   // alias for X64_WRITE_STDOUT
#define X64_EXIT_0                           EMIT u8 0x48 0xC7 0xC0 0x3C 0x00 0x00 0x00 0x48 0x31 0xFF 0x0F 0x05   // mov rax,60; xor rdi,rdi; syscall  — exit(0)
#define X64_EXIT_1                           EMIT u8 0x48 0xC7 0xC0 0x3C 0x00 0x00 0x00 0x48 0xC7 0xC7 0x01 0x00 0x00 0x00 0x0F 0x05   // exit(1)
#define X64_EXIT_GROUP_0                     EMIT u8 0x48 0xC7 0xC0 0xE7 0x00 0x00 0x00 0x48 0x31 0xFF 0x0F 0x05   // exit_group(0) — preferred for main
#define X64_GETPID                           EMIT u8 0x48 0xC7 0xC0 0x27 0x00 0x00 0x00 0x0F 0x05   // getpid() → rax
#define X64_FORK                             EMIT u8 0x48 0xC7 0xC0 0x39 0x00 0x00 0x00 0x0F 0x05   // fork() → rax

////////////////////////////////////////////////////////////////
// §10  x86-32 INSTRUCTIONS
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  Single-byte instructions
// ────────────────────────────────────────────────────────
#define X86_NOP                              EMIT u8 0x90
#define X86_RET                              EMIT u8 0xC3   // near
#define X86_RETF                             EMIT u8 0xCB   // far
#define X86_INT3                             EMIT u8 0xCC   // breakpoint
#define X86_HLT                              EMIT u8 0xF4
#define X86_CLI                              EMIT u8 0xFA
#define X86_STI                              EMIT u8 0xFB
#define X86_CLD                              EMIT u8 0xFC
#define X86_STD                              EMIT u8 0xFD
#define X86_PUSHA                            EMIT u8 0x60   // push all
#define X86_POPA                             EMIT u8 0x61   // pop all
#define X86_PUSHFD                           EMIT u8 0x9C   // push eflags
#define X86_POPFD                            EMIT u8 0x9D   // pop eflags
#define X86_LEAVE                            EMIT u8 0xC9   // mov esp,ebp; pop ebp
#define X86_PAUSE                            EMIT u8 0xF3 0x90   // spin-loop hint
#define X86_INT_80                           EMIT u8 0xCD 0x80   // Linux 32-bit syscall
#define X86_INT_21                           EMIT u8 0xCD 0x21   // DOS services
#define X86_INT_13                           EMIT u8 0xCD 0x13   // BIOS disk
#define X86_INT_10                           EMIT u8 0xCD 0x10   // BIOS video

// ────────────────────────────────────────────────────────
//  PUSH/POP 32-bit GPRs
// ────────────────────────────────────────────────────────
#define X86_PUSH_EAX                         EMIT u8 0x50
#define X86_POP_EAX                          EMIT u8 0x58
#define X86_PUSH_ECX                         EMIT u8 0x51
#define X86_POP_ECX                          EMIT u8 0x59
#define X86_PUSH_EDX                         EMIT u8 0x52
#define X86_POP_EDX                          EMIT u8 0x5A
#define X86_PUSH_EBX                         EMIT u8 0x53
#define X86_POP_EBX                          EMIT u8 0x5B
#define X86_PUSH_ESP                         EMIT u8 0x54
#define X86_POP_ESP                          EMIT u8 0x5C
#define X86_PUSH_EBP                         EMIT u8 0x55
#define X86_POP_EBP                          EMIT u8 0x5D
#define X86_PUSH_ESI                         EMIT u8 0x56
#define X86_POP_ESI                          EMIT u8 0x5E
#define X86_PUSH_EDI                         EMIT u8 0x57
#define X86_POP_EDI                          EMIT u8 0x5F

// ────────────────────────────────────────────────────────
//  XOR to zero  (2 bytes)
// ────────────────────────────────────────────────────────
#define X86_XOR_EAX                          EMIT u8 0x31 0xC0
#define X86_XOR_ECX                          EMIT u8 0x31 0xC9
#define X86_XOR_EDX                          EMIT u8 0x31 0xD2
#define X86_XOR_EBX                          EMIT u8 0x31 0xDB
#define X86_XOR_ESI                          EMIT u8 0x31 0xF6
#define X86_XOR_EDI                          EMIT u8 0x31 0xFF

// ────────────────────────────────────────────────────────
//  MOV reg, imm32  ⚠ follow with EMIT u32 <val>
// ────────────────────────────────────────────────────────
#define X86_MOV_EAX                          EMIT u8 0xB8
#define X86_MOV_ECX                          EMIT u8 0xB9
#define X86_MOV_EDX                          EMIT u8 0xBA
#define X86_MOV_EBX                          EMIT u8 0xBB
#define X86_MOV_ESP                          EMIT u8 0xBC
#define X86_MOV_EBP                          EMIT u8 0xBD
#define X86_MOV_ESI                          EMIT u8 0xBE
#define X86_MOV_EDI                          EMIT u8 0xBF

// ────────────────────────────────────────────────────────
//  Stack frame
// ────────────────────────────────────────────────────────
#define X86_FRAME_ENTER                      EMIT u8 0x55 0x89 0xE5   // push ebp; mov ebp,esp
#define X86_FRAME_LEAVE                      EMIT u8 0xC9 0xC3   // leave; ret
#define X86_ALIGN16                          EMIT u8 0x83 0xE4 0xF0   // and esp,-16

// ────────────────────────────────────────────────────────
//  Short jumps  ⚠ follow with EMIT u8 <rel8>
// ────────────────────────────────────────────────────────
#define X86_JMP_SHORT                        EMIT u8 0xEB
#define X86_JE_SHORT                         EMIT u8 0x74
#define X86_JNE_SHORT                        EMIT u8 0x75
#define X86_JL_SHORT                         EMIT u8 0x7C
#define X86_JLE_SHORT                        EMIT u8 0x7E
#define X86_JG_SHORT                         EMIT u8 0x7F
#define X86_JGE_SHORT                        EMIT u8 0x7D
#define X86_JB_SHORT                         EMIT u8 0x72
#define X86_JA_SHORT                         EMIT u8 0x77

// ────────────────────────────────────────────────────────
//  Near call/jmp  ⚠ follow with EMIT u32 <rel32>
// ────────────────────────────────────────────────────────
#define X86_CALL_REL32                       EMIT u8 0xE8
#define X86_JMP_NEAR                         EMIT u8 0xE9
#define X86_CALL_EAX                         EMIT u8 0xFF 0xD0
#define X86_JMP_EAX                          EMIT u8 0xFF 0xE0

// ────────────────────────────────────────────────────────
//  Linux x86-32 syscall numbers
// ────────────────────────────────────────────────────────
#define X86_SYS_READ                         3
#define X86_SYS_WRITE                        4
#define X86_SYS_OPEN                         5
#define X86_SYS_CLOSE                        6
#define X86_SYS_STAT                         106
#define X86_SYS_LSTAT                        107
#define X86_SYS_FSTAT                        108
#define X86_SYS_LSEEK                        19
#define X86_SYS_MMAP                         90
#define X86_SYS_MMAP2                        192
#define X86_SYS_MUNMAP                       91
#define X86_SYS_BRK                          45
#define X86_SYS_IOCTL                        54
#define X86_SYS_WRITEV                       146
#define X86_SYS_ACCESS                       33
#define X86_SYS_PIPE                         42
#define X86_SYS_DUP                          41
#define X86_SYS_DUP2                         63
#define X86_SYS_GETPID                       20
#define X86_SYS_FORK                         2
#define X86_SYS_VFORK                        190
#define X86_SYS_EXECVE                       11
#define X86_SYS_EXIT                         1
#define X86_SYS_WAIT4                        114
#define X86_SYS_KILL                         37
#define X86_SYS_RENAME                       38
#define X86_SYS_MKDIR                        39
#define X86_SYS_RMDIR                        40
#define X86_SYS_UNLINK                       10
#define X86_SYS_LINK                         9
#define X86_SYS_SYMLINK                      83
#define X86_SYS_READLINK                     85
#define X86_SYS_CHMOD                        15
#define X86_SYS_CHOWN                        182
#define X86_SYS_SOCKET                       359
#define X86_SYS_CONNECT                      362
#define X86_SYS_BIND                         361
#define X86_SYS_LISTEN                       363
#define X86_SYS_ACCEPT                       364
#define X86_SYS_SENDTO                       369
#define X86_SYS_RECVFROM                     371
#define X86_SYS_GETSOCKNAME                  367
#define X86_SYS_CLONE                        120
#define X86_SYS_SETUID                       23
#define X86_SYS_GETUID                       24
#define X86_SYS_SETGID                       46
#define X86_SYS_GETGID                       47
#define X86_SYS_GETEUID                      49
#define X86_SYS_GETEGID                      50
#define X86_SYS_FCNTL                        55
#define X86_SYS_SELECT                       82
#define X86_SYS_POLL                         168
#define X86_SYS_NANOSLEEP                    162
#define X86_SYS_CLOCK_GETTIME                265
#define X86_SYS_EXIT_GROUP                   252

////////////////////////////////////////////////////////////////
// §11  ARM64 / AArch64 INSTRUCTIONS
//     All AArch64 instructions are 32-bit little-endian.
//     Reference: Arm Architecture Reference Manual (DDI 0487)
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  Single-instruction macros (complete, 4 bytes)
// ────────────────────────────────────────────────────────
#define A64_NOP                              EMIT u32 0xD503201F   // no-op
#define A64_RET                              EMIT u32 0xD65F03C0   // ret (return via LR)
#define A64_BRK_0                            EMIT u32 0xD4200000   // brk #0  (debugger)
#define A64_BRK_1                            EMIT u32 0xD4200020   // brk #1
#define A64_SVC_0                            EMIT u32 0xD4000001   // svc #0  (Linux syscall)
#define A64_HLT_0                            EMIT u32 0xD4400000   // hlt #0
#define A64_WFI                              EMIT u32 0xD503207F   // wait for interrupt
#define A64_WFE                              EMIT u32 0xD503205F   // wait for event
#define A64_SEV                              EMIT u32 0xD503209F   // send event
#define A64_SEVL                             EMIT u32 0xD50320BF   // send event local
#define A64_YIELD                            EMIT u32 0xD503203F   // yield hint
#define A64_ISBB                             EMIT u32 0xD503305F   // ISB (instruction sync barrier)
#define A64_DMB_ISH                          EMIT u32 0xD5033BBF   // data memory barrier inner-shareable
#define A64_DSB_ISH                          EMIT u32 0xD5033B9F   // data sync barrier inner-shareable
#define A64_DSB_SY                           EMIT u32 0xD5033F9F   // data sync barrier full system
#define A64_DMB_SY                           EMIT u32 0xD5033FBF   // data memory barrier full system
#define A64_CLREX                            EMIT u32 0xD5033F5F   // clear exclusive monitor
#define A64_MSR_DAIF_ALL                     EMIT u32 0xD50342DF   // set DAIF (disable all interrupts)
#define A64_MSR_DAIF_NONE                    EMIT u32 0xD50342FF   // clear DAIF (enable all interrupts) - care!

// ────────────────────────────────────────────────────────
//  MOV Xn, #imm16  (common small constants)
// ────────────────────────────────────────────────────────
#define A64_MOV_X0_0                         EMIT u32 0xD2800000
#define A64_MOV_X0_1                         EMIT u32 0xD2800020
#define A64_MOV_X0_2                         EMIT u32 0xD2800040
#define A64_MOV_X0_3                         EMIT u32 0xD2800060
#define A64_MOV_X0_4                         EMIT u32 0xD2800080
#define A64_MOV_X0_8                         EMIT u32 0xD2800100
#define A64_MOV_X0_16                        EMIT u32 0xD2800200
#define A64_MOV_X0_64                        EMIT u32 0xD2800800
#define A64_MOV_X0_93                        EMIT u32 0xD2800BA0
#define A64_MOV_X0_94                        EMIT u32 0xD2800BC0
#define A64_MOV_X0_172                       EMIT u32 0xD2801580
#define A64_MOV_X0_214                       EMIT u32 0xD2801AC0
#define A64_MOV_X0_220                       EMIT u32 0xD2801B80
#define A64_MOV_X0_221                       EMIT u32 0xD2801BA0
#define A64_MOV_X0_222                       EMIT u32 0xD2801BC0
#define A64_MOV_X1_0                         EMIT u32 0xD2800001
#define A64_MOV_X1_1                         EMIT u32 0xD2800021
#define A64_MOV_X1_2                         EMIT u32 0xD2800041
#define A64_MOV_X1_3                         EMIT u32 0xD2800061
#define A64_MOV_X1_4                         EMIT u32 0xD2800081
#define A64_MOV_X1_8                         EMIT u32 0xD2800101
#define A64_MOV_X1_16                        EMIT u32 0xD2800201
#define A64_MOV_X1_64                        EMIT u32 0xD2800801
#define A64_MOV_X1_93                        EMIT u32 0xD2800BA1
#define A64_MOV_X1_94                        EMIT u32 0xD2800BC1
#define A64_MOV_X1_172                       EMIT u32 0xD2801581
#define A64_MOV_X1_214                       EMIT u32 0xD2801AC1
#define A64_MOV_X1_220                       EMIT u32 0xD2801B81
#define A64_MOV_X1_221                       EMIT u32 0xD2801BA1
#define A64_MOV_X1_222                       EMIT u32 0xD2801BC1
#define A64_MOV_X2_0                         EMIT u32 0xD2800002
#define A64_MOV_X2_1                         EMIT u32 0xD2800022
#define A64_MOV_X2_2                         EMIT u32 0xD2800042
#define A64_MOV_X2_3                         EMIT u32 0xD2800062
#define A64_MOV_X2_4                         EMIT u32 0xD2800082
#define A64_MOV_X2_8                         EMIT u32 0xD2800102
#define A64_MOV_X2_16                        EMIT u32 0xD2800202
#define A64_MOV_X2_64                        EMIT u32 0xD2800802
#define A64_MOV_X2_93                        EMIT u32 0xD2800BA2
#define A64_MOV_X2_94                        EMIT u32 0xD2800BC2
#define A64_MOV_X2_172                       EMIT u32 0xD2801582
#define A64_MOV_X2_214                       EMIT u32 0xD2801AC2
#define A64_MOV_X2_220                       EMIT u32 0xD2801B82
#define A64_MOV_X2_221                       EMIT u32 0xD2801BA2
#define A64_MOV_X2_222                       EMIT u32 0xD2801BC2
#define A64_MOV_X3_0                         EMIT u32 0xD2800003
#define A64_MOV_X3_1                         EMIT u32 0xD2800023
#define A64_MOV_X3_2                         EMIT u32 0xD2800043
#define A64_MOV_X3_3                         EMIT u32 0xD2800063
#define A64_MOV_X3_4                         EMIT u32 0xD2800083
#define A64_MOV_X3_8                         EMIT u32 0xD2800103
#define A64_MOV_X3_16                        EMIT u32 0xD2800203
#define A64_MOV_X3_64                        EMIT u32 0xD2800803
#define A64_MOV_X3_93                        EMIT u32 0xD2800BA3
#define A64_MOV_X3_94                        EMIT u32 0xD2800BC3
#define A64_MOV_X3_172                       EMIT u32 0xD2801583
#define A64_MOV_X3_214                       EMIT u32 0xD2801AC3
#define A64_MOV_X3_220                       EMIT u32 0xD2801B83
#define A64_MOV_X3_221                       EMIT u32 0xD2801BA3
#define A64_MOV_X3_222                       EMIT u32 0xD2801BC3
#define A64_MOV_X4_0                         EMIT u32 0xD2800004
#define A64_MOV_X4_1                         EMIT u32 0xD2800024
#define A64_MOV_X4_2                         EMIT u32 0xD2800044
#define A64_MOV_X4_3                         EMIT u32 0xD2800064
#define A64_MOV_X4_4                         EMIT u32 0xD2800084
#define A64_MOV_X4_8                         EMIT u32 0xD2800104
#define A64_MOV_X4_16                        EMIT u32 0xD2800204
#define A64_MOV_X4_64                        EMIT u32 0xD2800804
#define A64_MOV_X4_93                        EMIT u32 0xD2800BA4
#define A64_MOV_X4_94                        EMIT u32 0xD2800BC4
#define A64_MOV_X4_172                       EMIT u32 0xD2801584
#define A64_MOV_X4_214                       EMIT u32 0xD2801AC4
#define A64_MOV_X4_220                       EMIT u32 0xD2801B84
#define A64_MOV_X4_221                       EMIT u32 0xD2801BA4
#define A64_MOV_X4_222                       EMIT u32 0xD2801BC4
#define A64_MOV_X5_0                         EMIT u32 0xD2800005
#define A64_MOV_X5_1                         EMIT u32 0xD2800025
#define A64_MOV_X5_2                         EMIT u32 0xD2800045
#define A64_MOV_X5_3                         EMIT u32 0xD2800065
#define A64_MOV_X5_4                         EMIT u32 0xD2800085
#define A64_MOV_X5_8                         EMIT u32 0xD2800105
#define A64_MOV_X5_16                        EMIT u32 0xD2800205
#define A64_MOV_X5_64                        EMIT u32 0xD2800805
#define A64_MOV_X5_93                        EMIT u32 0xD2800BA5
#define A64_MOV_X5_94                        EMIT u32 0xD2800BC5
#define A64_MOV_X5_172                       EMIT u32 0xD2801585
#define A64_MOV_X5_214                       EMIT u32 0xD2801AC5
#define A64_MOV_X5_220                       EMIT u32 0xD2801B85
#define A64_MOV_X5_221                       EMIT u32 0xD2801BA5
#define A64_MOV_X5_222                       EMIT u32 0xD2801BC5
#define A64_MOV_X6_0                         EMIT u32 0xD2800006
#define A64_MOV_X6_1                         EMIT u32 0xD2800026
#define A64_MOV_X6_2                         EMIT u32 0xD2800046
#define A64_MOV_X6_3                         EMIT u32 0xD2800066
#define A64_MOV_X6_4                         EMIT u32 0xD2800086
#define A64_MOV_X6_8                         EMIT u32 0xD2800106
#define A64_MOV_X6_16                        EMIT u32 0xD2800206
#define A64_MOV_X6_64                        EMIT u32 0xD2800806
#define A64_MOV_X6_93                        EMIT u32 0xD2800BA6
#define A64_MOV_X6_94                        EMIT u32 0xD2800BC6
#define A64_MOV_X6_172                       EMIT u32 0xD2801586
#define A64_MOV_X6_214                       EMIT u32 0xD2801AC6
#define A64_MOV_X6_220                       EMIT u32 0xD2801B86
#define A64_MOV_X6_221                       EMIT u32 0xD2801BA6
#define A64_MOV_X6_222                       EMIT u32 0xD2801BC6
#define A64_MOV_X7_0                         EMIT u32 0xD2800007
#define A64_MOV_X7_1                         EMIT u32 0xD2800027
#define A64_MOV_X7_2                         EMIT u32 0xD2800047
#define A64_MOV_X7_3                         EMIT u32 0xD2800067
#define A64_MOV_X7_4                         EMIT u32 0xD2800087
#define A64_MOV_X7_8                         EMIT u32 0xD2800107
#define A64_MOV_X7_16                        EMIT u32 0xD2800207
#define A64_MOV_X7_64                        EMIT u32 0xD2800807
#define A64_MOV_X7_93                        EMIT u32 0xD2800BA7
#define A64_MOV_X7_94                        EMIT u32 0xD2800BC7
#define A64_MOV_X7_172                       EMIT u32 0xD2801587
#define A64_MOV_X7_214                       EMIT u32 0xD2801AC7
#define A64_MOV_X7_220                       EMIT u32 0xD2801B87
#define A64_MOV_X7_221                       EMIT u32 0xD2801BA7
#define A64_MOV_X7_222                       EMIT u32 0xD2801BC7
#define A64_MOV_X8_0                         EMIT u32 0xD2800008
#define A64_MOV_X8_1                         EMIT u32 0xD2800028
#define A64_MOV_X8_2                         EMIT u32 0xD2800048
#define A64_MOV_X8_3                         EMIT u32 0xD2800068
#define A64_MOV_X8_4                         EMIT u32 0xD2800088
#define A64_MOV_X8_8                         EMIT u32 0xD2800108
#define A64_MOV_X8_16                        EMIT u32 0xD2800208
#define A64_MOV_X8_64                        EMIT u32 0xD2800808
#define A64_MOV_X8_93                        EMIT u32 0xD2800BA8
#define A64_MOV_X8_94                        EMIT u32 0xD2800BC8
#define A64_MOV_X8_172                       EMIT u32 0xD2801588
#define A64_MOV_X8_214                       EMIT u32 0xD2801AC8
#define A64_MOV_X8_220                       EMIT u32 0xD2801B88
#define A64_MOV_X8_221                       EMIT u32 0xD2801BA8
#define A64_MOV_X8_222                       EMIT u32 0xD2801BC8

// ────────────────────────────────────────────────────────
//  Common complete syscall sequences (Linux AArch64)
// ────────────────────────────────────────────────────────
#define A64_WRITE_STDOUT                     EMIT u32 0xD2800020 0xD2800808 0xD4000001   // mov x0,1; mov x8,64(sys_write); svc #0
#define A64_EXIT_0                           EMIT u32 0xD2800000 0xD2800BA8 0xD4000001   // mov x0,0; mov x8,93(sys_exit); svc #0
#define A64_EXIT_GROUP_0                     EMIT u32 0xD2800000 0xD2800BC8 0xD4000001   // exit_group(0)
#define A64_GETPID                           EMIT u32 0xD2801588 0xD4000001   // mov x8,172(sys_getpid); svc #0

////////////////////////////////////////////////////////////////
// §12  RISC-V 64-bit INSTRUCTIONS  (RV64I + C)
//     All base instructions are 32-bit LE.
//     Reference: RISC-V ISA Specification 20191213
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  Base instructions (4 bytes)
// ────────────────────────────────────────────────────────
#define RV_NOP                               EMIT u32 0x00000013   // addi x0, x0, 0  (canonical NOP)
#define RV_RET                               EMIT u32 0x00008067   // jalr x0, 0(x1)
#define RV_ECALL                             EMIT u32 0x00000073   // system call
#define RV_EBREAK                            EMIT u32 0x00100073   // breakpoint
#define RV_WFI                               EMIT u32 0x10500073   // wait for interrupt
#define RV_MRET                              EMIT u32 0x30200073   // machine-mode return
#define RV_SRET                              EMIT u32 0x10200073   // supervisor-mode return
#define RV_FENCE                             EMIT u32 0x0FF0000F   // full fence
#define RV_FENCE_I                           EMIT u32 0x0000100F   // instruction fence
#define RV_SFENCE_VMA                        EMIT u32 0x12000073   // TLB flush

// ────────────────────────────────────────────────────────
//  RVC compressed instructions (2 bytes)
// ────────────────────────────────────────────────────────
#define RVC_NOP                              EMIT u16 0x0001   // c.nop
#define RVC_RET                              EMIT u16 0x8082   // c.jr x1  (ret)
#define RVC_EBREAK                           EMIT u16 0x9002   // c.ebreak
#define RVC_NOP_B                            EMIT u16 0x0001

// ────────────────────────────────────────────────────────
//  Common Linux RV64 syscall numbers
// ────────────────────────────────────────────────────────
#define RV_SYS_IO_SETUP                      0
#define RV_SYS_IO_DESTROY                    1
#define RV_SYS_IO_SUBMIT                     2
#define RV_SYS_IO_CANCEL                     3
#define RV_SYS_IO_GETEVENTS                  4
#define RV_SYS_OPENAT                        56
#define RV_SYS_CLOSE                         57
#define RV_SYS_LSEEK                         62
#define RV_SYS_READ                          63
#define RV_SYS_WRITE                         64
#define RV_SYS_READV                         65
#define RV_SYS_WRITEV                        66
#define RV_SYS_PREAD64                       67
#define RV_SYS_PWRITE64                      68
#define RV_SYS_SENDFILE                      71
#define RV_SYS_PSELECT6                      72
#define RV_SYS_PPOLL                         73
#define RV_SYS_READLINKAT                    78
#define RV_SYS_FSTATAT                       79
#define RV_SYS_FSTAT                         80
#define RV_SYS_SYNC                          81
#define RV_SYS_FSYNC                         82
#define RV_SYS_FDATASYNC                     83
#define RV_SYS_TRUNCATE                      45
#define RV_SYS_FTRUNCATE                     46
#define RV_SYS_MKDIRAT                       34
#define RV_SYS_UNLINKAT                      35
#define RV_SYS_RENAMEAT                      38
#define RV_SYS_LINKAT                        37
#define RV_SYS_SYMLINKAT                     36
#define RV_SYS_FACCESSAT                     48
#define RV_SYS_CHDIR                         49
#define RV_SYS_FCHDIR                        50
#define RV_SYS_CHROOT                        51
#define RV_SYS_FCHMOD                        52
#define RV_SYS_FCHMODAT                      53
#define RV_SYS_FCHOWNAT                      54
#define RV_SYS_FCHOWN                        55
#define RV_SYS_GETCWD                        17
#define RV_SYS_GETDENTS64                    61
#define RV_SYS_FCNTL                         25
#define RV_SYS_IOCTL                         29
#define RV_SYS_FLOCK                         32
#define RV_SYS_MMAP                          222
#define RV_SYS_MUNMAP                        215
#define RV_SYS_MPROTECT                      226
#define RV_SYS_MREMAP                        216
#define RV_SYS_MADVISE                       233
#define RV_SYS_BRK                           214
#define RV_SYS_MLOCK                         228
#define RV_SYS_MUNLOCK                       229
#define RV_SYS_MLOCKALL                      230
#define RV_SYS_MUNLOCKALL                    231
#define RV_SYS_MINCORE                       232
#define RV_SYS_CLONE                         220
#define RV_SYS_EXECVE                        221
#define RV_SYS_WAIT4                         260
#define RV_SYS_EXIT                          93
#define RV_SYS_EXIT_GROUP                    94
#define RV_SYS_KILL                          129
#define RV_SYS_GETPID                        172
#define RV_SYS_GETPPID                       173
#define RV_SYS_GETUID                        174
#define RV_SYS_GETEUID                       175
#define RV_SYS_GETGID                        176
#define RV_SYS_GETEGID                       177
#define RV_SYS_GETTID                        178
#define RV_SYS_FUTEX                         98
#define RV_SYS_NANOSLEEP                     101
#define RV_SYS_CLOCK_GETTIME                 113
#define RV_SYS_CLOCK_SETTIME                 112
#define RV_SYS_CLOCK_NANOSLEEP               115
#define RV_SYS_TIMER_CREATE                  107
#define RV_SYS_TIMER_DELETE                  111
#define RV_SYS_SETITIMER                     103
#define RV_SYS_GETITIMER                     102
#define RV_SYS_ALARM                         105
#define RV_SYS_SIGACTION                     134
#define RV_SYS_SIGPROCMASK                   135
#define RV_SYS_SIGRETURN                     139
#define RV_SYS_RAISE                         128
#define RV_SYS_SIGPENDING                    136
#define RV_SYS_SIGSUSPEND                    133
#define RV_SYS_SOCKET                        198
#define RV_SYS_BIND                          200
#define RV_SYS_LISTEN                        201
#define RV_SYS_ACCEPT                        202
#define RV_SYS_CONNECT                       203
#define RV_SYS_GETSOCKNAME                   204
#define RV_SYS_GETPEERNAME                   205
#define RV_SYS_SENDTO                        206
#define RV_SYS_RECVFROM                      207
#define RV_SYS_SETSOCKOPT                    208
#define RV_SYS_GETSOCKOPT                    209
#define RV_SYS_SHUTDOWN                      210
#define RV_SYS_SENDMSG                       211
#define RV_SYS_RECVMSG                       212
#define RV_SYS_SOCKETPAIR                    199
#define RV_SYS_PIPE2                         59
#define RV_SYS_DUP                           23
#define RV_SYS_DUP3                          24
#define RV_SYS_SCHED_YIELD                   124
#define RV_SYS_SCHED_GETPARAM                121
#define RV_SYS_SCHED_SETPARAM                118
#define RV_SYS_SCHED_SETSCHEDULER            119
#define RV_SYS_SCHED_GETSCHEDULER            120
#define RV_SYS_SCHED_GETAFFINITY             123
#define RV_SYS_SCHED_SETAFFINITY             122
#define RV_SYS_PRCTL                         167
#define RV_SYS_ARCH_PRCTL                    0
#define RV_SYS_PTRACE                        117
#define RV_SYS_PROCESS_VM_READV              270
#define RV_SYS_MEMFD_CREATE                  279
#define RV_SYS_MMAP2                         0

////////////////////////////////////////////////////////////////
// §13  LINUX SYSCALLS — x86-64
//     Reference: linux/arch/x86/entry/syscalls/syscall_64.tbl
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  All ~335 x86-64 Linux syscall numbers
// ────────────────────────────────────────────────────────
#define SYS_MMAP2                            0

////////////////////////////////////////////////////////////////
// §14  LINUX SYSCALLS — AArch64
//     Reference: linux/arch/arm64/include/asm/unistd.h
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  All AArch64 Linux syscall numbers
// ────────────────────────────────────────────────────────
#define A64_SYS_MMAP2                        0

////////////////////////////////////////////////////////////////
// §15  LINUX SYSCALLS — RISC-V 64
//     (same ABI as AArch64 for most syscalls)
////////////////////////////////////////////////////////////////

// RV64 uses the same syscall numbers as AArch64 from §14.
// Alias them with RV_ prefix for clarity in RISC-V emit files.

#define RV_SYS_READ                          63
#define RV_SYS_WRITE                         64
#define RV_SYS_OPENAT                        56
#define RV_SYS_CLOSE                         57
#define RV_SYS_LSEEK                         62
#define RV_SYS_FSTAT                         80
#define RV_SYS_FSTATAT                       79
#define RV_SYS_READLINKAT                    78
#define RV_SYS_GETDENTS64                    61
#define RV_SYS_GETCWD                        17
#define RV_SYS_FCNTL                         25
#define RV_SYS_IOCTL                         29
#define RV_SYS_MMAP                          222
#define RV_SYS_MUNMAP                        215
#define RV_SYS_MPROTECT                      226
#define RV_SYS_BRK                           214
#define RV_SYS_MADVISE                       233
#define RV_SYS_MREMAP                        216
#define RV_SYS_CLONE                         220
#define RV_SYS_EXECVE                        221
#define RV_SYS_WAIT4                         260
#define RV_SYS_EXIT                          93
#define RV_SYS_EXIT_GROUP                    94
#define RV_SYS_KILL                          129
#define RV_SYS_TGKILL                        131
#define RV_SYS_TKILL                         130
#define RV_SYS_GETPID                        172
#define RV_SYS_GETPPID                       173
#define RV_SYS_GETTID                        178
#define RV_SYS_GETUID                        174
#define RV_SYS_GETEUID                       175
#define RV_SYS_GETGID                        176
#define RV_SYS_GETEGID                       177
#define RV_SYS_FUTEX                         98
#define RV_SYS_NANOSLEEP                     101
#define RV_SYS_CLOCK_GETTIME                 113
#define RV_SYS_CLOCK_NANOSLEEP               115
#define RV_SYS_SETITIMER                     103
#define RV_SYS_GETITIMER                     102
#define RV_SYS_RT_SIGACTION                  134
#define RV_SYS_RT_SIGPROCMASK                135
#define RV_SYS_RT_SIGRETURN                  139
#define RV_SYS_SIGALTSTACK                   132
#define RV_SYS_SOCKET                        198
#define RV_SYS_BIND                          200
#define RV_SYS_LISTEN                        201
#define RV_SYS_ACCEPT                        202
#define RV_SYS_ACCEPT4                       242
#define RV_SYS_CONNECT                       203
#define RV_SYS_GETSOCKNAME                   204
#define RV_SYS_GETPEERNAME                   205
#define RV_SYS_SENDTO                        206
#define RV_SYS_RECVFROM                      207
#define RV_SYS_SETSOCKOPT                    208
#define RV_SYS_GETSOCKOPT                    209
#define RV_SYS_SHUTDOWN                      210
#define RV_SYS_SENDMSG                       211
#define RV_SYS_RECVMSG                       212
#define RV_SYS_SOCKETPAIR                    199
#define RV_SYS_PIPE2                         59
#define RV_SYS_DUP                           23
#define RV_SYS_DUP3                          24
#define RV_SYS_EPOLL_CREATE1                 20
#define RV_SYS_EPOLL_CTL                     21
#define RV_SYS_EPOLL_PWAIT                   22
#define RV_SYS_EVENTFD2                      19
#define RV_SYS_TIMERFD_CREATE                85
#define RV_SYS_TIMERFD_SETTIME               86
#define RV_SYS_TIMERFD_GETTIME               87
#define RV_SYS_INOTIFY_INIT1                 26
#define RV_SYS_INOTIFY_ADD_WATCH             27
#define RV_SYS_INOTIFY_RM_WATCH              28
#define RV_SYS_PRCTL                         167
#define RV_SYS_PTRACE                        117
#define RV_SYS_MEMFD_CREATE                  279
#define RV_SYS_BPF                           280
#define RV_SYS_GETRANDOM                     278
#define RV_SYS_SECCOMP                       277
#define RV_SYS_PROCESS_VM_READV              270
#define RV_SYS_PROCESS_VM_WRITEV             271
#define RV_SYS_STATX                         291
#define RV_SYS_IO_URING_SETUP                425
#define RV_SYS_IO_URING_ENTER                426
#define RV_SYS_IO_URING_REGISTER             427
#define RV_SYS_CLONE3                        435
#define RV_SYS_OPENAT2                       437
#define RV_SYS_PIDFD_OPEN                    434
#define RV_SYS_COPY_FILE_RANGE               285

////////////////////////////////////////////////////////////////
// §16  macOS / BSD SYSCALLS — x86-64
//     Reference: xnu/bsd/kern/syscalls.master
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  macOS x86-64 syscall numbers (use syscall instruction)
// ────────────────────────────────────────────────────────
#define MACOS_SYS_COPY_FILE_RANGE            285

////////////////////////////////////////////////////////////////
// §17  WINDOWS NT NATIVE API SYSCALL NUMBERS
//     ⚠  These vary by Windows version! Numbers below are Windows 11 22H2.
//     Use NtCurrentTeb()->PEB→ntdll for runtime lookup in production.
////////////////////////////////////////////////////////////////

// ────────────────────────────────────────────────────────
//  NtXxx syscall numbers (Windows 11 22H2 / Server 2022)
// ────────────────────────────────────────────────────────
#define WINNT_SYS_NtAccessCheck              0
#define WINNT_SYS_NtWorkerFactoryWorkerReady 1
#define WINNT_SYS_NtAcceptConnectPort        2
#define WINNT_SYS_NtMapUserPhysicalPagesScatter 3
#define WINNT_SYS_NtWaitForSingleObject      4
#define WINNT_SYS_NtCallbackReturn           5
#define WINNT_SYS_NtReadFile                 6
#define WINNT_SYS_NtDeviceIoControlFile      7
#define WINNT_SYS_NtWriteFile                8
#define WINNT_SYS_NtRemoveIoCompletion       9
#define WINNT_SYS_NtReleaseSemaphore         10
#define WINNT_SYS_NtReplyWaitReceivePort     11
#define WINNT_SYS_NtReplyPort                12
#define WINNT_SYS_NtSetInformationThread     13
#define WINNT_SYS_NtSetEvent                 14
#define WINNT_SYS_NtClose                    15
#define WINNT_SYS_NtQueryObject              16
#define WINNT_SYS_NtQueryInformationFile     17
#define WINNT_SYS_NtOpenKey                  18
#define WINNT_SYS_NtEnumerateValueKey        19
#define WINNT_SYS_NtFindAtom                 20
#define WINNT_SYS_NtQueryDefaultLocale       21
#define WINNT_SYS_NtQueryKey                 22
#define WINNT_SYS_NtQueryValueKey            23
#define WINNT_SYS_NtAllocateVirtualMemory    24
#define WINNT_SYS_NtQueryInformationProcess  25
#define WINNT_SYS_NtWaitForMultipleObjects32 26
#define WINNT_SYS_NtWriteFileGather          27
#define WINNT_SYS_NtSetInformationProcess    28
#define WINNT_SYS_NtCreateKey                29
#define WINNT_SYS_NtFreeVirtualMemory        30
#define WINNT_SYS_NtImpersonateClientOfPort  31
#define WINNT_SYS_NtReleaseMutant            32
#define WINNT_SYS_NtQueryInformationToken    33
#define WINNT_SYS_NtRequestWaitReplyPort     34
#define WINNT_SYS_NtQueryVirtualMemory       35
#define WINNT_SYS_NtOpenThreadToken          36
#define WINNT_SYS_NtQueryInformationThread   37
#define WINNT_SYS_NtOpenProcess              38
#define WINNT_SYS_NtSetInformationFile       39
#define WINNT_SYS_NtMapViewOfSection         40
#define WINNT_SYS_NtAccessCheckAndAuditAlarm 41
#define WINNT_SYS_NtUnmapViewOfSection       42
#define WINNT_SYS_NtReplyWaitReceivePortEx   43
#define WINNT_SYS_NtTerminateProcess         44
#define WINNT_SYS_NtSetEventBoostPriority    45
#define WINNT_SYS_NtReadFileScatter          46
#define WINNT_SYS_NtOpenThreadTokenEx        47
#define WINNT_SYS_NtOpenProcessTokenEx       48
#define WINNT_SYS_NtQueryPerformanceCounter  49
#define WINNT_SYS_NtEnumerateKey             50
#define WINNT_SYS_NtOpenFile                 51
#define WINNT_SYS_NtDelayExecution           52
#define WINNT_SYS_NtQueryDirectoryFile       53
#define WINNT_SYS_NtQuerySystemInformation   54
#define WINNT_SYS_NtOpenSection              55
#define WINNT_SYS_NtQueryTimer               56
#define WINNT_SYS_NtFsControlFile            57
#define WINNT_SYS_NtWriteVirtualMemory       58
#define WINNT_SYS_NtCloseObjectAuditAlarm    59
#define WINNT_SYS_NtDuplicateObject          60
#define WINNT_SYS_NtQueryAttributesFile      61
#define WINNT_SYS_NtClearEvent               62
#define WINNT_SYS_NtReadVirtualMemory        63
#define WINNT_SYS_NtOpenEvent                64
#define WINNT_SYS_NtAdjustPrivilegesToken    65
#define WINNT_SYS_NtDuplicateToken           66
#define WINNT_SYS_NtContinue                 67

#endif // EMIT_DICTIONARY_H
