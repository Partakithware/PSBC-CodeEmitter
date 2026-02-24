import sys

lines = []
def s(line=""):
    lines.append(line)

def sec(title):
    s()
    s("/" * 64)
    s(f"// {title}")
    s("/" * 64)
    s()

def sub(title):
    s(f"// {'─' * 56}")
    s(f"//  {title}")
    s(f"// {'─' * 56}")

def d(name, body, comment=""):
    c = f"   // {comment}" if comment else ""
    s(f"#define {name:<36} {body}{c}")

# ── header ──────────────────────────────────────────────────
s("// " + "=" * 60)
s("//  emit_dictionary.h  —  The Emit Code Dictionary  v3.0")
s("//")
s("//  Replace every raw hex byte and opcode with a named macro.")
s("//  #include \"emit_dictionary.h\"  in your .emit file.")
s("//")
s("//  SECTIONS")
s("//  §01  Sizes, numeric constants, IEEE 754 specials")
s("//  §02  Padding & alignment")
s("//  §03  Text / encoding markers & ANSI escapes")
s("//  §04  ELF executable format (full field coverage)")
s("//  §05  PE/COFF Windows executable format")
s("//  §06  Mach-O macOS/iOS executable format")
s("//  §07  WebAssembly (all opcodes + section types)")
s("//  §08  JVM .class bytecode (all opcodes)")
s("//  §09  x86-64 instructions — complete coverage")
s("//       · Prefix-only macros (⚠ need operand follow-up)")
s("//       · Complete self-contained macros")
s("//       · All GPR push/pop, xor-zero, moves")
s("//       · Arithmetic, logic, shifts, rotate, bit ops")
s("//       · Conditionals: Jcc, CMOVcc, SETcc")
s("//       · String ops + REP/REPNE")
s("//       · Atomics: LOCK, XCHG, CMPXCHG, XADD")
s("//       · Memory fences, system/privileged")
s("//       · SSE2 / AVX2 common instructions")
s("//       · Complete Linux syscall sequences")
s("//  §10  x86-32 instructions")
s("//  §11  ARM64 / AArch64 instructions")
s("//  §12  RISC-V 64-bit instructions (RV64I + C)")
s("//  §13  Linux syscalls — x86-64  (all ~340)")
s("//  §14  Linux syscalls — AArch64")
s("//  §15  Linux syscalls — RISC-V 64")
s("//  §16  macOS/BSD syscalls — x86-64")
s("//  §17  Windows NT native API syscall numbers")
s("//  §18  Calling convention constants (SysV, Win64, ARM64)")
s("//  §19  Network: Ethernet, ARP, IP, TCP, UDP, ICMP, DNS, TLS, HTTP, DHCP")
s("//  §20  Filesystem: FAT32, ext4, NTFS, MBR, GPT")
s("//  §21  UEFI / ACPI / firmware")
s("//  §22  USB descriptors & PCI config space")
s("//  §23  Cryptography (SHA, MD5, AES, ChaCha20, ASN.1, OIDs)")
s("//  §24  CRC polynomials & hash magic constants")
s("//  §25  User presets")
s("// " + "=" * 60)
s()
s("#ifndef EMIT_DICTIONARY_H")
s("#define EMIT_DICTIONARY_H")

# ──────────────────────────────────────────────────────────────
sec("§01  SIZES, NUMERIC CONSTANTS, IEEE 754 SPECIALS")
d("KB",              "1024")
d("MB",              "(1024 * 1024)")
d("GB",              "(1024 * 1024 * 1024)")
d("PAGE_SIZE",       "4096")
d("HUGE_PAGE",       "(2 * 1024 * 1024)")
d("SECTOR_SIZE",     "512")
d("CACHE_LINE",      "64")
s()
sub("Bit masks")
d("MASK_U8",         "0xFF")
d("MASK_U16",        "0xFFFF")
d("MASK_U32",        "0xFFFFFFFF")
d("MASK_LO32",       "0x00000000FFFFFFFF")
d("MASK_HI32",       "0xFFFFFFFF00000000")
d("MASK_7BIT",       "0x7F")
d("MASK_LO4",        "0x0F")
d("MASK_HI4",        "0xF0")
s()
sub("Sentinel / debug-fill values")
d("DEAD_BEEF",       "0xDEADBEEF")
d("DEAD_C0DE",       "0xDEADC0DE")
d("CAFEBABE",        "0xCAFEBABE")
d("CAFED00D",        "0xCAFED00D")
d("FEEDFACE",        "0xFEEDFACE")
d("BAADF00D",        "0xBAADF00D")
d("CCCCCCCC",        "0xCCCCCCCC",  "MSVC uninitialised stack fill")
d("CDCDCDCD",        "0xCDCDCDCD",  "MSVC uninitialised heap fill")
d("FDFDFDFD",        "0xFDFDFDFD",  "MSVC guard byte (no-man's land)")
d("ABABABAB",        "0xABABABAB",  "MSVC freed heap fill")
s()
sub("IEEE 754 float32 specials (use as raw u32 constants)")
d("F32_POS_ZERO",    "0x00000000")
d("F32_NEG_ZERO",    "0x80000000")
d("F32_POS_INF",     "0x7F800000")
d("F32_NEG_INF",     "0xFF800000")
d("F32_QNAN",        "0x7FC00000")
d("F32_SNAN",        "0x7F800001")
d("F32_ONE",         "0x3F800000",  "1.0f")
d("F32_NEG_ONE",     "0xBF800000",  "-1.0f")
d("F32_HALF",        "0x3F000000",  "0.5f")
d("F32_TWO",         "0x40000000",  "2.0f")
d("F32_TEN",         "0x41200000",  "10.0f")
d("F32_PI",          "0x40490FDB",  "3.14159265f")
d("F32_TAU",         "0x40C90FDB",  "6.28318530f  (2*pi)")
d("F32_E",           "0x402DF854",  "2.71828182f")
d("F32_SQRT2",       "0x3FB504F3",  "1.41421356f")
d("F32_LN2",         "0x3F317218",  "0.69314718f")
d("F32_LOG2E",       "0x3FB8AA3B",  "1.44269504f")
d("F32_LOG10E",      "0x3EDE5BD9",  "0.43429448f")
d("F32_MAX",         "0x7F7FFFFF")
d("F32_MIN_NORMAL",  "0x00800000")
d("F32_EPSILON",     "0x34000000",  "~1.19e-7  (ulp of 1.0)")
s()
sub("IEEE 754 float64 specials (use as raw u64 constants)")
d("F64_POS_ZERO",    "0x0000000000000000")
d("F64_NEG_ZERO",    "0x8000000000000000")
d("F64_POS_INF",     "0x7FF0000000000000")
d("F64_NEG_INF",     "0xFFF0000000000000")
d("F64_QNAN",        "0x7FF8000000000000")
d("F64_ONE",         "0x3FF0000000000000",  "1.0")
d("F64_NEG_ONE",     "0xBFF0000000000000",  "-1.0")
d("F64_HALF",        "0x3FE0000000000000",  "0.5")
d("F64_PI",          "0x400921FB54442D18")
d("F64_TAU",         "0x401921FB54442D18",  "2*pi")
d("F64_E",           "0x4005BF0A8B145769")
d("F64_SQRT2",       "0x3FF6A09E667F3BCD")
d("F64_LN2",         "0x3FE62E42FEFA39EF")
d("F64_LOG2E",       "0x3FF71547652B82FE")
d("F64_MAX",         "0x7FEFFFFFFFFFFFFF")
d("F64_EPSILON",     "0x3CB0000000000000",  "~2.22e-16")

# ──────────────────────────────────────────────────────────────
sec("§02  PADDING & ALIGNMENT")
sub("Zero fills (exact byte counts)")
for n in [1,2,3,4,6,8,10,12,14,16,20,24,28,32,48,64,128,256,512]:
    d(f"ZERO_{n}", f"EMIT u8[{n}] 0x00")
s()
sub("0xFF fills")
for n in [1,2,4,8,16,32,64,128,256]:
    d(f"FF_{n}", f"EMIT u8[{n}] 0xFF")
s()
sub("0x90 NOP fills (code sections)")
for n in [4,8,16,32,64]:
    d(f"NOP_{n}", f"EMIT u8[{n}] 0x90")
s()
sub("0xCC INT3 fills (guard / uninitialised code)")
for n in [4,8,16,32]:
    d(f"CC_{n}", f"EMIT u8[{n}] 0xCC")
s()
sub("Align-to-boundary with zero fill")
for n in [2,4,8,16,32,64,128,256,512]:
    d(f"PAD_TO_{n}", f"ALIGN {n} 0x00")
d("PAD_TO_PAGE",     "ALIGN 4096 0x00")
d("PAD_TO_SECTOR",   "ALIGN 512  0x00")
d("PAD_TO_CACHELN",  "ALIGN 64   0x00")
s()
sub("Align-to-boundary with NOP fill (code sections)")
for n in [4,8,16,32,64]:
    d(f"CODE_ALIGN_{n}", f"ALIGN {n} 0x90")

# ──────────────────────────────────────────────────────────────
sec("§03  TEXT / ENCODING MARKERS & ANSI ESCAPES")
sub("Byte Order Marks")
d("UTF8_BOM",        "EMIT u8 0xEF 0xBB 0xBF")
d("UTF16_LE_BOM",    "EMIT u8 0xFF 0xFE")
d("UTF16_BE_BOM",    "EMIT u8 0xFE 0xFF")
d("UTF32_LE_BOM",    "EMIT u8 0xFF 0xFE 0x00 0x00")
d("UTF32_BE_BOM",    "EMIT u8 0x00 0x00 0xFE 0xFF")
s()
sub("Line endings & common control chars")
d("CRLF",           "EMIT u8 0x0D 0x0A",  "Windows")
d("LF",             "EMIT u8 0x0A",        "Unix")
d("CR",             "EMIT u8 0x0D",        "old Mac")
d("TAB",            "EMIT u8 0x09")
d("NULL_TERM",      "EMIT u8 0x00")
d("ASCII_BEL",      "EMIT u8 0x07")
d("ASCII_BS",       "EMIT u8 0x08")
d("ASCII_ESC",      "EMIT u8 0x1B")
d("ASCII_DEL",      "EMIT u8 0x7F")
d("ASCII_SPACE",    "EMIT u8 0x20")
s()
sub("ANSI VT100 / VT220 escape sequences")
d("ANSI_RESET",     "EMIT u8 0x1B 0x5B 0x30 0x6D")
d("ANSI_BOLD",      "EMIT u8 0x1B 0x5B 0x31 0x6D")
d("ANSI_DIM",       "EMIT u8 0x1B 0x5B 0x32 0x6D")
d("ANSI_ITALIC",    "EMIT u8 0x1B 0x5B 0x33 0x6D")
d("ANSI_UNDERLINE", "EMIT u8 0x1B 0x5B 0x34 0x6D")
d("ANSI_BLINK",     "EMIT u8 0x1B 0x5B 0x35 0x6D")
d("ANSI_REVERSE",   "EMIT u8 0x1B 0x5B 0x37 0x6D")
d("ANSI_STRIKE",    "EMIT u8 0x1B 0x5B 0x39 0x6D")
for name,n in [("BLACK",30),("RED",31),("GREEN",32),("YELLOW",33),
               ("BLUE",34),("MAGENTA",35),("CYAN",36),("WHITE",37),
               ("DEFAULT",39)]:
    hi = str(n).encode()
    nb = " ".join(f"0x{b:02X}" for b in (f"\x1b[{n}m").encode())
    d(f"ANSI_{name}",    f"EMIT u8 {nb}")
for name,n in [("BLACK",40),("RED",41),("GREEN",42),("YELLOW",43),
               ("BLUE",44),("MAGENTA",45),("CYAN",46),("WHITE",47)]:
    nb = " ".join(f"0x{b:02X}" for b in (f"\x1b[{n}m").encode())
    d(f"ANSI_BG_{name}", f"EMIT u8 {nb}")
for name,seq in [("CLR_SCREEN","2J"),("CLR_LINE","2K"),("HOME","H"),
                 ("CURSOR_UP","A"),("CURSOR_DN","B"),("CURSOR_RT","C"),
                 ("CURSOR_LT","D"),("SAVE_CUR","s"),("REST_CUR","u"),
                 ("HIDE_CUR","?25l"),("SHOW_CUR","?25h")]:
    nb = " ".join(f"0x{b:02X}" for b in (f"\x1b[{seq}").encode())
    d(f"ANSI_{name}",    f"EMIT u8 {nb}")

# ──────────────────────────────────────────────────────────────
sec("§04  ELF — Executable and Linkable Format\n//     Reference: System V ABI + linux/elf.h")
sub("e_ident (16-byte identification block)")
d("ELF_MAGIC",       "EMIT u8 0x7F 0x45 0x4C 0x46",  "\\x7FELF")
d("ELF64_IDENT",     "EMIT u8 0x7F 0x45 0x4C 0x46 0x02 0x01 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00", "64-bit LE Linux")
d("ELF32_IDENT",     "EMIT u8 0x7F 0x45 0x4C 0x46 0x01 0x01 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00", "32-bit LE Linux")
d("ELF64_IDENT_BSD", "EMIT u8 0x7F 0x45 0x4C 0x46 0x02 0x01 0x01 0x09 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00", "64-bit LE FreeBSD")
d("ELF64_IDENT_BE",  "EMIT u8 0x7F 0x45 0x4C 0x46 0x02 0x02 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00", "64-bit BE")
s()
sub("EI_CLASS")
d("ELFCLASS32",      "0x01")
d("ELFCLASS64",      "0x02")
sub("EI_DATA")
d("ELFDATA2LSB",     "0x01",  "little-endian")
d("ELFDATA2MSB",     "0x02",  "big-endian")
sub("EI_OSABI")
for name,val in [("NONE",0),("HPUX",1),("NETBSD",2),("LINUX",3),
                 ("SOLARIS",6),("AIX",7),("IRIX",8),("FREEBSD",9),
                 ("TRU64",10),("OPENBSD",12),("ARM",0x61),("STANDALONE",0xFF)]:
    d(f"ELFOSABI_{name}", f"0x{val:02X}")
s()
sub("e_type")
for name,val in [("NONE",0),("REL",1),("EXEC",2),("DYN",3),("CORE",4)]:
    d(f"ELF_ET_{name}", f"EMIT u16 0x{val:04X}")
s()
sub("e_machine")
for name,val in [("NONE",0),("M32",1),("SPARC",2),("386",3),("68K",4),
                 ("MIPS",8),("MIPS_RS3_LE",10),("PPC",20),("PPC64",21),
                 ("S390",22),("ARM",0x28),("SH",0x2A),("SPARCV9",0x2B),
                 ("IA64",0x32),("X86_64",0x3E),("VAX",0x4B),
                 ("AVR",0x53),("AARCH64",0xB7),("RISCV",0xF3),
                 ("BPF",0xF7),("LOONGARCH",0x102)]:
    d(f"ELF_EM_{name}", f"EMIT u16 0x{val:04X}")
s()
sub("e_version")
d("ELF_EV_CURRENT",  "EMIT u32 0x00000001")
s()
sub("Header sizes (u16)")
d("ELF64_EHSIZE",    "EMIT u16 64",  "sizeof(Elf64_Ehdr)")
d("ELF64_PHENTSIZE", "EMIT u16 56",  "sizeof(Elf64_Phdr)")
d("ELF64_SHENTSIZE", "EMIT u16 64",  "sizeof(Elf64_Shdr)")
d("ELF32_EHSIZE",    "EMIT u16 52")
d("ELF32_PHENTSIZE", "EMIT u16 32")
d("ELF32_SHENTSIZE", "EMIT u16 40")
s()
sub("p_type values")
for name,val in [("NULL",0),("LOAD",1),("DYNAMIC",2),("INTERP",3),
                 ("NOTE",4),("SHLIB",5),("PHDR",6),("TLS",7),
                 ("GNU_EH_FRAME",0x6474E550),("GNU_STACK",0x6474E551),
                 ("GNU_RELRO",0x6474E552),("GNU_PROPERTY",0x6474E553)]:
    d(f"PT_{name}", f"0x{val:08X}")
s()
sub("p_flags  (combine with |)")
d("PF_X",           "0x00000001",  "execute")
d("PF_W",           "0x00000002",  "write")
d("PF_R",           "0x00000004",  "read")
s()
sub("Complete PT_LOAD program header prefix  (p_type u32 + p_flags u32)")
d("ELF_PHDR_LOAD_RX",  "EMIT u32 0x00000001 0x00000005",  "code segment")
d("ELF_PHDR_LOAD_RW",  "EMIT u32 0x00000001 0x00000006",  "data segment")
d("ELF_PHDR_LOAD_R",   "EMIT u32 0x00000001 0x00000004",  "read-only data")
d("ELF_PHDR_LOAD_RWX", "EMIT u32 0x00000001 0x00000007",  "rwx (avoid in production)")
s()
sub("sh_type values")
for name,val in [("NULL",0),("PROGBITS",1),("SYMTAB",2),("STRTAB",3),
                 ("RELA",4),("HASH",5),("DYNAMIC",6),("NOTE",7),
                 ("NOBITS",8),("REL",9),("SHLIB",10),("DYNSYM",11),
                 ("INIT_ARRAY",14),("FINI_ARRAY",15),("PREINIT_ARRAY",16),
                 ("GROUP",17),("SYMTAB_SHNDX",18)]:
    d(f"SHT_{name}", f"0x{val:08X}")
s()
sub("sh_flags  (combine with |)")
for name,val,comm in [("WRITE",1,"writable"),("ALLOC",2,"occupies memory"),
                      ("EXECINSTR",4,"executable"),("MERGE",0x10,"mergeable"),
                      ("STRINGS",0x20,"string table"),("INFO_LINK",0x40,"sh_info is link"),
                      ("LINK_ORDER",0x80,"order after link"),("TLS",0x400,"thread-local")]:
    d(f"SHF_{name}", f"0x{val:08X}", comm)
d("SHF_AX",   "0x00000006",  "ALLOC+EXECINSTR (.text)")
d("SHF_WA",   "0x00000003",  "WRITE+ALLOC (.data)")
d("SHF_A",    "0x00000002",  "ALLOC only (.rodata)")
s()
sub("d_tag values (dynamic section)")
for name,val in [("NULL",0),("NEEDED",1),("PLTRELSZ",2),("PLTGOT",3),
                 ("HASH",4),("STRTAB",5),("SYMTAB",6),("RELA",7),
                 ("RELASZ",8),("RELAENT",9),("STRSZ",10),("SYMENT",11),
                 ("INIT",12),("FINI",13),("SONAME",14),("RPATH",15),
                 ("SYMBOLIC",16),("REL",17),("RELSZ",18),("RELENT",19),
                 ("PLTREL",20),("DEBUG",21),("TEXTREL",22),("JMPREL",23),
                 ("BIND_NOW",24),("INIT_ARRAY",25),("FINI_ARRAY",26),
                 ("INIT_ARRAYSZ",27),("FINI_ARRAYSZ",28),("RUNPATH",29),
                 ("FLAGS",30),("PREINIT_ARRAY",32),("PREINIT_ARRAYSZ",33),
                 ("FLAGS_1",0x6FFFFFFB),("VERSYM",0x6FFFFFF0),
                 ("VERDEF",0x6FFFFFFC),("VERDEFNUM",0x6FFFFFFD),
                 ("VERNEED",0x6FFFFFFE),("VERNEEDNUM",0x6FFFFFFF)]:
    d(f"DT_{name}", f"0x{val:08X}")
s()
sub("Symbol binding (STB) & type (STT)")
for name,val in [("LOCAL",0),("GLOBAL",1),("WEAK",2),("GNU_UNIQUE",10)]:
    d(f"STB_{name}", str(val))
for name,val in [("NOTYPE",0),("OBJECT",1),("FUNC",2),("SECTION",3),
                 ("FILE",4),("COMMON",5),("TLS",6),("GNU_IFUNC",10)]:
    d(f"STT_{name}", str(val))
s()
sub("x86-64 relocation types (R_X86_64_*)")
for name,val in [("NONE",0),("64",1),("PC32",2),("GOT32",3),("PLT32",4),
                 ("COPY",5),("GLOB_DAT",6),("JUMP_SLOT",7),("RELATIVE",8),
                 ("GOTPCREL",9),("32",10),("32S",11),("16",12),("PC16",13),
                 ("8",14),("PC8",15),("DTPMOD64",16),("DTPOFF64",17),
                 ("TPOFF64",18),("TLSGD",19),("TLSLD",20),("DTPOFF32",21),
                 ("GOTTPOFF",22),("TPOFF32",23),("PC64",24),("GOTOFF64",25),
                 ("GOTPC32",26),("SIZE32",32),("SIZE64",33),("IRELATIVE",37)]:
    d(f"R_X86_64_{name}", str(val))
s()
sub("AArch64 relocation types (R_AARCH64_*)")
for name,val in [("NONE",0),("ABS64",257),("ABS32",258),("ABS16",259),
                 ("PREL64",260),("PREL32",261),("PREL16",262),
                 ("MOVW_UABS_G0",263),("MOVW_UABS_G1",265),("MOVW_UABS_G2",267),
                 ("MOVW_UABS_G3",269),("CALL26",283),("JUMP26",282),
                 ("GLOB_DAT",1025),("JUMP_SLOT",1026),("RELATIVE",1027),
                 ("COPY",1024),("TLSDESC",1031),("IRELATIVE",1032)]:
    d(f"R_AARCH64_{name}", str(val))
s()
sub("Common Linux ELF interpreter paths (null-terminated)")
# /lib64/ld-linux-x86-64.so.2\0
interp_x64 = "/lib64/ld-linux-x86-64.so.2\x00"
nb = " ".join(f"0x{ord(c):02X}" for c in interp_x64)
d("ELF_INTERP_X64",  f"EMIT u8 {nb}")
# /lib/ld-linux-aarch64.so.1\0
interp_a64 = "/lib/ld-linux-aarch64.so.1\x00"
nb = " ".join(f"0x{ord(c):02X}" for c in interp_a64)
d("ELF_INTERP_AARCH64", f"EMIT u8 {nb}")
# /lib/ld-musl-x86_64.so.1\0
interp_musl = "/lib/ld-musl-x86_64.so.1\x00"
nb = " ".join(f"0x{ord(c):02X}" for c in interp_musl)
d("ELF_INTERP_MUSL_X64", f"EMIT u8 {nb}")

# ──────────────────────────────────────────────────────────────
sec("§05  PE/COFF — Windows Portable Executable\n//     Reference: Microsoft PE/COFF Specification")
sub("DOS header")
d("PE_DOS_MAGIC",    "EMIT u8 0x4D 0x5A",  "MZ signature")
# minimal 64-byte MZ stub with e_lfanew=0x40
stub = [0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,
        0x04,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,
        0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00]
nb = " ".join(f"0x{b:02X}" for b in stub)
d("PE_DOS_STUB",     f"EMIT u8 {nb}", "64-byte MZ stub, e_lfanew=0x40")
d("PE_SIGNATURE",    "EMIT u8 0x50 0x45 0x00 0x00",  "PE\\0\\0")
s()
sub("Machine types (u16 LE)")
for name,val in [("UNKNOWN",0),("X86",0x014C),("ALPHA",0x0184),
                 ("ARM",0x01C0),("ARMNT",0x01C4),("ARM64",0xAA64),
                 ("EBC",0x0EBC),("X64",0x8664),("IA64",0x0200),
                 ("LOONGARCH32",0x6232),("LOONGARCH64",0x6264),
                 ("M32R",0x9041),("MIPS16",0x0266),("MIPSF41",0x0366),
                 ("POWERPC",0x01F0),("R4000",0x0166),("RISCV32",0x5032),
                 ("RISCV64",0x5064),("RISCV128",0x5128),
                 ("SH3",0x01A2),("SH4",0x01A6),("THUMB",0x01C2),
                 ("WCEMIPS",0x0169)]:
    d(f"PE_MACHINE_{name}", f"EMIT u16 0x{val:04X}")
s()
sub("COFF Characteristics flags")
for name,val,comm in [
    ("RELOCS_STRIPPED",0x0001,"relocs removed"),
    ("EXECUTABLE",0x0002,"image is executable"),
    ("LINE_NUMS_STRIPPED",0x0004,""),
    ("LOCAL_SYMS_STRIPPED",0x0008,""),
    ("AGGRESSIVE_WS_TRIM",0x0010,"obsolete"),
    ("LARGE_ADDRESS_AWARE",0x0020,">2GB addresses"),
    ("BYTES_REVERSED_LO",0x0080,"obsolete"),
    ("32BIT_MACHINE",0x0100,""),
    ("DEBUG_STRIPPED",0x0200,""),
    ("REMOVABLE_RUN_FROM_SWAP",0x0400,""),
    ("NET_RUN_FROM_SWAP",0x0800,""),
    ("SYSTEM",0x1000,"system file"),
    ("DLL",0x2000,"DLL"),
    ("UP_SYSTEM_ONLY",0x4000,"uni-processor only"),
    ("BYTES_REVERSED_HI",0x8000,"obsolete")]:
    d(f"PE_CHAR_{name}", f"0x{val:04X}", comm)
d("PE_CHARS_EXE64",  "EMIT u16 0x0022",  "typical 64-bit exe")
d("PE_CHARS_EXE32",  "EMIT u16 0x0102",  "typical 32-bit exe")
d("PE_CHARS_DLL64",  "EMIT u16 0x2022",  "typical 64-bit DLL")
s()
sub("Optional header magic")
d("PE_OPT_PE32",     "EMIT u16 0x010B",  "32-bit image")
d("PE_OPT_PE32PLUS", "EMIT u16 0x020B",  "64-bit image")
d("PE_OPT_ROM",      "EMIT u16 0x0107",  "ROM image")
s()
sub("Subsystem values (u16)")
for name,val in [("UNKNOWN",0),("NATIVE",1),("WINDOWS_GUI",2),
                 ("WINDOWS_CUI",3),("OS2_CUI",5),("POSIX_CUI",7),
                 ("NATIVE_WINDOWS",8),("WINDOWS_CE_GUI",9),
                 ("EFI_APPLICATION",10),("EFI_BOOT_SERVICE_DRIVER",11),
                 ("EFI_RUNTIME_DRIVER",12),("EFI_ROM",13),("XBOX",14),
                 ("WINDOWS_BOOT_APPLICATION",16)]:
    d(f"PE_SUBSYS_{name}", f"EMIT u16 0x{val:04X}")
s()
sub("DLL Characteristics flags (u16)")
for name,val,comm in [
    ("HIGH_ENTROPY_VA",0x0020,"ASLR with 64-bit VA"),
    ("DYNAMIC_BASE",0x0040,"ASLR"),
    ("FORCE_INTEGRITY",0x0080,"code integrity checks"),
    ("NX_COMPAT",0x0100,"DEP compatible"),
    ("NO_ISOLATION",0x0200,"do not isolate"),
    ("NO_SEH",0x0400,"no structured exception handling"),
    ("NO_BIND",0x0800,"do not bind"),
    ("APPCONTAINER",0x1000,"must run in appcontainer"),
    ("WDM_DRIVER",0x2000,"WDM driver"),
    ("GUARD_CF",0x4000,"Control Flow Guard"),
    ("TERMINAL_SERVER_AWARE",0x8000,"")]:
    d(f"PE_DLLCHAR_{name}", f"0x{val:04X}", comm)
d("PE_DLLCHARS_MODERN", "EMIT u16 0x8160", "NX+ASLR+HIGH_ENTROPY+TERMINAL_AWARE")
s()
sub("Section characteristics flags")
for name,val in [
    ("CNT_CODE",0x20),("CNT_INIT_DATA",0x40),("CNT_UNINIT_DATA",0x80),
    ("LNK_INFO",0x200),("LNK_REMOVE",0x800),("LNK_COMDAT",0x1000),
    ("GPREL",0x8000),("MEM_PURGEABLE",0x20000),
    ("MEM_16BIT",0x20000),("MEM_LOCKED",0x40000),("MEM_PRELOAD",0x80000),
    ("ALIGN_1BYTES",0x100000),("ALIGN_2BYTES",0x200000),
    ("ALIGN_4BYTES",0x300000),("ALIGN_8BYTES",0x400000),
    ("ALIGN_16BYTES",0x500000),("ALIGN_32BYTES",0x600000),
    ("ALIGN_64BYTES",0x700000),("ALIGN_128BYTES",0x800000),
    ("ALIGN_256BYTES",0x900000),("ALIGN_512BYTES",0xA00000),
    ("ALIGN_1024BYTES",0xB00000),("ALIGN_2048BYTES",0xC00000),
    ("ALIGN_4096BYTES",0xD00000),("ALIGN_8192BYTES",0xE00000),
    ("LNK_NRELOC_OVFL",0x1000000),("MEM_DISCARDABLE",0x2000000),
    ("MEM_NOT_CACHED",0x4000000),("MEM_NOT_PAGED",0x8000000),
    ("MEM_SHARED",0x10000000),("MEM_EXECUTE",0x20000000),
    ("MEM_READ",0x40000000),("MEM_WRITE",0x80000000)]:
    d(f"PE_SCN_{name}", f"0x{val:08X}")
s()
sub("Combined section flags (emit as u32)")
d("PE_TEXT_FLAGS",   "EMIT u32 0x60000020",  ".text: code+exec+read")
d("PE_DATA_FLAGS",   "EMIT u32 0xC0000040",  ".data: init_data+read+write")
d("PE_RDATA_FLAGS",  "EMIT u32 0x40000040",  ".rdata: init_data+read")
d("PE_BSS_FLAGS",    "EMIT u32 0xC0000080",  ".bss: uninit+read+write")
d("PE_RSRC_FLAGS",   "EMIT u32 0x40000040",  ".rsrc: init_data+read")
d("PE_RELOC_FLAGS",  "EMIT u32 0x42000040",  ".reloc: discardable+init_data+read")
s()
sub("Section names (8-byte zero-padded ASCII)")
for sname,sval in [("TEXT",".text"),("DATA",".data"),("RDATA",".rdata"),
                   ("BSS",".bss"),("IDATA",".idata"),("EDATA",".edata"),
                   ("RSRC",".rsrc"),("RELOC",".reloc"),("PDATA",".pdata"),
                   ("XDATA",".xdata"),("TLS",".tls"),("DEBUG",".debug"),
                   ("DIDAT",".didat"),("CRT",".CRT")]:
    padded = (sval + "\0"*8)[:8]
    nb = " ".join(f"0x{ord(c):02X}" for c in padded)
    d(f"PE_SECTION_{sname}", f"EMIT u8 {nb}")
s()
sub("Data directory indices")
for name,val in [("EXPORT",0),("IMPORT",1),("RESOURCE",2),("EXCEPTION",3),
                 ("SECURITY",4),("BASERELOC",5),("DEBUG",6),("COPYRIGHT",7),
                 ("GLOBALPTR",8),("TLS",9),("LOAD_CONFIG",10),
                 ("BOUND_IMPORT",11),("IAT",12),("DELAY_IMPORT",13),
                 ("COM_DESCRIPTOR",14)]:
    d(f"PE_DD_{name}", str(val))
s()
sub("Base relocation types")
for name,val in [("ABSOLUTE",0),("HIGH",1),("LOW",2),("HIGHLOW",3),
                 ("HIGHADJ",4),("MIPS_JMPADDR",5),("ARM_MOV32",5),
                 ("RISCV_HIGH20",5),("THUMB_MOV32",7),("RISCV_LOW12I",7),
                 ("RISCV_LOW12S",8),("MIPS_JMPADDR16",9),("DIR64",10)]:
    d(f"IMAGE_REL_BASED_{name}", str(val))

# ──────────────────────────────────────────────────────────────
sec("§06  MACH-O — macOS / iOS / watchOS\n//     Reference: <mach-o/loader.h>")
sub("Magic numbers")
d("MACHO_MAGIC32",   "EMIT u32 0xFEEDFACE",  "32-bit LE")
d("MACHO_MAGIC64",   "EMIT u32 0xFEEDFACF",  "64-bit LE")
d("MACHO_CIGAM32",   "EMIT u32 0xCEFAEDFE",  "32-bit BE")
d("MACHO_CIGAM64",   "EMIT u32 0xCFFAEDFE",  "64-bit BE")
d("MACHO_FAT_MAGIC", "EMIT u32 0xCAFEBABE",  "universal/fat binary")
d("MACHO_FAT_CIGAM", "EMIT u32 0xBEBAFECA")
s()
sub("CPU type + subtype pairs (cputype u32, cpusubtype u32)")
d("MACHO_CPU_X86",      "EMIT u32 0x00000007 0x00000003")
d("MACHO_CPU_X86_64",   "EMIT u32 0x01000007 0x00000003")
d("MACHO_CPU_ARM",      "EMIT u32 0x0000000C 0x00000000")
d("MACHO_CPU_ARM64",    "EMIT u32 0x0100000C 0x00000000")
d("MACHO_CPU_ARM64E",   "EMIT u32 0x0100000C 0x80000002")
d("MACHO_CPU_PPC",      "EMIT u32 0x00000012 0x00000000")
d("MACHO_CPU_PPC64",    "EMIT u32 0x01000012 0x00000000")
s()
sub("File types (mach_header.filetype)")
for name,val in [("OBJECT",1),("EXECUTE",2),("FVMLIB",3),("CORE",4),
                 ("PRELOAD",5),("DYLIB",6),("DYLINKER",7),("BUNDLE",8),
                 ("DYLIB_STUB",9),("DSYM",10),("KEXT_BUNDLE",11),
                 ("FILESET",12)]:
    d(f"MACHO_MH_{name}", f"0x{val:08X}")
s()
sub("Header flags (mach_header.flags  — combine with |)")
for name,val,comm in [
    ("NOUNDEFS",0x1,"no undefined refs"),
    ("INCRLINK",0x2,"incremental link"),
    ("DYLDLINK",0x4,"input to dyld"),
    ("BINDATLOAD",0x8,""),
    ("PREBOUND",0x10,""),
    ("SPLIT_SEGS",0x20,""),
    ("LAZY_INIT",0x40,""),
    ("TWOLEVEL",0x80,"two-level namespace"),
    ("FORCE_FLAT",0x100,""),
    ("NOMULTIDEFS",0x200,""),
    ("NOFIXPREBINDING",0x400,""),
    ("PREBINDABLE",0x800,""),
    ("ALLMODSBOUND",0x1000,""),
    ("SUBSECTIONS_VIA_SYMBOLS",0x2000,""),
    ("CANONICAL",0x4000,""),
    ("WEAK_DEFINES",0x8000,""),
    ("BINDS_TO_WEAK",0x10000,""),
    ("ALLOW_STACK_EXECUTION",0x20000,""),
    ("ROOT_SAFE",0x40000,""),
    ("SETUID_SAFE",0x80000,""),
    ("NO_REEXPORTED_DYLIBS",0x100000,""),
    ("PIE",0x200000,"ASLR"),
    ("DEAD_STRIPPABLE_DYLIB",0x400000,""),
    ("HAS_TLV_DESCRIPTORS",0x800000,""),
    ("NO_HEAP_EXECUTION",0x1000000,"")]:
    d(f"MACHO_MH_{name}", f"0x{val:08X}", comm)
d("MACHO_FLAGS_EXE_PIE",  "0x00200085",  "typical PIE executable")
d("MACHO_FLAGS_DYLIB",    "0x00000085",  "typical dylib")
s()
sub("Load command types (LC_*)")
lc_list = [
    ("SEGMENT",1),("SYMTAB",2),("SYMSEG",3),("THREAD",4),("UNIXTHREAD",5),
    ("LOADFVMLIB",6),("IDFVMLIB",7),("IDENT",8),("FVMFILE",9),("PREPAGE",10),
    ("DYSYMTAB",11),("LOAD_DYLIB",12),("ID_DYLIB",13),("LOAD_DYLINKER",14),
    ("ID_DYLINKER",15),("PREBOUND_DYLIB",16),("ROUTINES",17),("SUB_FRAMEWORK",18),
    ("SUB_UMBRELLA",19),("SUB_CLIENT",20),("SUB_LIBRARY",21),("TWOLEVEL_HINTS",22),
    ("PREBIND_CKSUM",23),("SEGMENT_64",0x19),("ROUTINES_64",0x1A),("UUID",0x1B),
    ("RPATH",0x8000001C),("CODE_SIGNATURE",0x1D),("SEGMENT_SPLIT_INFO",0x1E),
    ("REEXPORT_DYLIB",0x8000001F),("LAZY_LOAD_DYLIB",0x20),("ENCRYPTION_INFO",0x21),
    ("DYLD_INFO",0x22),("DYLD_INFO_ONLY",0x80000022),("LOAD_UPWARD_DYLIB",0x80000023),
    ("VERSION_MIN_MACOSX",0x24),("VERSION_MIN_IPHONEOS",0x25),
    ("FUNCTION_STARTS",0x26),("DYLD_ENVIRONMENT",0x27),("MAIN",0x80000028),
    ("DATA_IN_CODE",0x29),("SOURCE_VERSION",0x2A),("DYLIB_CODE_SIGN_DRS",0x2B),
    ("ENCRYPTION_INFO_64",0x2C),("LINKER_OPTION",0x2D),("LINKER_OPTIMIZATION_HINT",0x2E),
    ("VERSION_MIN_TVOS",0x2F),("VERSION_MIN_WATCHOS",0x30),("NOTE",0x31),
    ("BUILD_VERSION",0x32),("DYLD_EXPORTS_TRIE",0x80000033),
    ("DYLD_CHAINED_FIXUPS",0x80000034),("FILESET_ENTRY",0x80000035)]
name, val = lc_list[-1] if False else (name,val)
for name,val in lc_list:
    d(f"LC_{name}", f"0x{val:08X}")
s()
sub("VM protection flags (vm_prot_t — combine with |)")
d("VM_PROT_NONE",   "0x00")
d("VM_PROT_READ",   "0x01")
d("VM_PROT_WRITE",  "0x02")
d("VM_PROT_EXEC",   "0x04")
d("VM_PROT_RX",     "0x05")
d("VM_PROT_RW",     "0x03")
d("VM_PROT_RWX",    "0x07")
s()
sub("Common segment names (16-byte zero-padded ASCII)")
for sname,sval in [("TEXT","__TEXT"),("DATA","__DATA"),
                   ("DATA_CONST","__DATA_CONST"),
                   ("LINKEDIT","__LINKEDIT"),("PAGEZERO","__PAGEZERO")]:
    padded = (sval + "\0"*16)[:16]
    nb = " ".join(f"0x{ord(c):02X}" for c in padded)
    d(f"MACHO_SEG_{sname}", f"EMIT u8 {nb}")
s()
sub("Common section names (16-byte zero-padded ASCII)")
for sname,sval in [("TEXT","__text"),("STUBS","__stubs"),
                   ("STUB_HELPER","__stub_helper"),("DATA","__data"),
                   ("BSS","__bss"),("CONST","__const"),("CSTRING","__cstring"),
                   ("OBJC_METHNAMES","__objc_methnames"),
                   ("UNWIND_INFO","__unwind_info"),
                   ("EH_FRAME","__eh_frame"),("CFSTRING","__cfstring"),
                   ("GOT","__got"),("LA_SYMBOL_PTR","__la_symbol_ptr"),
                   ("NL_SYMBOL_PTR","__nl_symbol_ptr")]:
    padded = (sval + "\0"*16)[:16]
    nb = " ".join(f"0x{ord(c):02X}" for c in padded)
    d(f"MACHO_SECT_{sname}", f"EMIT u8 {nb}")

# ──────────────────────────────────────────────────────────────
sec("§07  WEBASSEMBLY — All opcodes, section IDs, value types\n//     Reference: WebAssembly Core Specification 2.0")
sub("Module header")
d("WASM_MAGIC",      "EMIT u8 0x00 0x61 0x73 0x6D",  "\\0asm")
d("WASM_VERSION",    "EMIT u8 0x01 0x00 0x00 0x00")
d("WASM_HEADER",     "EMIT u8 0x00 0x61 0x73 0x6D 0x01 0x00 0x00 0x00")
s()
sub("Section IDs")
for name,val in [("CUSTOM",0),("TYPE",1),("IMPORT",2),("FUNCTION",3),
                 ("TABLE",4),("MEMORY",5),("GLOBAL",6),("EXPORT",7),
                 ("START",8),("ELEMENT",9),("CODE",10),("DATA",11),
                 ("DATA_COUNT",12),("TAG",13)]:
    d(f"WASM_SEC_{name}", f"EMIT u8 0x{val:02X}")
s()
sub("Value types (LEB128-encoded)")
d("WASM_I32",        "0x7F")
d("WASM_I64",        "0x7E")
d("WASM_F32",        "0x7D")
d("WASM_F64",        "0x7C")
d("WASM_V128",       "0x7B")
d("WASM_FUNCREF",    "0x70")
d("WASM_EXTERNREF",  "0x6F")
d("WASM_VOID",       "0x40",  "block type: empty")
s()
sub("Import/export external kinds")
d("WASM_EXT_FUNC",   "0x00")
d("WASM_EXT_TABLE",  "0x01")
d("WASM_EXT_MEM",    "0x02")
d("WASM_EXT_GLOBAL", "0x03")
d("WASM_EXT_TAG",    "0x04")
s()
sub("Global mutability")
d("WASM_CONST",      "0x00")
d("WASM_MUT",        "0x01")
s()
sub("Numeric opcodes (single byte)")
wasm_ops = [
    ("UNREACHABLE",0x00),("NOP",0x01),("BLOCK",0x02),("LOOP",0x03),
    ("IF",0x04),("ELSE",0x05),("TRY",0x06),("CATCH",0x07),
    ("THROW",0x08),("RETHROW",0x09),("END",0x0B),("BR",0x0C),
    ("BR_IF",0x0D),("BR_TABLE",0x0E),("RETURN",0x0F),("CALL",0x10),
    ("CALL_INDIRECT",0x11),("RETURN_CALL",0x12),("RETURN_CALL_INDIRECT",0x13),
    ("CALL_REF",0x14),("RETURN_CALL_REF",0x15),("DROP",0x1A),
    ("SELECT",0x1B),("SELECT_T",0x1C),
    ("LOCAL_GET",0x20),("LOCAL_SET",0x21),("LOCAL_TEE",0x22),
    ("GLOBAL_GET",0x23),("GLOBAL_SET",0x24),
    ("TABLE_GET",0x25),("TABLE_SET",0x26),
    ("I32_LOAD",0x28),("I64_LOAD",0x29),("F32_LOAD",0x2A),("F64_LOAD",0x2B),
    ("I32_LOAD8_S",0x2C),("I32_LOAD8_U",0x2D),("I32_LOAD16_S",0x2E),("I32_LOAD16_U",0x2F),
    ("I64_LOAD8_S",0x30),("I64_LOAD8_U",0x31),("I64_LOAD16_S",0x32),("I64_LOAD16_U",0x33),
    ("I64_LOAD32_S",0x34),("I64_LOAD32_U",0x35),
    ("I32_STORE",0x36),("I64_STORE",0x37),("F32_STORE",0x38),("F64_STORE",0x39),
    ("I32_STORE8",0x3A),("I32_STORE16",0x3B),("I64_STORE8",0x3C),
    ("I64_STORE16",0x3D),("I64_STORE32",0x3E),
    ("MEMORY_SIZE",0x3F),("MEMORY_GROW",0x40),
    ("I32_CONST",0x41),("I64_CONST",0x42),("F32_CONST",0x43),("F64_CONST",0x44),
    ("I32_EQZ",0x45),("I32_EQ",0x46),("I32_NE",0x47),
    ("I32_LT_S",0x48),("I32_LT_U",0x49),("I32_GT_S",0x4A),("I32_GT_U",0x4B),
    ("I32_LE_S",0x4C),("I32_LE_U",0x4D),("I32_GE_S",0x4E),("I32_GE_U",0x4F),
    ("I64_EQZ",0x50),("I64_EQ",0x51),("I64_NE",0x52),
    ("I64_LT_S",0x53),("I64_LT_U",0x54),("I64_GT_S",0x55),("I64_GT_U",0x56),
    ("I64_LE_S",0x57),("I64_LE_U",0x58),("I64_GE_S",0x59),("I64_GE_U",0x5A),
    ("F32_EQ",0x5B),("F32_NE",0x5C),("F32_LT",0x5D),("F32_GT",0x5E),
    ("F32_LE",0x5F),("F32_GE",0x60),
    ("F64_EQ",0x61),("F64_NE",0x62),("F64_LT",0x63),("F64_GT",0x64),
    ("F64_LE",0x65),("F64_GE",0x66),
    ("I32_CLZ",0x67),("I32_CTZ",0x68),("I32_POPCNT",0x69),
    ("I32_ADD",0x6A),("I32_SUB",0x6B),("I32_MUL",0x6C),
    ("I32_DIV_S",0x6D),("I32_DIV_U",0x6E),("I32_REM_S",0x6F),("I32_REM_U",0x70),
    ("I32_AND",0x71),("I32_OR",0x72),("I32_XOR",0x73),
    ("I32_SHL",0x74),("I32_SHR_S",0x75),("I32_SHR_U",0x76),
    ("I32_ROTL",0x77),("I32_ROTR",0x78),
    ("I64_CLZ",0x79),("I64_CTZ",0x7A),("I64_POPCNT",0x7B),
    ("I64_ADD",0x7C),("I64_SUB",0x7D),("I64_MUL",0x7E),
    ("I64_DIV_S",0x7F),("I64_DIV_U",0x80),("I64_REM_S",0x81),("I64_REM_U",0x82),
    ("I64_AND",0x83),("I64_OR",0x84),("I64_XOR",0x85),
    ("I64_SHL",0x86),("I64_SHR_S",0x87),("I64_SHR_U",0x88),
    ("I64_ROTL",0x89),("I64_ROTR",0x8A),
    ("F32_ABS",0x8B),("F32_NEG",0x8C),("F32_CEIL",0x8D),("F32_FLOOR",0x8E),
    ("F32_TRUNC",0x8F),("F32_NEAREST",0x90),("F32_SQRT",0x91),
    ("F32_ADD",0x92),("F32_SUB",0x93),("F32_MUL",0x94),("F32_DIV",0x95),
    ("F32_MIN",0x96),("F32_MAX",0x97),("F32_COPYSIGN",0x98),
    ("F64_ABS",0x99),("F64_NEG",0x9A),("F64_CEIL",0x9B),("F64_FLOOR",0x9C),
    ("F64_TRUNC",0x9D),("F64_NEAREST",0x9E),("F64_SQRT",0x9F),
    ("F64_ADD",0xA0),("F64_SUB",0xA1),("F64_MUL",0xA2),("F64_DIV",0xA3),
    ("F64_MIN",0xA4),("F64_MAX",0xA5),("F64_COPYSIGN",0xA6),
    ("I32_WRAP_I64",0xA7),("I32_TRUNC_F32_S",0xA8),("I32_TRUNC_F32_U",0xA9),
    ("I32_TRUNC_F64_S",0xAA),("I32_TRUNC_F64_U",0xAB),
    ("I64_EXTEND_I32_S",0xAC),("I64_EXTEND_I32_U",0xAD),
    ("I64_TRUNC_F32_S",0xAE),("I64_TRUNC_F32_U",0xAF),
    ("I64_TRUNC_F64_S",0xB0),("I64_TRUNC_F64_U",0xB1),
    ("F32_CONVERT_I32_S",0xB2),("F32_CONVERT_I32_U",0xB3),
    ("F32_CONVERT_I64_S",0xB4),("F32_CONVERT_I64_U",0xB5),
    ("F32_DEMOTE_F64",0xB6),("F64_CONVERT_I32_S",0xB7),("F64_CONVERT_I32_U",0xB8),
    ("F64_CONVERT_I64_S",0xB9),("F64_CONVERT_I64_U",0xBA),
    ("F64_PROMOTE_F32",0xBB),
    ("I32_REINTERPRET_F32",0xBC),("I64_REINTERPRET_F64",0xBD),
    ("F32_REINTERPRET_I32",0xBE),("F64_REINTERPRET_I64",0xBF),
    ("I32_EXTEND8_S",0xC0),("I32_EXTEND16_S",0xC1),
    ("I64_EXTEND8_S",0xC2),("I64_EXTEND16_S",0xC3),("I64_EXTEND32_S",0xC4),
    ("REF_NULL",0xD0),("REF_IS_NULL",0xD1),("REF_FUNC",0xD2),
    ("REF_EQ",0xD3),("REF_AS_NON_NULL",0xD4),("BR_ON_NULL",0xD5),
    ("BR_ON_NON_NULL",0xD6),
]
for name,val in wasm_ops:
    d(f"WASM_{name}", f"EMIT u8 0x{val:02X}")

# ──────────────────────────────────────────────────────────────
sec("§08  JVM .class BYTECODE — All opcodes\n//     Reference: JVM Specification SE 21")
sub("class file magic")
d("CLASS_MAGIC",     "EMIT u8 0xCA 0xFE 0xBA 0xBE")
for name,val in [("JAVA8",52),("JAVA11",55),("JAVA17",61),("JAVA21",65)]:
    d(f"CLASS_VER_{name}", f"EMIT u16 0x{val:04X}")
d("CLASS_MINOR_0",   "EMIT u16 0x0000")
d("CLASS_MINOR_PREVIEW","EMIT u16 0xFFFF")
s()
sub("Constant pool tags")
for name,val in [("UTF8",1),("INTEGER",3),("FLOAT",4),("LONG",5),("DOUBLE",6),
                 ("CLASS",7),("STRING",8),("FIELDREF",9),("METHODREF",10),
                 ("INTERFACE_METHODREF",11),("NAME_AND_TYPE",12),
                 ("METHOD_HANDLE",15),("METHOD_TYPE",16),("DYNAMIC",17),
                 ("INVOKE_DYNAMIC",18),("MODULE",19),("PACKAGE",20)]:
    d(f"CP_{name}", str(val))
s()
sub("Access flags (class, field, method)")
for name,val in [("PUBLIC",0x0001),("PRIVATE",0x0002),("PROTECTED",0x0004),
                 ("STATIC",0x0008),("FINAL",0x0010),("SUPER",0x0020),
                 ("SYNCHRONIZED",0x0020),("VOLATILE",0x0040),("BRIDGE",0x0040),
                 ("TRANSIENT",0x0080),("VARARGS",0x0080),("NATIVE",0x0100),
                 ("INTERFACE",0x0200),("ABSTRACT",0x0400),("STRICT",0x0800),
                 ("SYNTHETIC",0x1000),("ANNOTATION",0x2000),("ENUM",0x4000),
                 ("MODULE",0x8000)]:
    d(f"ACC_{name}", f"0x{val:04X}")
s()
sub("JVM opcodes (all 202)")
jvm_ops = [
    ("NOP",0),("ACONST_NULL",1),("ICONST_M1",2),("ICONST_0",3),("ICONST_1",4),
    ("ICONST_2",5),("ICONST_3",6),("ICONST_4",7),("ICONST_5",8),
    ("LCONST_0",9),("LCONST_1",10),("FCONST_0",11),("FCONST_1",12),("FCONST_2",13),
    ("DCONST_0",14),("DCONST_1",15),("BIPUSH",16),("SIPUSH",17),
    ("LDC",18),("LDC_W",19),("LDC2_W",20),
    ("ILOAD",21),("LLOAD",22),("FLOAD",23),("DLOAD",24),("ALOAD",25),
    ("ILOAD_0",26),("ILOAD_1",27),("ILOAD_2",28),("ILOAD_3",29),
    ("LLOAD_0",30),("LLOAD_1",31),("LLOAD_2",32),("LLOAD_3",33),
    ("FLOAD_0",34),("FLOAD_1",35),("FLOAD_2",36),("FLOAD_3",37),
    ("DLOAD_0",38),("DLOAD_1",39),("DLOAD_2",40),("DLOAD_3",41),
    ("ALOAD_0",42),("ALOAD_1",43),("ALOAD_2",44),("ALOAD_3",45),
    ("IALOAD",46),("LALOAD",47),("FALOAD",48),("DALOAD",49),("AALOAD",50),
    ("BALOAD",51),("CALOAD",52),("SALOAD",53),
    ("ISTORE",54),("LSTORE",55),("FSTORE",56),("DSTORE",57),("ASTORE",58),
    ("ISTORE_0",59),("ISTORE_1",60),("ISTORE_2",61),("ISTORE_3",62),
    ("LSTORE_0",63),("LSTORE_1",64),("LSTORE_2",65),("LSTORE_3",66),
    ("FSTORE_0",67),("FSTORE_1",68),("FSTORE_2",69),("FSTORE_3",70),
    ("DSTORE_0",71),("DSTORE_1",72),("DSTORE_2",73),("DSTORE_3",74),
    ("ASTORE_0",75),("ASTORE_1",76),("ASTORE_2",77),("ASTORE_3",78),
    ("IASTORE",79),("LASTORE",80),("FASTORE",81),("DASTORE",82),("AASTORE",83),
    ("BASTORE",84),("CASTORE",85),("SASTORE",86),
    ("POP",87),("POP2",88),("DUP",89),("DUP_X1",90),("DUP_X2",91),
    ("DUP2",92),("DUP2_X1",93),("DUP2_X2",94),("SWAP",95),
    ("IADD",96),("LADD",97),("FADD",98),("DADD",99),
    ("ISUB",100),("LSUB",101),("FSUB",102),("DSUB",103),
    ("IMUL",104),("LMUL",105),("FMUL",106),("DMUL",107),
    ("IDIV",108),("LDIV",109),("FDIV",110),("DDIV",111),
    ("IREM",112),("LREM",113),("FREM",114),("DREM",115),
    ("INEG",116),("LNEG",117),("FNEG",118),("DNEG",119),
    ("ISHL",120),("LSHL",121),("ISHR",122),("LSHR",123),("IUSHR",124),("LUSHR",125),
    ("IAND",126),("LAND",127),("IOR",128),("LOR",129),("IXOR",130),("LXOR",131),
    ("IINC",132),
    ("I2L",133),("I2F",134),("I2D",135),("L2I",136),("L2F",137),("L2D",138),
    ("F2I",139),("F2L",140),("F2D",141),("D2I",142),("D2L",143),("D2F",144),
    ("I2B",145),("I2C",146),("I2S",147),
    ("LCMP",148),("FCMPL",149),("FCMPG",150),("DCMPL",151),("DCMPG",152),
    ("IFEQ",153),("IFNE",154),("IFLT",155),("IFGE",156),("IFGT",157),("IFLE",158),
    ("IF_ICMPEQ",159),("IF_ICMPNE",160),("IF_ICMPLT",161),("IF_ICMPGE",162),
    ("IF_ICMPGT",163),("IF_ICMPLE",164),("IF_ACMPEQ",165),("IF_ACMPNE",166),
    ("GOTO",167),("JSR",168),("RET",169),("TABLESWITCH",170),("LOOKUPSWITCH",171),
    ("IRETURN",172),("LRETURN",173),("FRETURN",174),("DRETURN",175),
    ("ARETURN",176),("RETURN",177),
    ("GETSTATIC",178),("PUTSTATIC",179),("GETFIELD",180),("PUTFIELD",181),
    ("INVOKEVIRTUAL",182),("INVOKESPECIAL",183),("INVOKESTATIC",184),
    ("INVOKEINTERFACE",185),("INVOKEDYNAMIC",186),
    ("NEW",187),("NEWARRAY",188),("ANEWARRAY",189),("ARRAYLENGTH",190),
    ("ATHROW",191),("CHECKCAST",192),("INSTANCEOF",193),
    ("MONITORENTER",194),("MONITOREXIT",195),
    ("WIDE",196),("MULTIANEWARRAY",197),
    ("IFNULL",198),("IFNONNULL",199),("GOTO_W",200),("JSR_W",201),
]
for name,val in jvm_ops:
    d(f"JVM_{name}", f"EMIT u8 0x{val:02X}")
s()
sub("newarray type codes (used with NEWARRAY opcode)")
for name,val in [("BOOLEAN",4),("CHAR",5),("FLOAT",6),("DOUBLE",7),
                 ("BYTE",8),("SHORT",9),("INT",10),("LONG",11)]:
    d(f"JVM_ATYPE_{name}", str(val))

# ──────────────────────────────────────────────────────────────
sec("§09  x86-64 INSTRUCTIONS — COMPLETE COVERAGE\n//\n//  Two families of macros:\n//    PREFIX  macros — emit opcode bytes only\n//                    ⚠ MUST be followed by the operand emit\n//    COMPLETE macros — self-contained, correct instruction\n//\n//  Register encoding:\n//    RAX=0  RCX=1  RDX=2  RBX=3  RSP=4  RBP=5  RSI=6  RDI=7\n//    R8=8   R9=9   R10=10 R11=11 R12=12 R13=13 R14=14 R15=15")

sub("Simple / single-byte instructions")
for name,enc,comm in [
    ("NOP",       "0x90",                "no operation"),
    ("RET",       "0xC3",                "near return"),
    ("RET_FAR",   "0xCB",                "far return"),
    ("INT3",      "0xCC",                "breakpoint"),
    ("INT1",      "0xF1",                "ICEBP"),
    ("HLT",       "0xF4",                "halt — CPL 0 only"),
    ("CLI",       "0xFA",                "clear interrupt flag"),
    ("STI",       "0xFB",                "set interrupt flag"),
    ("CLD",       "0xFC",                "clear direction flag"),
    ("STD",       "0xFD",                "set direction flag"),
    ("CLC",       "0xF8",                "clear carry"),
    ("STC",       "0xF9",                "set carry"),
    ("CMC",       "0xF5",                "complement carry"),
    ("LAHF",      "0x9F",                "load AH ← flags"),
    ("SAHF",      "0x9E",                "store AH → flags"),
    ("PUSHFQ",    "0x9C",                "push RFLAGS"),
    ("POPFQ",     "0x9D",                "pop RFLAGS"),
    ("LEAVE",     "0xC9",                "mov rsp,rbp; pop rbp"),
    ("CLTS",      "0x0F 0x06",           "clear TS flag in CR0"),
    ("INVD",      "0x0F 0x08",           "invalidate caches"),
    ("WBINVD",    "0x0F 0x09",           "writeback+invalidate"),
    ("UD2",       "0x0F 0x0B",           "guaranteed illegal instruction"),
    ("CDQE",      "0x48 0x98",           "sign-extend EAX→RAX"),
    ("CQO",       "0x48 0x99",           "sign-extend RAX into RDX:RAX"),
    ("IRETQ",     "0x48 0xCF",           "interrupt return (64-bit)"),
    ("SYSCALL",   "0x0F 0x05",           "fast user→kernel call"),
    ("SYSRET",    "0x0F 0x07",           "fast kernel→user return"),
    ("SYSENTER",  "0x0F 0x34",           "fast system call (32-bit style)"),
    ("SYSEXIT",   "0x0F 0x35",           ""),
    ("CPUID",     "0x0F 0xA2",           "CPU identification"),
    ("RDTSC",     "0x0F 0x31",           "read time-stamp counter → EDX:EAX"),
    ("RDTSCP",    "0x0F 0x01 0xF9",      "read TSC + IA32_TSC_AUX → ECX"),
    ("RDMSR",     "0x0F 0x32",           "read MSR(ECX) → EDX:EAX"),
    ("WRMSR",     "0x0F 0x30",           "write EDX:EAX → MSR(ECX)"),
    ("RDPMC",     "0x0F 0x33",           "read performance counter"),
    ("PAUSE",     "0xF3 0x90",           "spin-loop hint"),
    ("LOCK",      "0xF0",                "atomic prefix"),
    ("REP",       "0xF3",                "repeat string prefix"),
    ("REPNE",     "0xF2",                "repeat-not-equal prefix"),
    ("MFENCE",    "0x0F 0xAE 0xF0",     "full memory fence"),
    ("SFENCE",    "0x0F 0xAE 0xF8",     "store fence"),
    ("LFENCE",    "0x0F 0xAE 0xE8",     "load fence"),
]:
    nb = " ".join(f"0x{b}" if b.startswith("0x") else b for b in enc.split())
    d(f"X64_{name}", f"EMIT u8 {enc}", comm)
s()
sub("String / memory operations")
for name,enc,comm in [
    ("MOVSB","0xA4","mov byte [rdi]←[rsi]; rsi++; rdi++"),
    ("MOVSW","0x66 0xA5","mov word"),
    ("MOVSD","0xA5","mov dword"),
    ("MOVSQ","0x48 0xA5","mov qword (REX.W)"),
    ("STOSB","0xAA","store AL→[rdi]; rdi++"),
    ("STOSW","0x66 0xAB","store AX"),
    ("STOSD","0xAB","store EAX"),
    ("STOSQ","0x48 0xAB","store RAX (REX.W)"),
    ("LODSB","0xAC","load [rsi]→AL; rsi++"),
    ("LODSQ","0x48 0xAD","load [rsi]→RAX"),
    ("SCASB","0xAE","compare AL with [rdi]; rdi++"),
    ("SCASQ","0x48 0xAF","compare RAX with [rdi]"),
    ("CMPSB","0xA6","compare [rsi] with [rdi]"),
    ("CMPSQ","0x48 0xA7","compare qword"),
    ("REP_MOVSB","0xF3 0xA4","memcpy (byte)"),
    ("REP_MOVSQ","0xF3 0x48 0xA5","memcpy (qword, RCX times)"),
    ("REP_STOSB","0xF3 0xAA","memset (byte)"),
    ("REP_STOSQ","0xF3 0x48 0xAB","memset (qword)"),
    ("REPNE_SCASB","0xF2 0xAE","strlen pattern: scan for 0 in [rdi]"),
    ("REPNE_SCASQ","0xF2 0x48 0xAF","scan qword"),
]:
    d(f"X64_{name}", f"EMIT u8 {enc}", comm)
s()
sub("PUSH / POP — all GPRs")
gpr64 = [("RAX",0x50),("RCX",0x51),("RDX",0x52),("RBX",0x53),
         ("RSP",0x54),("RBP",0x55),("RSI",0x56),("RDI",0x57)]
for reg,base in gpr64:
    d(f"X64_PUSH_{reg}", f"EMIT u8 0x{base:02X}")
for ext,base in [("R8",0x50),("R9",0x51),("R10",0x52),("R11",0x53),
                 ("R12",0x54),("R13",0x55),("R14",0x56),("R15",0x57)]:
    d(f"X64_PUSH_{ext}", f"EMIT u8 0x41 0x{base:02X}")
for reg,base in gpr64:
    d(f"X64_POP_{reg}", f"EMIT u8 0x{base+8:02X}")
for ext,base in [("R8",0x58),("R9",0x59),("R10",0x5A),("R11",0x5B),
                 ("R12",0x5C),("R13",0x5D),("R14",0x5E),("R15",0x5F)]:
    d(f"X64_POP_{ext}", f"EMIT u8 0x41 0x{base:02X}")
s()
sub("MOV reg, imm64  ⚠ follow with EMIT u64 <val>  (10 bytes total)")
for reg,hi,lo in [("RAX",0x48,0xB8),("RCX",0x48,0xB9),("RDX",0x48,0xBA),
                  ("RBX",0x48,0xBB),("RSP",0x48,0xBC),("RBP",0x48,0xBD),
                  ("RSI",0x48,0xBE),("RDI",0x48,0xBF)]:
    d(f"X64_MOV_{reg}", f"EMIT u8 0x{hi:02X} 0x{lo:02X}")
for reg,hi,lo in [("R8",0x49,0xB8),("R9",0x49,0xB9),("R10",0x49,0xBA),
                  ("R11",0x49,0xBB),("R12",0x49,0xBC),("R13",0x49,0xBD),
                  ("R14",0x49,0xBE),("R15",0x49,0xBF)]:
    d(f"X64_MOV_{reg}", f"EMIT u8 0x{hi:02X} 0x{lo:02X}")
s()
sub("MOV reg, imm32 sign-extended  ⚠ follow with EMIT u32 <val>  (7 bytes total)")
for reg,modrm in [("RAX",0xC0),("RCX",0xC1),("RDX",0xC2),("RBX",0xC3),
                  ("RSP",0xC4),("RBP",0xC5),("RSI",0xC6),("RDI",0xC7)]:
    d(f"X64_MOV_{reg}32", f"EMIT u8 0x48 0xC7 0x{modrm:02X}")
s()
sub("Complete MOV reg, small_constant  (7 bytes, self-contained)")
# RAX
for n in list(range(0,16)) + [17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,
                               39,40,41,42,43,44,56,57,58,59,60,61,62,
                               100,101,200,201,202,231,232,233,234,235,
                               257,258,259,260,262,266,273,274,275,281,290,
                               302,303,304,305,306,307,308,309,310,311,312,
                               313,314,315,316,317,318,319,320,321,322,323,
                               324,325,326,327,328,329,330,331,332,333,334,335,
                               401,402,403,404,405,406,407,408,409,410]:
    v4 = n.to_bytes(4, 'little')
    nb = " ".join(f"0x{b:02X}" for b in v4)
    d(f"X64_RAX_{n}", f"EMIT u8 0x48 0xC7 0xC0 {nb}")
s()
# RDI (first arg)
for n in list(range(0,8)) + [10,16,17,100,200]:
    v4 = n.to_bytes(4, 'little')
    nb = " ".join(f"0x{b:02X}" for b in v4)
    d(f"X64_RDI_{n}", f"EMIT u8 0x48 0xC7 0xC7 {nb}")
s()
# RSI (second arg)
for n in list(range(0,8)):
    v4 = n.to_bytes(4, 'little')
    nb = " ".join(f"0x{b:02X}" for b in v4)
    d(f"X64_RSI_{n}", f"EMIT u8 0x48 0xC7 0xC6 {nb}")
s()
# RDX (third arg)
for n in list(range(0,8)) + [16,32,64,128,256,512,1024,4096]:
    v4 = n.to_bytes(4, 'little')
    nb = " ".join(f"0x{b:02X}" for b in v4)
    d(f"X64_RDX_{n}", f"EMIT u8 0x48 0xC7 0xC2 {nb}")
s()
# RCX, R8, R9 (Windows calling convention args)
for n in list(range(0,8)):
    v4 = n.to_bytes(4, 'little')
    nb = " ".join(f"0x{b:02X}" for b in v4)
    d(f"X64_RCX_{n}", f"EMIT u8 0x48 0xC7 0xC1 {nb}")
s()
sub("XOR to zero register  (use 32-bit form = 2 bytes, implicitly zeroes 64-bit)")
for reg,modrm in [("EAX",0xC0),("ECX",0xC9),("EDX",0xD2),("EBX",0xDB),
                  ("ESI",0xF6),("EDI",0xFF)]:
    d(f"X64_XOR_{reg}", f"EMIT u8 0x31 0x{modrm:02X}", f"zeroes R{reg[1:]}")
for reg,enc in [("RAX","0x48 0x31 0xC0"),("RCX","0x48 0x31 0xC9"),
                ("RDX","0x48 0x31 0xD2"),("RBX","0x48 0x31 0xDB"),
                ("RSI","0x48 0x31 0xF6"),("RDI","0x48 0x31 0xFF"),
                ("R8", "0x4D 0x31 0xC0"),("R9", "0x4D 0x31 0xC9"),
                ("R10","0x4D 0x31 0xD2"),("R11","0x4D 0x31 0xDB"),
                ("R12","0x4D 0x31 0xE4"),("R13","0x4D 0x31 0xED"),
                ("R14","0x4D 0x31 0xF6"),("R15","0x4D 0x31 0xFF")]:
    d(f"X64_XOR_{reg}", f"EMIT u8 {enc}",  "REX.W form (3 bytes)")
s()
sub("Register-to-register MOV  (REX.W 89 /r, 3 bytes)")
r2r = [
    ("RAX_RCX","0xC8"),("RAX_RDX","0xD0"),("RAX_RBX","0xD8"),
    ("RAX_RSI","0xF0"),("RAX_RDI","0xF8"),("RAX_R8",""),
    ("RCX_RAX","0xC1"),("RCX_RDX","0xD1"),("RCX_RBX","0xD9"),
    ("RDX_RAX","0xC2"),("RDX_RCX","0xCA"),("RDX_RBX","0xDA"),
    ("RBX_RAX","0xC3"),("RBX_RCX","0xCB"),("RBX_RDX","0xD3"),
    ("RSI_RAX","0xC6"),("RSI_RCX","0xCE"),("RSI_RDX","0xD6"),
    ("RDI_RAX","0xC7"),("RDI_RCX","0xCF"),("RDI_RDX","0xD7"),
    ("RDI_RSI","0xF7"),("RSI_RDI","0xFE"),
    ("RBP_RSP","0xE5"),("RSP_RBP","0xEC"),
    ("RDX_RCX","0xD1"),("RCX_RDX","0xCA"),
]
for pair,modrm in r2r:
    if not modrm: continue
    d(f"X64_MOV_{pair}", f"EMIT u8 0x48 0x89 {modrm}")
s()
sub("Stack frame helpers")
d("X64_FRAME_ENTER",   "EMIT u8 0x55 0x48 0x89 0xE5",  "push rbp; mov rbp, rsp")
d("X64_FRAME_LEAVE",   "EMIT u8 0x5D 0xC3",             "pop rbp; ret")
d("X64_LEAVE_ONLY",    "EMIT u8 0xC9",                  "leave  (mov rsp,rbp; pop rbp)")
d("X64_SUB_RSP_IMM8",  "EMIT u8 0x48 0x83 0xEC",        "⚠ follow with EMIT u8 <n>")
d("X64_ADD_RSP_IMM8",  "EMIT u8 0x48 0x83 0xC4",        "⚠ follow with EMIT u8 <n>")
d("X64_SUB_RSP_IMM32", "EMIT u8 0x48 0x81 0xEC",        "⚠ follow with EMIT u32 <n>")
d("X64_ADD_RSP_IMM32", "EMIT u8 0x48 0x81 0xC4",        "⚠ follow with EMIT u32 <n>")
d("X64_SHADOW_32",     "EMIT u8 0x48 0x83 0xEC 0x20",   "sub rsp,32  (Win64 shadow space)")
d("X64_SHADOW_32_RET", "EMIT u8 0x48 0x83 0xC4 0x20",   "add rsp,32")
d("X64_ALIGN16",       "EMIT u8 0x48 0x83 0xE4 0xF0",   "and rsp,-16  (16-byte align)")
s()
sub("Arithmetic — reg/reg (3 bytes each)")
alu3 = [
    ("ADD_RAX_RCX","0x48 0x01 0xC8"),("ADD_RAX_RDX","0x48 0x01 0xD0"),
    ("ADD_RAX_RBX","0x48 0x01 0xD8"),("ADD_RAX_RSI","0x48 0x01 0xF0"),
    ("ADD_RAX_RDI","0x48 0x01 0xF8"),
    ("ADD_RCX_RDX","0x48 0x01 0xD1"),("ADD_RDX_RCX","0x48 0x01 0xCA"),
    ("SUB_RAX_RCX","0x48 0x29 0xC8"),("SUB_RAX_RDX","0x48 0x29 0xD0"),
    ("SUB_RAX_RBX","0x48 0x29 0xD8"),
    ("SUB_RCX_RDX","0x48 0x29 0xD1"),("SUB_RDX_RCX","0x48 0x29 0xCA"),
    ("AND_RAX_RCX","0x48 0x21 0xC8"),("AND_RAX_RDX","0x48 0x21 0xD0"),
    ("AND_RCX_RDX","0x48 0x21 0xD1"),
    ("OR_RAX_RCX", "0x48 0x09 0xC8"),("OR_RAX_RDX", "0x48 0x09 0xD0"),
    ("OR_RCX_RDX", "0x48 0x09 0xD1"),
    ("XOR_RAX_RCX","0x48 0x31 0xC8"),("XOR_RAX_RDX","0x48 0x31 0xD0"),
    ("XOR_RCX_RDX","0x48 0x31 0xD1"),
    ("NEG_RAX",    "0x48 0xF7 0xD8"),("NEG_RCX",    "0x48 0xF7 0xD9"),
    ("NEG_RDX",    "0x48 0xF7 0xDA"),("NEG_RBX",    "0x48 0xF7 0xDB"),
    ("NOT_RAX",    "0x48 0xF7 0xD0"),("NOT_RCX",    "0x48 0xF7 0xD1"),
    ("INC_RAX",    "0x48 0xFF 0xC0"),("INC_RCX",    "0x48 0xFF 0xC1"),
    ("INC_RDX",    "0x48 0xFF 0xC2"),("INC_RBX",    "0x48 0xFF 0xC3"),
    ("INC_RSI",    "0x48 0xFF 0xC6"),("INC_RDI",    "0x48 0xFF 0xC7"),
    ("DEC_RAX",    "0x48 0xFF 0xC8"),("DEC_RCX",    "0x48 0xFF 0xC9"),
    ("DEC_RDX",    "0x48 0xFF 0xCA"),("DEC_RBX",    "0x48 0xFF 0xCB"),
    ("DEC_RSI",    "0x48 0xFF 0xCE"),("DEC_RDI",    "0x48 0xFF 0xCF"),
    ("IMUL_RAX_RCX","0x48 0x0F 0xAF 0xC1"),("IMUL_RAX_RDX","0x48 0x0F 0xAF 0xC2"),
    ("IMUL_RAX_RBX","0x48 0x0F 0xAF 0xC3"),("IMUL_RCX_RDX","0x48 0x0F 0xAF 0xCA"),
    ("IMUL_RDX_RCX","0x48 0x0F 0xAF 0xD1"),
    ("MUL_RCX",    "0x48 0xF7 0xE1",),("MUL_RBX",   "0x48 0xF7 0xE3"),
    ("DIV_RCX",    "0x48 0xF7 0xF1"),("DIV_RBX",    "0x48 0xF7 0xF3"),
    ("IDIV_RCX",   "0x48 0xF7 0xF9"),("IDIV_RBX",   "0x48 0xF7 0xFB"),
]
for name,enc in alu3:
    d(f"X64_{name}", f"EMIT u8 {enc}")
s()
sub("Arithmetic with imm8  ⚠ follow with EMIT u8 <n>")
alu_imm8 = [
    ("ADD_RAX_IMM8","0x48 0x83 0xC0"),("ADD_RCX_IMM8","0x48 0x83 0xC1"),
    ("ADD_RDX_IMM8","0x48 0x83 0xC2"),("ADD_RBX_IMM8","0x48 0x83 0xC3"),
    ("ADD_RSI_IMM8","0x48 0x83 0xC6"),("ADD_RDI_IMM8","0x48 0x83 0xC7"),
    ("SUB_RAX_IMM8","0x48 0x83 0xE8"),("SUB_RCX_IMM8","0x48 0x83 0xE9"),
    ("SUB_RDX_IMM8","0x48 0x83 0xEA"),("SUB_RBX_IMM8","0x48 0x83 0xEB"),
    ("AND_RAX_IMM8","0x48 0x83 0xE0"),("AND_RCX_IMM8","0x48 0x83 0xE1"),
    ("OR_RAX_IMM8", "0x48 0x83 0xC8"),("OR_RCX_IMM8", "0x48 0x83 0xC9"),
    ("XOR_RAX_IMM8","0x48 0x83 0xF0"),("XOR_RCX_IMM8","0x48 0x83 0xF1"),
    ("CMP_RAX_IMM8","0x48 0x83 0xF8"),("CMP_RCX_IMM8","0x48 0x83 0xF9"),
    ("CMP_RDX_IMM8","0x48 0x83 0xFA"),("CMP_RBX_IMM8","0x48 0x83 0xFB"),
    ("CMP_RSI_IMM8","0x48 0x83 0xFE"),("CMP_RDI_IMM8","0x48 0x83 0xFF"),
]
for name,enc in alu_imm8:
    d(f"X64_{name}", f"EMIT u8 {enc}")
s()
sub("TEST / CMP reg-reg")
for name,enc in [
    ("TEST_RAX_RAX","0x48 0x85 0xC0"),("TEST_RCX_RCX","0x48 0x85 0xC9"),
    ("TEST_RDX_RDX","0x48 0x85 0xD2"),("TEST_RBX_RBX","0x48 0x85 0xDB"),
    ("TEST_RSI_RSI","0x48 0x85 0xF6"),("TEST_RDI_RDI","0x48 0x85 0xFF"),
    ("TEST_RAX_RCX","0x48 0x85 0xC1"),("TEST_RAX_RDX","0x48 0x85 0xC2"),
    ("TEST_AL_AL",  "0x84 0xC0"),
    ("CMP_RAX_RCX", "0x48 0x39 0xC8"),("CMP_RAX_RDX", "0x48 0x39 0xD0"),
    ("CMP_RAX_RBX", "0x48 0x39 0xD8"),("CMP_RAX_RSI", "0x48 0x39 0xF0"),
    ("CMP_RAX_RDI", "0x48 0x39 0xF8"),
    ("CMP_RCX_RDX", "0x48 0x39 0xD1"),("CMP_RCX_RBX", "0x48 0x39 0xD9"),
    ("CMP_RDX_RBX", "0x48 0x39 0xDA"),("CMP_RDX_RSI", "0x48 0x39 0xF2"),
]:
    d(f"X64_{name}", f"EMIT u8 {enc}")
s()
sub("Shift / rotate  ⚠ follow with EMIT u8 <count>")
for name,enc in [
    ("SHL_RAX_IMM","0x48 0xC1 0xE0"),("SHR_RAX_IMM","0x48 0xC1 0xE8"),
    ("SAR_RAX_IMM","0x48 0xC1 0xF8"),("ROL_RAX_IMM","0x48 0xC1 0xC0"),
    ("ROR_RAX_IMM","0x48 0xC1 0xC8"),("RCL_RAX_IMM","0x48 0xC1 0xD0"),
    ("RCR_RAX_IMM","0x48 0xC1 0xD8"),
    ("SHL_RCX_IMM","0x48 0xC1 0xE1"),("SHR_RCX_IMM","0x48 0xC1 0xE9"),
    ("SAR_RCX_IMM","0x48 0xC1 0xF9"),
    ("SHL_RDX_IMM","0x48 0xC1 0xE2"),("SHR_RDX_IMM","0x48 0xC1 0xEA"),
    ("SAR_RDX_IMM","0x48 0xC1 0xFA"),
    ("SHL_RBX_IMM","0x48 0xC1 0xE3"),("SHR_RBX_IMM","0x48 0xC1 0xEB"),
]:
    d(f"X64_{name}", f"EMIT u8 {enc}")
s()
sub("Shift by CL")
for name,enc in [
    ("SHL_RAX_CL","0x48 0xD3 0xE0"),("SHR_RAX_CL","0x48 0xD3 0xE8"),
    ("SAR_RAX_CL","0x48 0xD3 0xF8"),("ROL_RAX_CL","0x48 0xD3 0xC0"),
    ("ROR_RAX_CL","0x48 0xD3 0xC8"),
    ("SHL_RCX_CL","0x48 0xD3 0xE1"),("SHR_RCX_CL","0x48 0xD3 0xE9"),
    ("SHL_RDX_CL","0x48 0xD3 0xE2"),("SHR_RDX_CL","0x48 0xD3 0xEA"),
]:
    d(f"X64_{name}", f"EMIT u8 {enc}")
s()
sub("Bit operations")
for name,enc,comm in [
    ("BT_RAX_RCX",   "0x48 0x0F 0xA3 0xC8","bit test"),
    ("BTS_RAX_RCX",  "0x48 0x0F 0xAB 0xC8","bit test and set"),
    ("BTR_RAX_RCX",  "0x48 0x0F 0xB3 0xC8","bit test and reset"),
    ("BTC_RAX_RCX",  "0x48 0x0F 0xBB 0xC8","bit test and complement"),
    ("BSF_RAX_RCX",  "0x48 0x0F 0xBC 0xC1","bit scan forward"),
    ("BSR_RAX_RCX",  "0x48 0x0F 0xBD 0xC1","bit scan reverse"),
    ("LZCNT_RAX_RCX","0xF3 0x48 0x0F 0xBD 0xC1","leading zeros"),
    ("TZCNT_RAX_RCX","0xF3 0x48 0x0F 0xBC 0xC1","trailing zeros"),
    ("POPCNT_RAX_RCX","0xF3 0x48 0x0F 0xB8 0xC1","population count"),
    ("ANDN_RAX_RCX_RDX","0xC4 0xE2 0xB0 0xF2 0xC2","~RCX & RDX → RAX (BMI1)"),
    ("BLSI_RCX_RAX","0xC4 0xE2 0xB8 0xF3 0xC8","extract lowest set bit"),
    ("BLSMSK_RCX_RAX","0xC4 0xE2 0xB8 0xF3 0xD0","mask up to lowest set bit"),
    ("BLSR_RCX_RAX","0xC4 0xE2 0xB8 0xF3 0xC0","reset lowest set bit"),
]:
    d(f"X64_{name}", f"EMIT u8 {enc}", comm)
s()
sub("Atomic / locked operations")
for name,enc,comm in [
    ("XCHG_RAX_RCX",    "0x48 0x87 0xC1","exchange (implicit LOCK)"),
    ("XCHG_RAX_RDX",    "0x48 0x87 0xC2",""),
    ("XCHG_RAX_RBX",    "0x48 0x87 0xC3",""),
    ("LOCK_XADD_MEM_RAX","0xF0 0x48 0x0F 0xC1 0x07","LOCK XADD [RDI], RAX"),
    ("LOCK_CMPXCHG",    "0xF0 0x48 0x0F 0xB1 0x0F","LOCK CMPXCHG [RDI], RCX  (cmp RAX)"),
    ("LOCK_INC_MEM",    "0xF0 0x48 0xFF 0x07","LOCK INC qword [RDI]"),
    ("LOCK_DEC_MEM",    "0xF0 0x48 0xFF 0x0F","LOCK DEC qword [RDI]"),
    ("LOCK_ADD_MEM_RAX","0xF0 0x48 0x01 0x07","LOCK ADD [RDI], RAX"),
    ("LOCK_OR_MEM_RAX", "0xF0 0x48 0x09 0x07","LOCK OR  [RDI], RAX"),
    ("LOCK_AND_MEM_RAX","0xF0 0x48 0x21 0x07","LOCK AND [RDI], RAX"),
    ("LOCK_XOR_MEM_RAX","0xF0 0x48 0x31 0x07","LOCK XOR [RDI], RAX"),
    ("CMPXCHG8B",       "0x0F 0xC7 0x0F","CMPXCHG8B [RDI]"),
    ("CMPXCHG16B",      "0x48 0x0F 0xC7 0x0F","CMPXCHG16B [RDI]"),
]:
    d(f"X64_{name}", f"EMIT u8 {enc}", comm)
s()
sub("Conditional moves (CMOVcc rax, rcx)")
for cc,op in [("E",0x44),("NE",0x45),("L",0x4C),("LE",0x4E),("G",0x4F),
              ("GE",0x4D),("B",0x42),("BE",0x46),("A",0x47),("AE",0x43),
              ("S",0x48),("NS",0x49),("O",0x40),("NO",0x41),
              ("Z",0x44),("NZ",0x45),("C",0x42),("NC",0x43)]:
    d(f"X64_CMOV{cc}_RAX_RCX", f"EMIT u8 0x48 0x0F 0x{op:02X} 0xC1")
s()
sub("SETcc — write 0 or 1 to AL")
for cc,op in [("E",0x94),("NE",0x95),("L",0x9C),("LE",0x9E),("G",0x9F),
              ("GE",0x9D),("B",0x92),("BE",0x96),("A",0x97),("AE",0x93),
              ("S",0x98),("NS",0x99),("O",0x90),("NO",0x91),
              ("Z",0x94),("NZ",0x95),("C",0x92),("NC",0x93),("P",0x9A),("NP",0x9B)]:
    d(f"X64_SET{cc}_AL", f"EMIT u8 0x0F 0x{op:02X} 0xC0")
s()
sub("Short jumps  ⚠ follow with EMIT u8 <signed rel8>")
for cc,op in [("JMP",0xEB),("JE",0x74),("JNE",0x75),("JZ",0x74),("JNZ",0x75),
              ("JL",0x7C),("JLE",0x7E),("JG",0x7F),("JGE",0x7D),
              ("JB",0x72),("JBE",0x76),("JA",0x77),("JAE",0x73),
              ("JS",0x78),("JNS",0x79),("JO",0x70),("JNO",0x71),
              ("JP",0x7A),("JNP",0x7B),("JRCXZ",0xE3),("LOOP",0xE2),
              ("LOOPE",0xE1),("LOOPNE",0xE0)]:
    d(f"X64_{cc}_SHORT", f"EMIT u8 0x{op:02X}")
s()
sub("Near jumps  ⚠ follow with EMIT u32 <signed rel32>")
d("X64_JMP_NEAR",    "EMIT u8 0xE9")
d("X64_CALL_REL32",  "EMIT u8 0xE8")
for cc,op in [("JE",0x84),("JNE",0x85),("JZ",0x84),("JNZ",0x85),
              ("JL",0x8C),("JLE",0x8E),("JG",0x8F),("JGE",0x8D),
              ("JB",0x82),("JBE",0x86),("JA",0x87),("JAE",0x83),
              ("JS",0x88),("JNS",0x89),("JO",0x80),("JNO",0x81),
              ("JP",0x8A),("JNP",0x8B)]:
    d(f"X64_{cc}_NEAR", f"EMIT u8 0x0F 0x{op:02X}")
s()
sub("Indirect call / jump via register")
for reg,enc in [("RAX","0xFF 0xD0"),("RCX","0xFF 0xD1"),("RDX","0xFF 0xD2"),
                ("RBX","0xFF 0xD3"),("RSI","0xFF 0xD6"),("RDI","0xFF 0xD7"),
                ("R8","0x41 0xFF 0xD0"),("R9","0x41 0xFF 0xD1"),
                ("R10","0x41 0xFF 0xD2"),("R11","0x41 0xFF 0xD3")]:
    d(f"X64_CALL_{reg}", f"EMIT u8 {enc}")
for reg,enc in [("RAX","0xFF 0xE0"),("RCX","0xFF 0xE1"),("RDX","0xFF 0xE2"),
                ("RBX","0xFF 0xE3"),("RSI","0xFF 0xE6"),("RDI","0xFF 0xE7"),
                ("R8","0x41 0xFF 0xE0"),("R11","0x41 0xFF 0xE3")]:
    d(f"X64_JMP_{reg}", f"EMIT u8 {enc}")
s()
sub("Control register access  (CPL 0)")
for op,name,modrm in [(0x22,"CR0_RAX",0xC0),(0x22,"CR3_RAX",0xD8),
                      (0x22,"CR4_RAX",0xE0),(0x22,"CR8_RAX",0xC0)]:
    rex = 0x44 if "CR8" in name else 0x0F
    d(f"X64_MOV_{name}", f"EMIT u8 0x0F 0x{op:02X} 0x{modrm:02X}")
for op,name,modrm in [(0x20,"RAX_CR0",0xC0),(0x20,"RAX_CR3",0xD8),
                      (0x20,"RAX_CR4",0xE0)]:
    d(f"X64_MOV_{name}", f"EMIT u8 0x0F 0x{op:02X} 0x{modrm:02X}")
s()
sub("SSE2 — basic XMM operations (most used)")
sse2 = [
    ("MOVAPS_XMM0_XMM1",  "0x0F 0x28 0xC1","aligned move"),
    ("MOVUPS_XMM0_XMM1",  "0x0F 0x10 0xC1","unaligned move"),
    ("XORPS_XMM0_XMM0",   "0x0F 0x57 0xC0","zero xmm0"),
    ("XORPD_XMM0_XMM0",   "0x66 0x0F 0x57 0xC0","zero xmm0 double"),
    ("ADDPS_XMM0_XMM1",   "0x0F 0x58 0xC1","add packed float"),
    ("ADDPD_XMM0_XMM1",   "0x66 0x0F 0x58 0xC1","add packed double"),
    ("SUBPS_XMM0_XMM1",   "0x0F 0x5C 0xC1","sub packed float"),
    ("MULPS_XMM0_XMM1",   "0x0F 0x59 0xC1","mul packed float"),
    ("DIVPS_XMM0_XMM1",   "0x0F 0x5E 0xC1","div packed float"),
    ("ADDSS_XMM0_XMM1",   "0xF3 0x0F 0x58 0xC1","add scalar float"),
    ("ADDSD_XMM0_XMM1",   "0xF2 0x0F 0x58 0xC1","add scalar double"),
    ("SUBSS_XMM0_XMM1",   "0xF3 0x0F 0x5C 0xC1","sub scalar float"),
    ("MULSS_XMM0_XMM1",   "0xF3 0x0F 0x59 0xC1","mul scalar float"),
    ("DIVSS_XMM0_XMM1",   "0xF3 0x0F 0x5E 0xC1","div scalar float"),
    ("SQRTSS_XMM0_XMM1",  "0xF3 0x0F 0x51 0xC1","sqrt scalar float"),
    ("SQRTSD_XMM0_XMM1",  "0xF2 0x0F 0x51 0xC1","sqrt scalar double"),
    ("CVTSI2SS_XMM0_RAX", "0xF3 0x48 0x0F 0x2A 0xC0","int64→float32"),
    ("CVTSI2SD_XMM0_RAX", "0xF2 0x48 0x0F 0x2A 0xC0","int64→float64"),
    ("CVTSS2SI_RAX_XMM0", "0xF3 0x48 0x0F 0x2D 0xC0","float32→int64"),
    ("CVTSD2SI_RAX_XMM0", "0xF2 0x48 0x0F 0x2D 0xC0","float64→int64"),
    ("CVTSS2SD_XMM0_XMM1","0xF3 0x0F 0x5A 0xC1","float32→float64"),
    ("CVTSD2SS_XMM0_XMM1","0xF2 0x0F 0x5A 0xC1","float64→float32"),
    ("PXOR_XMM0_XMM0",    "0x66 0x0F 0xEF 0xC0","zero xmm0 integer"),
    ("PADDB_XMM0_XMM1",   "0x66 0x0F 0xFC 0xC1","add packed bytes"),
    ("PADDW_XMM0_XMM1",   "0x66 0x0F 0xFD 0xC1","add packed words"),
    ("PADDD_XMM0_XMM1",   "0x66 0x0F 0xFE 0xC1","add packed dwords"),
    ("PADDQ_XMM0_XMM1",   "0x66 0x0F 0xD4 0xC1","add packed qwords"),
    ("PCMPEQB_XMM0_XMM1", "0x66 0x0F 0x74 0xC1","compare bytes =="),
    ("PCMPEQD_XMM0_XMM1", "0x66 0x0F 0x76 0xC1","compare dwords =="),
    ("PMOVMSKB_RAX_XMM0", "0x66 0x0F 0xD7 0xC0","move byte mask → RAX"),
]
for name,enc,comm in sse2:
    d(f"X64_{name}", f"EMIT u8 {enc}", comm)
s()
sub("Complete Linux syscall sequences  (self-contained)")
d("X64_WRITE_STDOUT",  "EMIT u8 0x48 0xC7 0xC0 0x01 0x00 0x00 0x00 0x48 0xC7 0xC7 0x01 0x00 0x00 0x00",
  "mov rax,1; mov rdi,1  (then set rsi=ptr rdx=len + SYSCALL)")
d("X64_WRITE_STDERR",  "EMIT u8 0x48 0xC7 0xC0 0x01 0x00 0x00 0x00 0x48 0xC7 0xC7 0x02 0x00 0x00 0x00",
  "mov rax,1; mov rdi,2")
d("X64_WRITE_1",       "EMIT u8 0x48 0xC7 0xC0 0x01 0x00 0x00 0x00 0x48 0xC7 0xC7 0x01 0x00 0x00 0x00",
  "alias for X64_WRITE_STDOUT")
d("X64_EXIT_0",        "EMIT u8 0x48 0xC7 0xC0 0x3C 0x00 0x00 0x00 0x48 0x31 0xFF 0x0F 0x05",
  "mov rax,60; xor rdi,rdi; syscall  — exit(0)")
d("X64_EXIT_1",        "EMIT u8 0x48 0xC7 0xC0 0x3C 0x00 0x00 0x00 0x48 0xC7 0xC7 0x01 0x00 0x00 0x00 0x0F 0x05",
  "exit(1)")
d("X64_EXIT_GROUP_0",  "EMIT u8 0x48 0xC7 0xC0 0xE7 0x00 0x00 0x00 0x48 0x31 0xFF 0x0F 0x05",
  "exit_group(0) — preferred for main")
d("X64_GETPID",        "EMIT u8 0x48 0xC7 0xC0 0x27 0x00 0x00 0x00 0x0F 0x05",
  "getpid() → rax")
d("X64_FORK",          "EMIT u8 0x48 0xC7 0xC0 0x39 0x00 0x00 0x00 0x0F 0x05",
  "fork() → rax")

# ──────────────────────────────────────────────────────────────
sec("§10  x86-32 INSTRUCTIONS")
sub("Single-byte instructions")
for name,enc,comm in [
    ("NOP","0x90",""),("RET","0xC3","near"),("RETF","0xCB","far"),
    ("INT3","0xCC","breakpoint"),("HLT","0xF4",""),("CLI","0xFA",""),
    ("STI","0xFB",""),("CLD","0xFC",""),("STD","0xFD",""),
    ("PUSHA","0x60","push all"),("POPA","0x61","pop all"),
    ("PUSHFD","0x9C","push eflags"),("POPFD","0x9D","pop eflags"),
    ("LEAVE","0xC9","mov esp,ebp; pop ebp"),
    ("PAUSE","0xF3 0x90","spin-loop hint"),
    ("INT_80","0xCD 0x80","Linux 32-bit syscall"),
    ("INT_21","0xCD 0x21","DOS services"),
    ("INT_13","0xCD 0x13","BIOS disk"),
    ("INT_10","0xCD 0x10","BIOS video"),
]:
    d(f"X86_{name}", f"EMIT u8 {enc}", comm)
s()
sub("PUSH/POP 32-bit GPRs")
for reg,pb,pp in [("EAX",0x50,0x58),("ECX",0x51,0x59),("EDX",0x52,0x5A),
                  ("EBX",0x53,0x5B),("ESP",0x54,0x5C),("EBP",0x55,0x5D),
                  ("ESI",0x56,0x5E),("EDI",0x57,0x5F)]:
    d(f"X86_PUSH_{reg}", f"EMIT u8 0x{pb:02X}")
    d(f"X86_POP_{reg}",  f"EMIT u8 0x{pp:02X}")
s()
sub("XOR to zero  (2 bytes)")
for reg,modrm in [("EAX",0xC0),("ECX",0xC9),("EDX",0xD2),
                  ("EBX",0xDB),("ESI",0xF6),("EDI",0xFF)]:
    d(f"X86_XOR_{reg}", f"EMIT u8 0x31 0x{modrm:02X}")
s()
sub("MOV reg, imm32  ⚠ follow with EMIT u32 <val>")
for reg,op in [("EAX",0xB8),("ECX",0xB9),("EDX",0xBA),("EBX",0xBB),
               ("ESP",0xBC),("EBP",0xBD),("ESI",0xBE),("EDI",0xBF)]:
    d(f"X86_MOV_{reg}", f"EMIT u8 0x{op:02X}")
s()
sub("Stack frame")
d("X86_FRAME_ENTER",  "EMIT u8 0x55 0x89 0xE5", "push ebp; mov ebp,esp")
d("X86_FRAME_LEAVE",  "EMIT u8 0xC9 0xC3",      "leave; ret")
d("X86_ALIGN16",      "EMIT u8 0x83 0xE4 0xF0", "and esp,-16")
s()
sub("Short jumps  ⚠ follow with EMIT u8 <rel8>")
for cc,op in [("JMP",0xEB),("JE",0x74),("JNE",0x75),("JL",0x7C),
              ("JLE",0x7E),("JG",0x7F),("JGE",0x7D),
              ("JB",0x72),("JA",0x77)]:
    d(f"X86_{cc}_SHORT", f"EMIT u8 0x{op:02X}")
s()
sub("Near call/jmp  ⚠ follow with EMIT u32 <rel32>")
d("X86_CALL_REL32", "EMIT u8 0xE8")
d("X86_JMP_NEAR",   "EMIT u8 0xE9")
d("X86_CALL_EAX",   "EMIT u8 0xFF 0xD0")
d("X86_JMP_EAX",    "EMIT u8 0xFF 0xE0")
s()
sub("Linux x86-32 syscall numbers")
for name,val in [("READ",3),("WRITE",4),("OPEN",5),("CLOSE",6),("STAT",106),
                 ("LSTAT",107),("FSTAT",108),("LSEEK",19),("MMAP",90),
                 ("MMAP2",192),("MUNMAP",91),("BRK",45),("IOCTL",54),
                 ("WRITEV",146),("ACCESS",33),("PIPE",42),("DUP",41),
                 ("DUP2",63),("GETPID",20),("FORK",2),("VFORK",190),
                 ("EXECVE",11),("EXIT",1),("WAIT4",114),("KILL",37),
                 ("RENAME",38),("MKDIR",39),("RMDIR",40),("UNLINK",10),
                 ("LINK",9),("SYMLINK",83),("READLINK",85),("CHMOD",15),
                 ("CHOWN",182),("SOCKET",359),("CONNECT",362),("BIND",361),
                 ("LISTEN",363),("ACCEPT",364),("SENDTO",369),("RECVFROM",371),
                 ("GETSOCKNAME",367),("CLONE",120),("SETUID",23),("GETUID",24),
                 ("SETGID",46),("GETGID",47),("GETEUID",49),("GETEGID",50),
                 ("FCNTL",55),("SELECT",82),("POLL",168),("NANOSLEEP",162),
                 ("CLOCK_GETTIME",265),("EXIT_GROUP",252)]:
    d(f"X86_SYS_{name}", str(val))

# ──────────────────────────────────────────────────────────────
sec("§11  ARM64 / AArch64 INSTRUCTIONS\n//     All AArch64 instructions are 32-bit little-endian.\n//     Reference: Arm Architecture Reference Manual (DDI 0487)")
sub("Single-instruction macros (complete, 4 bytes)")
a64 = [
    ("NOP",          0xD503201F,"no-op"),
    ("RET",          0xD65F03C0,"ret (return via LR)"),
    ("BRK_0",        0xD4200000,"brk #0  (debugger)"),
    ("BRK_1",        0xD4200020,"brk #1"),
    ("SVC_0",        0xD4000001,"svc #0  (Linux syscall)"),
    ("HLT_0",        0xD4400000,"hlt #0"),
    ("WFI",          0xD503207F,"wait for interrupt"),
    ("WFE",          0xD503205F,"wait for event"),
    ("SEV",          0xD503209F,"send event"),
    ("SEVL",         0xD50320BF,"send event local"),
    ("YIELD",        0xD503203F,"yield hint"),
    ("ISBB",         0xD503305F,"ISB (instruction sync barrier)"),
    ("DMB_ISH",      0xD5033BBF,"data memory barrier inner-shareable"),
    ("DSB_ISH",      0xD5033B9F,"data sync barrier inner-shareable"),
    ("DSB_SY",       0xD5033F9F,"data sync barrier full system"),
    ("DMB_SY",       0xD5033FBF,"data memory barrier full system"),
    ("CLREX",        0xD5033F5F,"clear exclusive monitor"),
    ("MSR_DAIF_ALL", 0xD50342DF,"set DAIF (disable all interrupts)"),
    ("MSR_DAIF_NONE",0xD50342FF,"clear DAIF (enable all interrupts) - care!"),
]
for name,enc,comm in a64:
    d(f"A64_{name}", f"EMIT u32 0x{enc:08X}", comm)
s()
sub("MOV Xn, #imm16  (common small constants)")
# MOVZ Xn, #imm  encoding: 0xD280_0000 | (imm<<5) | Rd
def movz(rd, imm): return 0xD2800000 | (imm << 5) | rd
for reg in range(9):  # x0..x8
    for val in [0,1,2,3,4,8,16,64,93,94,172,214,220,221,222]:
        enc = movz(reg, val)
        d(f"A64_MOV_X{reg}_{val}", f"EMIT u32 0x{enc:08X}")
s()
sub("Common complete syscall sequences (Linux AArch64)")
# write(1, x1=ptr, x2=len): mov x0,1; mov x8,64; svc #0
d("A64_WRITE_STDOUT",  f"EMIT u32 0x{movz(0,1):08X} 0x{movz(8,64):08X} 0xD4000001",
  "mov x0,1; mov x8,64(sys_write); svc #0")
# exit(0): mov x0,0; mov x8,93; svc #0
d("A64_EXIT_0",        f"EMIT u32 0x{movz(0,0):08X} 0x{movz(8,93):08X} 0xD4000001",
  "mov x0,0; mov x8,93(sys_exit); svc #0")
d("A64_EXIT_GROUP_0",  f"EMIT u32 0x{movz(0,0):08X} 0x{movz(8,94):08X} 0xD4000001",
  "exit_group(0)")
d("A64_GETPID",        f"EMIT u32 0x{movz(8,172):08X} 0xD4000001",
  "mov x8,172(sys_getpid); svc #0")

# ──────────────────────────────────────────────────────────────
sec("§12  RISC-V 64-bit INSTRUCTIONS  (RV64I + C)\n//     All base instructions are 32-bit LE.\n//     Reference: RISC-V ISA Specification 20191213")
sub("Base instructions (4 bytes)")
rv_ops = [
    ("NOP",     0x00000013,"addi x0, x0, 0  (canonical NOP)"),
    ("RET",     0x00008067,"jalr x0, 0(x1)"),
    ("ECALL",   0x00000073,"system call"),
    ("EBREAK",  0x00100073,"breakpoint"),
    ("WFI",     0x10500073,"wait for interrupt"),
    ("MRET",    0x30200073,"machine-mode return"),
    ("SRET",    0x10200073,"supervisor-mode return"),
    ("FENCE",   0x0FF0000F,"full fence"),
    ("FENCE_I", 0x0000100F,"instruction fence"),
    ("SFENCE_VMA",0x12000073,"TLB flush"),
]
for name,enc,comm in rv_ops:
    d(f"RV_{name}", f"EMIT u32 0x{enc:08X}", comm)
s()
sub("RVC compressed instructions (2 bytes)")
for name,enc,comm in [
    ("NOP",  0x0001,"c.nop"),
    ("RET",  0x8082,"c.jr x1  (ret)"),
    ("EBREAK",0x9002,"c.ebreak"),
    ("NOP_B",0x0001,""),
]:
    d(f"RVC_{name}", f"EMIT u16 0x{enc:04X}", comm)
s()
sub("Common Linux RV64 syscall numbers")
for name,val in [("IO_SETUP",0),("IO_DESTROY",1),("IO_SUBMIT",2),
                 ("IO_CANCEL",3),("IO_GETEVENTS",4),
                 ("OPENAT",56),("CLOSE",57),("LSEEK",62),("READ",63),("WRITE",64),
                 ("READV",65),("WRITEV",66),("PREAD64",67),("PWRITE64",68),
                 ("SENDFILE",71),("PSELECT6",72),("PPOLL",73),
                 ("READLINKAT",78),("FSTATAT",79),("FSTAT",80),
                 ("SYNC",81),("FSYNC",82),("FDATASYNC",83),
                 ("TRUNCATE",45),("FTRUNCATE",46),
                 ("MKDIRAT",34),("UNLINKAT",35),("RENAMEAT",38),
                 ("LINKAT",37),("SYMLINKAT",36),("FACCESSAT",48),
                 ("CHDIR",49),("FCHDIR",50),("CHROOT",51),("FCHMOD",52),
                 ("FCHMODAT",53),("FCHOWNAT",54),("FCHOWN",55),
                 ("GETCWD",17),("GETDENTS64",61),
                 ("FCNTL",25),("IOCTL",29),("FLOCK",32),
                 ("MMAP",222),("MUNMAP",215),("MPROTECT",226),
                 ("MREMAP",216),("MADVISE",233),("BRK",214),
                 ("MLOCK",228),("MUNLOCK",229),("MLOCKALL",230),("MUNLOCKALL",231),
                 ("MINCORE",232),
                 ("CLONE",220),("EXECVE",221),("WAIT4",260),("EXIT",93),
                 ("EXIT_GROUP",94),("KILL",129),
                 ("GETPID",172),("GETPPID",173),("GETUID",174),("GETEUID",175),
                 ("GETGID",176),("GETEGID",177),("GETTID",178),
                 ("FUTEX",98),("NANOSLEEP",101),("CLOCK_GETTIME",113),
                 ("CLOCK_SETTIME",112),("CLOCK_NANOSLEEP",115),
                 ("TIMER_CREATE",107),("TIMER_DELETE",111),
                 ("SETITIMER",103),("GETITIMER",102),("ALARM",105),
                 ("SIGACTION",134),("SIGPROCMASK",135),("SIGRETURN",139),
                 ("RAISE",128),("SIGPENDING",136),("SIGSUSPEND",133),
                 ("SOCKET",198),("BIND",200),("LISTEN",201),("ACCEPT",202),
                 ("CONNECT",203),("GETSOCKNAME",204),("GETPEERNAME",205),
                 ("SENDTO",206),("RECVFROM",207),("SETSOCKOPT",208),
                 ("GETSOCKOPT",209),("SHUTDOWN",210),("SENDMSG",211),
                 ("RECVMSG",212),("SOCKETPAIR",199),
                 ("PIPE2",59),("DUP",23),("DUP3",24),
                 ("SCHED_YIELD",124),("SCHED_GETPARAM",121),
                 ("SCHED_SETPARAM",118),("SCHED_SETSCHEDULER",119),
                 ("SCHED_GETSCHEDULER",120),("SCHED_GETAFFINITY",123),
                 ("SCHED_SETAFFINITY",122),
                 ("PRCTL",167),("ARCH_PRCTL",0),
                 ("PTRACE",117),("PROCESS_VM_READV",270),
                 ("MEMFD_CREATE",279),("MMAP2",0)]:
    d(f"RV_SYS_{name}", str(val))

# ──────────────────────────────────────────────────────────────
sec("§13  LINUX SYSCALLS — x86-64\n//     Reference: linux/arch/x86/entry/syscalls/syscall_64.tbl")
sub("All ~335 x86-64 Linux syscall numbers")
syscalls_x64 = [
    ("READ",0),("WRITE",1),("OPEN",2),("CLOSE",3),("STAT",4),("FSTAT",5),
    ("LSTAT",6),("POLL",7),("LSEEK",8),("MMAP",9),("MPROTECT",10),
    ("MUNMAP",11),("BRK",12),("RT_SIGACTION",13),("RT_SIGPROCMASK",14),
    ("RT_SIGRETURN",15),("IOCTL",16),("PREAD64",17),("PWRITE64",18),
    ("READV",19),("WRITEV",20),("ACCESS",21),("PIPE",22),("SELECT",23),
    ("SCHED_YIELD",24),("MREMAP",25),("MSYNC",26),("MINCORE",27),
    ("MADVISE",28),("SHMGET",29),("SHMAT",30),("SHMCTL",31),
    ("DUP",32),("DUP2",33),("PAUSE",34),("NANOSLEEP",35),("GETITIMER",36),
    ("ALARM",37),("SETITIMER",38),("GETPID",39),("SENDFILE",40),
    ("SOCKET",41),("CONNECT",42),("ACCEPT",43),("SENDTO",44),
    ("RECVFROM",45),("SENDMSG",46),("RECVMSG",47),("SHUTDOWN",48),
    ("BIND",49),("LISTEN",50),("GETSOCKNAME",51),("GETPEERNAME",52),
    ("SOCKETPAIR",53),("SETSOCKOPT",54),("GETSOCKOPT",55),
    ("CLONE",56),("FORK",57),("VFORK",58),("EXECVE",59),
    ("EXIT",60),("WAIT4",61),("KILL",62),("UNAME",63),
    ("SEMGET",64),("SEMOP",65),("SEMCTL",66),("SHMDT",67),
    ("MSGGET",68),("MSGSND",69),("MSGRCV",70),("MSGCTL",71),
    ("FCNTL",72),("FLOCK",73),("FSYNC",74),("FDATASYNC",75),
    ("TRUNCATE",76),("FTRUNCATE",77),("GETDENTS",78),("GETCWD",79),
    ("CHDIR",80),("FCHDIR",81),("RENAME",82),("MKDIR",83),("RMDIR",84),
    ("CREAT",85),("LINK",86),("UNLINK",87),("SYMLINK",88),("READLINK",89),
    ("CHMOD",90),("FCHMOD",91),("CHOWN",92),("FCHOWN",93),("LCHOWN",94),
    ("UMASK",95),("GETTIMEOFDAY",96),("GETRLIMIT",97),("GETRUSAGE",98),
    ("SYSINFO",99),("TIMES",100),("PTRACE",101),("GETUID",102),
    ("SYSLOG",103),("GETGID",104),("SETUID",105),("SETGID",106),
    ("GETEUID",107),("GETEGID",108),("SETPGID",109),("GETPPID",110),
    ("GETPGRP",111),("SETSID",112),("SETREUID",113),("SETREGID",114),
    ("GETGROUPS",115),("SETGROUPS",116),("SETRESUID",117),("GETRESUID",118),
    ("SETRESGID",119),("GETRESGID",120),("GETPGID",121),("SETFSUID",122),
    ("SETFSGID",123),("GETSID",124),("CAPGET",125),("CAPSET",126),
    ("RT_SIGPENDING",127),("RT_SIGTIMEDWAIT",128),("RT_SIGQUEUEINFO",129),
    ("RT_SIGSUSPEND",130),("SIGALTSTACK",131),("UTIME",132),("MKNOD",133),
    ("USELIB",134),("PERSONALITY",135),("USTAT",136),("STATFS",137),
    ("FSTATFS",138),("SYSFS",139),("GETPRIORITY",140),("SETPRIORITY",141),
    ("SCHED_SETPARAM",142),("SCHED_GETPARAM",143),("SCHED_SETSCHEDULER",144),
    ("SCHED_GETSCHEDULER",145),("SCHED_GET_PRIORITY_MAX",146),
    ("SCHED_GET_PRIORITY_MIN",147),("SCHED_RR_GET_INTERVAL",148),
    ("MLOCK",149),("MUNLOCK",150),("MLOCKALL",151),("MUNLOCKALL",152),
    ("VHANGUP",153),("MODIFY_LDT",154),("PIVOT_ROOT",155),
    ("SYSCTL",156),("PRCTL",157),("ARCH_PRCTL",158),("ADJTIMEX",159),
    ("SETRLIMIT",160),("CHROOT",161),("SYNC",162),("ACCT",163),
    ("SETTIMEOFDAY",164),("MOUNT",165),("UMOUNT2",166),("SWAPON",167),
    ("SWAPOFF",168),("REBOOT",169),("SETHOSTNAME",170),("SETDOMAINNAME",171),
    ("IOPL",172),("IOPERM",173),("CREATE_MODULE",174),("INIT_MODULE",175),
    ("DELETE_MODULE",176),("GET_KERNEL_SYMS",177),("QUERY_MODULE",178),
    ("QUOTACTL",179),("NFSSERVCTL",180),("GETPMSG",181),("PUTPMSG",182),
    ("AFS_SYSCALL",183),("TUXCALL",184),("SECURITY",185),("GETTID",186),
    ("READAHEAD",187),("SETXATTR",188),("LSETXATTR",189),("FSETXATTR",190),
    ("GETXATTR",191),("LGETXATTR",192),("FGETXATTR",193),("LISTXATTR",194),
    ("LLISTXATTR",195),("FLISTXATTR",196),("REMOVEXATTR",197),
    ("LREMOVEXATTR",198),("FREMOVEXATTR",199),("TKILL",200),
    ("TIME",201),("FUTEX",202),("SCHED_SETAFFINITY",203),
    ("SCHED_GETAFFINITY",204),("SET_THREAD_AREA",205),
    ("IO_SETUP",206),("IO_DESTROY",207),("IO_GETEVENTS",208),
    ("IO_SUBMIT",209),("IO_CANCEL",210),("GET_THREAD_AREA",211),
    ("LOOKUP_DCOOKIE",212),("EPOLL_CREATE",213),("EPOLL_CTL_OLD",214),
    ("EPOLL_WAIT_OLD",215),("REMAP_FILE_PAGES",216),("GETDENTS64",217),
    ("SET_TID_ADDRESS",218),("RESTART_SYSCALL",219),("SEMTIMEDOP",220),
    ("FADVISE64",221),("TIMER_CREATE",222),("TIMER_SETTIME",223),
    ("TIMER_GETTIME",224),("TIMER_GETOVERRUN",225),("TIMER_DELETE",226),
    ("CLOCK_SETTIME",227),("CLOCK_GETTIME",228),("CLOCK_GETRES",229),
    ("CLOCK_NANOSLEEP",230),("EXIT_GROUP",231),("EPOLL_WAIT",232),
    ("EPOLL_CTL",233),("TGKILL",234),("UTIMES",235),("VSERVER",236),
    ("MBIND",237),("SET_MEMPOLICY",238),("GET_MEMPOLICY",239),
    ("MQ_OPEN",240),("MQ_UNLINK",241),("MQ_TIMEDSEND",242),
    ("MQ_TIMEDRECEIVE",243),("MQ_NOTIFY",244),("MQ_GETSETATTR",245),
    ("KEXEC_LOAD",246),("WAITID",247),("ADD_KEY",248),
    ("REQUEST_KEY",249),("KEYCTL",250),("IOPRIO_SET",251),
    ("IOPRIO_GET",252),("INOTIFY_INIT",253),("INOTIFY_ADD_WATCH",254),
    ("INOTIFY_RM_WATCH",255),("MIGRATE_PAGES",256),("OPENAT",257),
    ("MKDIRAT",258),("MKNODAT",259),("FCHOWNAT",260),("FUTIMESAT",261),
    ("NEWFSTATAT",262),("UNLINKAT",263),("RENAMEAT",264),("LINKAT",265),
    ("SYMLINKAT",266),("READLINKAT",267),("FCHMODAT",268),("FACCESSAT",269),
    ("PSELECT6",270),("PPOLL",271),("UNSHARE",272),
    ("SET_ROBUST_LIST",273),("GET_ROBUST_LIST",274),("SPLICE",275),
    ("TEE",276),("SYNC_FILE_RANGE",277),("VMSPLICE",278),
    ("MOVE_PAGES",279),("UTIMENSAT",280),("EPOLL_PWAIT",281),
    ("SIGNALFD",282),("TIMERFD_CREATE",283),("EVENTFD",284),
    ("FALLOCATE",285),("TIMERFD_SETTIME",286),("TIMERFD_GETTIME",287),
    ("ACCEPT4",288),("SIGNALFD4",289),("EVENTFD2",290),
    ("EPOLL_CREATE1",291),("DUP3",292),("PIPE2",293),("INOTIFY_INIT1",294),
    ("PREADV",295),("PWRITEV",296),("RT_TGSIGQUEUEINFO",297),
    ("PERF_EVENT_OPEN",298),("RECVMMSG",299),("FANOTIFY_INIT",300),
    ("FANOTIFY_MARK",301),("PRLIMIT64",302),("NAME_TO_HANDLE_AT",303),
    ("OPEN_BY_HANDLE_AT",304),("CLOCK_ADJTIME",305),("SYNCFS",306),
    ("SENDMMSG",307),("SETNS",308),("GETCPU",309),("PROCESS_VM_READV",310),
    ("PROCESS_VM_WRITEV",311),("KCMP",312),("FINIT_MODULE",313),
    ("SCHED_SETATTR",314),("SCHED_GETATTR",315),("RENAMEAT2",316),
    ("SECCOMP",317),("GETRANDOM",318),("MEMFD_CREATE",319),
    ("KEXEC_FILE_LOAD",320),("BPF",321),("EXECVEAT",322),("USERFAULTFD",323),
    ("MEMBARRIER",324),("MLOCK2",325),("COPY_FILE_RANGE",326),
    ("PREADV2",327),("PWRITEV2",328),("PKEY_MPROTECT",329),
    ("PKEY_ALLOC",330),("PKEY_FREE",331),("STATX",332),
    ("IO_PGETEVENTS",333),("RSEQ",334),("PIDFD_SEND_SIGNAL",424),
    ("IO_URING_SETUP",425),("IO_URING_ENTER",426),("IO_URING_REGISTER",427),
    ("OPEN_TREE",428),("MOVE_MOUNT",429),("FSOPEN",430),("FSCONFIG",431),
    ("FSMOUNT",432),("FSPICK",433),("PIDFD_OPEN",434),("CLONE3",435),
    ("CLOSE_RANGE",436),("OPENAT2",437),("PIDFD_GETFD",438),
    ("FACCESSAT2",439),("PROCESS_MADVISE",440),("EPOLL_PWAIT2",441),
    ("MOUNT_SETATTR",442),("LANDLOCK_CREATE_RULESET",444),
    ("LANDLOCK_ADD_RULE",445),("LANDLOCK_RESTRICT_SELF",446),
    ("MEMFD_SECRET",447),("PROCESS_MRELEASE",448),
]
d(f"SYS_{name}", str(val))

# ──────────────────────────────────────────────────────────────
sec("§14  LINUX SYSCALLS — AArch64\n//     Reference: linux/arch/arm64/include/asm/unistd.h")
sub("All AArch64 Linux syscall numbers")
syscalls_a64 = [
    ("IO_SETUP",0),("IO_DESTROY",1),("IO_SUBMIT",2),("IO_CANCEL",3),
    ("IO_GETEVENTS",4),("SETXATTR",5),("LSETXATTR",6),("FSETXATTR",7),
    ("GETXATTR",8),("LGETXATTR",9),("FGETXATTR",10),("LISTXATTR",11),
    ("LLISTXATTR",12),("FLISTXATTR",13),("REMOVEXATTR",14),
    ("LREMOVEXATTR",15),("FREMOVEXATTR",16),("GETCWD",17),
    ("LOOKUP_DCOOKIE",18),("EVENTFD2",19),("EPOLL_CREATE1",20),
    ("EPOLL_CTL",21),("EPOLL_PWAIT",22),("DUP",23),("DUP3",24),
    ("FCNTL",25),("INOTIFY_INIT1",26),("INOTIFY_ADD_WATCH",27),
    ("INOTIFY_RM_WATCH",28),("IOCTL",29),("IOPRIO_SET",30),
    ("IOPRIO_GET",31),("FLOCK",32),("MKNODAT",33),("MKDIRAT",34),
    ("UNLINKAT",35),("SYMLINKAT",36),("LINKAT",37),("RENAMEAT",38),
    ("UMOUNT2",39),("MOUNT",40),("PIVOT_ROOT",41),("NFSSERVCTL",42),
    ("STATFS",43),("FSTATFS",44),("TRUNCATE",45),("FTRUNCATE",46),
    ("FALLOCATE",47),("FACCESSAT",48),("CHDIR",49),("FCHDIR",50),
    ("CHROOT",51),("FCHMOD",52),("FCHMODAT",53),("FCHOWNAT",54),
    ("FCHOWN",55),("OPENAT",56),("CLOSE",57),("VHANGUP",58),
    ("PIPE2",59),("QUOTACTL",60),("GETDENTS64",61),("LSEEK",62),
    ("READ",63),("WRITE",64),("READV",65),("WRITEV",66),
    ("PREAD64",67),("PWRITE64",68),("PREADV",69),("PWRITEV",70),
    ("SENDFILE",71),("PSELECT6",72),("PPOLL",73),("SIGNALFD4",74),
    ("VMSPLICE",75),("SPLICE",76),("TEE",77),("READLINKAT",78),
    ("FSTATAT",79),("FSTAT",80),("SYNC",81),("FSYNC",82),
    ("FDATASYNC",83),("SYNC_FILE_RANGE",84),("TIMERFD_CREATE",85),
    ("TIMERFD_SETTIME",86),("TIMERFD_GETTIME",87),("UTIMENSAT",88),
    ("ACCT",89),("CAPGET",90),("CAPSET",91),("PERSONALITY",92),
    ("EXIT",93),("EXIT_GROUP",94),("WAITID",95),("SET_TID_ADDRESS",96),
    ("UNSHARE",97),("FUTEX",98),("SET_ROBUST_LIST",99),
    ("GET_ROBUST_LIST",100),("NANOSLEEP",101),("GETITIMER",102),
    ("SETITIMER",103),("KEXEC_LOAD",104),("INIT_MODULE",105),
    ("DELETE_MODULE",106),("TIMER_CREATE",107),("TIMER_GETTIME",108),
    ("TIMER_GETOVERRUN",109),("TIMER_SETTIME",110),("TIMER_DELETE",111),
    ("CLOCK_SETTIME",112),("CLOCK_GETTIME",113),("CLOCK_GETRES",114),
    ("CLOCK_NANOSLEEP",115),("SYSLOG",116),("PTRACE",117),
    ("SCHED_SETPARAM",118),("SCHED_SETSCHEDULER",119),
    ("SCHED_GETSCHEDULER",120),("SCHED_GETPARAM",121),
    ("SCHED_SETAFFINITY",122),("SCHED_GETAFFINITY",123),
    ("SCHED_YIELD",124),("SCHED_GET_PRIORITY_MAX",125),
    ("SCHED_GET_PRIORITY_MIN",126),("SCHED_RR_GET_INTERVAL",127),
    ("RESTART_SYSCALL",128),("KILL",129),("TKILL",130),("TGKILL",131),
    ("SIGALTSTACK",132),("RT_SIGSUSPEND",133),("RT_SIGACTION",134),
    ("RT_SIGPROCMASK",135),("RT_SIGPENDING",136),("RT_SIGTIMEDWAIT",137),
    ("RT_SIGQUEUEINFO",138),("RT_SIGRETURN",139),("SETPRIORITY",140),
    ("GETPRIORITY",141),("REBOOT",142),("SETREGID",143),("SETGID",144),
    ("SETREUID",145),("SETUID",146),("SETRESUID",147),("GETRESUID",148),
    ("SETRESGID",149),("GETRESGID",150),("SETFSUID",151),("SETFSGID",152),
    ("TIMES",153),("SETPGID",154),("GETPGID",155),("GETSID",156),
    ("SETSID",157),("GETGROUPS",158),("SETGROUPS",159),("UNAME",160),
    ("SETHOSTNAME",161),("SETDOMAINNAME",162),("GETRLIMIT",163),
    ("SETRLIMIT",164),("GETRUSAGE",165),("UMASK",166),("PRCTL",167),
    ("GETCPU",168),("GETTIMEOFDAY",169),("SETTIMEOFDAY",170),
    ("ADJTIMEX",171),("GETPID",172),("GETPPID",173),("GETUID",174),
    ("GETEUID",175),("GETGID",176),("GETEGID",177),("GETTID",178),
    ("SYSINFO",179),("MQ_OPEN",180),("MQ_UNLINK",181),("MQ_TIMEDSEND",182),
    ("MQ_TIMEDRECEIVE",183),("MQ_NOTIFY",184),("MQ_GETSETATTR",185),
    ("MSGGET",186),("MSGCTL",187),("MSGRCV",188),("MSGSND",189),
    ("SEMGET",190),("SEMCTL",191),("SEMTIMEDOP",192),("SEMOP",193),
    ("SHMGET",194),("SHMCTL",195),("SHMAT",196),("SHMDT",197),
    ("SOCKET",198),("SOCKETPAIR",199),("BIND",200),("LISTEN",201),
    ("ACCEPT",202),("CONNECT",203),("GETSOCKNAME",204),("GETPEERNAME",205),
    ("SENDTO",206),("RECVFROM",207),("SETSOCKOPT",208),("GETSOCKOPT",209),
    ("SHUTDOWN",210),("SENDMSG",211),("RECVMSG",212),("READAHEAD",213),
    ("BRK",214),("MUNMAP",215),("MREMAP",216),("ADD_KEY",217),
    ("REQUEST_KEY",218),("KEYCTL",219),("CLONE",220),("EXECVE",221),
    ("MMAP",222),("FADVISE64",223),("SWAPON",224),("SWAPOFF",225),
    ("MPROTECT",226),("MSYNC",227),("MLOCK",228),("MUNLOCK",229),
    ("MLOCKALL",230),("MUNLOCKALL",231),("MINCORE",232),("MADVISE",233),
    ("REMAP_FILE_PAGES",234),("MBIND",235),("GET_MEMPOLICY",236),
    ("SET_MEMPOLICY",237),("MIGRATE_PAGES",238),("MOVE_PAGES",239),
    ("RT_TGSIGQUEUEINFO",240),("PERF_EVENT_OPEN",241),("ACCEPT4",242),
    ("RECVMMSG",243),("FANOTIFY_INIT",250),("FANOTIFY_MARK",251),
    ("PRLIMIT64",261),("NAME_TO_HANDLE_AT",264),("OPEN_BY_HANDLE_AT",265),
    ("CLOCK_ADJTIME",266),("SYNCFS",267),("SETNS",268),("SENDMMSG",269),
    ("PROCESS_VM_READV",270),("PROCESS_VM_WRITEV",271),("KCMP",272),
    ("FINIT_MODULE",273),("SCHED_SETATTR",274),("SCHED_GETATTR",275),
    ("RENAMEAT2",276),("SECCOMP",277),("GETRANDOM",278),
    ("MEMFD_CREATE",279),("BPF",280),("EXECVEAT",281),("USERFAULTFD",282),
    ("MEMBARRIER",283),("MLOCK2",284),("COPY_FILE_RANGE",285),
    ("PREADV2",286),("PWRITEV2",287),("PKEY_MPROTECT",288),
    ("PKEY_ALLOC",289),("PKEY_FREE",290),("STATX",291),
    ("IO_PGETEVENTS",292),("RSEQ",293),("KEXEC_FILE_LOAD",294),
    ("PIDFD_SEND_SIGNAL",424),("IO_URING_SETUP",425),
    ("IO_URING_ENTER",426),("IO_URING_REGISTER",427),("CLONE3",435),
    ("OPENAT2",437),("PIDFD_GETFD",438),("FACCESSAT2",439),
]
d(f"A64_SYS_{name}", str(val))

# ──────────────────────────────────────────────────────────────
sec("§15  LINUX SYSCALLS — RISC-V 64\n//     (same ABI as AArch64 for most syscalls)")
s("// RV64 uses the same syscall numbers as AArch64 from §14.")
s("// Alias them with RV_ prefix for clarity in RISC-V emit files.")
s()
for name,val in [
    ("READ",63),("WRITE",64),("OPENAT",56),("CLOSE",57),("LSEEK",62),
    ("FSTAT",80),("FSTATAT",79),("READLINKAT",78),("GETDENTS64",61),
    ("GETCWD",17),("FCNTL",25),("IOCTL",29),("MMAP",222),("MUNMAP",215),
    ("MPROTECT",226),("BRK",214),("MADVISE",233),("MREMAP",216),
    ("CLONE",220),("EXECVE",221),("WAIT4",260),("EXIT",93),
    ("EXIT_GROUP",94),("KILL",129),("TGKILL",131),("TKILL",130),
    ("GETPID",172),("GETPPID",173),("GETTID",178),("GETUID",174),
    ("GETEUID",175),("GETGID",176),("GETEGID",177),
    ("FUTEX",98),("NANOSLEEP",101),("CLOCK_GETTIME",113),
    ("CLOCK_NANOSLEEP",115),("SETITIMER",103),("GETITIMER",102),
    ("RT_SIGACTION",134),("RT_SIGPROCMASK",135),("RT_SIGRETURN",139),
    ("SIGALTSTACK",132),("SOCKET",198),("BIND",200),("LISTEN",201),
    ("ACCEPT",202),("ACCEPT4",242),("CONNECT",203),("GETSOCKNAME",204),
    ("GETPEERNAME",205),("SENDTO",206),("RECVFROM",207),
    ("SETSOCKOPT",208),("GETSOCKOPT",209),("SHUTDOWN",210),
    ("SENDMSG",211),("RECVMSG",212),("SOCKETPAIR",199),
    ("PIPE2",59),("DUP",23),("DUP3",24),("EPOLL_CREATE1",20),
    ("EPOLL_CTL",21),("EPOLL_PWAIT",22),("EVENTFD2",19),
    ("TIMERFD_CREATE",85),("TIMERFD_SETTIME",86),("TIMERFD_GETTIME",87),
    ("INOTIFY_INIT1",26),("INOTIFY_ADD_WATCH",27),("INOTIFY_RM_WATCH",28),
    ("PRCTL",167),("PTRACE",117),("MEMFD_CREATE",279),("BPF",280),
    ("GETRANDOM",278),("SECCOMP",277),("PROCESS_VM_READV",270),
    ("PROCESS_VM_WRITEV",271),("STATX",291),("IO_URING_SETUP",425),
    ("IO_URING_ENTER",426),("IO_URING_REGISTER",427),("CLONE3",435),
    ("OPENAT2",437),("PIDFD_OPEN",434),("COPY_FILE_RANGE",285),
]:
    d(f"RV_SYS_{name}", str(val))

# ──────────────────────────────────────────────────────────────
sec("§16  macOS / BSD SYSCALLS — x86-64\n//     Reference: xnu/bsd/kern/syscalls.master")
sub("macOS x86-64 syscall numbers (use syscall instruction)")
macos_sys = [
    ("EXIT",1),("FORK",2),("READ",3),("WRITE",4),("OPEN",5),("CLOSE",6),
    ("WAIT4",7),("LINK",9),("UNLINK",10),("CHDIR",12),("FCHDIR",13),
    ("MKNOD",14),("CHMOD",15),("CHOWN",16),("GETFSSTAT",18),("LSEEK",19),
    ("GETPID",20),("SETUID",23),("GETUID",24),("GETEUID",25),("PTRACE",26),
    ("RECVMSG",27),("SENDMSG",28),("RECVFROM",29),("ACCEPT",30),
    ("GETPEERNAME",31),("GETSOCKNAME",32),("ACCESS",33),("CHFLAGS",34),
    ("FCHFLAGS",35),("SYNC",36),("KILL",37),("GETPPID",39),("DUP",41),
    ("PIPE",42),("GETEGID",43),("SIGACTION",46),("GETGID",47),
    ("SIGPROCMASK",48),("GETLOGIN",49),("SETLOGIN",50),("ACCT",51),
    ("SIGPENDING",52),("SIGALTSTACK",53),("IOCTL",54),("REBOOT",55),
    ("REVOKE",56),("SYMLINK",57),("READLINK",58),("EXECVE",59),
    ("UMASK",60),("CHROOT",61),("MSYNC",65),("VFORK",66),("MUNMAP",73),
    ("MPROTECT",74),("MADVISE",75),("MINCORE",78),("GETGROUPS",79),
    ("SETGROUPS",80),("GETPGRP",81),("SETPGID",82),("SETITIMER",83),
    ("SWAPON",85),("GETITIMER",86),("GETDTABLESIZE",89),("DUP2",90),
    ("FCNTL",92),("SELECT",93),("FSYNC",95),("SETPRIORITY",96),
    ("SOCKET",97),("CONNECT",98),("GETPRIORITY",100),("BIND",104),
    ("SETSOCKOPT",105),("LISTEN",106),("SIGSUSPEND",111),
    ("GETTIMEOFDAY",116),("GETRUSAGE",117),("GETSOCKOPT",118),
    ("READV",120),("WRITEV",121),("SETTIMEOFDAY",122),("FCHOWN",123),
    ("FCHMOD",124),("SETREUID",126),("SETREGID",127),("RENAME",128),
    ("MKFIFO",132),("SENDTO",133),("SHUTDOWN",134),("SOCKETPAIR",135),
    ("MKDIR",136),("RMDIR",137),("UTIMES",138),("FUTIMES",139),
    ("ADJTIME",140),("GETHOSTUUID",142),("SETSID",147),("GETPGID",151),
    ("SETPRIVEXEC",152),("PREAD",153),("PWRITE",154),("NFSSVC",155),
    ("STATFS",157),("FSTATFS",158),("UNMOUNT",159),("GETFH",161),
    ("QUOTACTL",165),("MOUNT",167),("CSOPS",169),("WAITID",173),
    ("KDEBUG_TYPEFILTER",177),("KDEBUG_TRACE_STRING",178),
    ("KDEBUG_TRACE64",179),("KDEBUG_TRACE",180),("GETLOGINCLASS",182),
    ("SETLOGINCLASS",183),("PTHREAD_GETUGID_NP",184),("WORKQ_OPEN",187),
    ("WORKQ_KERNRETURN",188),("KEVENT",192),("LCHOWN",198),
    ("GETXATTR",234),("FGETXATTR",235),("SETXATTR",236),("FSETXATTR",237),
    ("REMOVEXATTR",238),("FREMOVEXATTR",239),("LISTXATTR",240),
    ("FLISTXATTR",241),("FSCTL",242),("INITGROUPS",243),
    ("POSIX_SPAWN",244),("FFSCTL",245),("NFSCLNT",247),("FHOPEN",248),
    ("MINHERIT",250),("SEMSYS",251),("MSGSYS",252),("SHMSYS",253),
    ("SEMCTL",254),("SEMGET",255),("SEMOP",256),("MSGCTL",258),
    ("MSGGET",259),("MSGSND",260),("MSGRCV",261),("SHMAT",262),
    ("SHMCTL",263),("SHMDT",264),("SHMGET",265),("SHM_OPEN",266),
    ("SHM_UNLINK",267),("SEM_OPEN",268),("SEM_CLOSE",269),
    ("SEM_UNLINK",270),("SEM_WAIT",271),("SEM_TRYWAIT",272),
    ("SEM_POST",273),("SYSCTLBYNAME",274),("OPEN_EXTENDED",277),
    ("UMASK_EXTENDED",278),("STAT_EXTENDED",279),("LSTAT_EXTENDED",280),
    ("FSTAT_EXTENDED",281),("CHMOD_EXTENDED",282),("FCHMOD_EXTENDED",283),
    ("ACCESS_EXTENDED",284),("SETTID",285),("GETTID",286),
    ("SETSGROUPS",287),("GETSGROUPS",288),("SETWGROUPS",289),
    ("GETWGROUPS",290),("MKFIFO_EXTENDED",291),("MKDIR_EXTENDED",292),
    ("IDENTITYSVC",293),("SHARED_REGION_CHECK_NP",294),("VM_PRESSURE_MONITOR",296),
    ("PSYNCH_RWTRYRDLOCK",297),("PSYNCH_RWTRYRDLOCK_X",298),
    ("PSYNCH_RWYWRLOCK",299),("PSYNCH_RWUNLOCK",301),
    ("GETSID",310),("SETTID_WITH_PID",311),("PSYNCH_CVCLRPREPOST",312),
    ("AIO_FSYNC",313),("AIO_RETURN",314),("AIO_SUSPEND",315),
    ("AIO_CANCEL",316),("AIO_ERROR",317),("AIO_READ",318),("AIO_WRITE",319),
    ("LIO_LISTIO",320),("IOPOLICYSYS",322),("PROCESS_POLICY",323),
    ("MLOCKALL",324),("MUNLOCKALL",325),("ISSETUGID",327),
    ("PTHREAD_KILL",328),("PTHREAD_SIGMASK",329),("SIGWAIT",330),
    ("DISABLE_THREADSIGNAL",331),("PTHREAD_MARKCANCEL",332),
    ("PTHREAD_CANCELED",333),("CONNECT_NOCANCEL",343),
    ("SENDMSG_NOCANCEL",347),("RECVFROM_NOCANCEL",348),
    ("ACCEPT_NOCANCEL",349),("MMAP",197),("LSTAT",340),("STAT",338),
    ("FSTAT",339),("GETDIRENTRIES",196),("MMAP_EXTENDED",194),
    ("GETDIRENTRIES64",344),("LSTAT64",340),("FSTAT64",339),("STAT64",338),
]
d(f"MACOS_SYS_{name}", str(val))

# ──────────────────────────────────────────────────────────────
sec("§17  WINDOWS NT NATIVE API SYSCALL NUMBERS\n//     ⚠  These vary by Windows version! Numbers below are Windows 11 22H2.\n//     Use NtCurrentTeb()->PEB→ntdll for runtime lookup in production.")
sub("NtXxx syscall numbers (Windows 11 22H2 / Server 2022)")
nt_sys = [
    ("NtAccessCheck",0x00),("NtWorkerFactoryWorkerReady",0x01),
    ("NtAcceptConnectPort",0x02),("NtMapUserPhysicalPagesScatter",0x03),
    ("NtWaitForSingleObject",0x04),("NtCallbackReturn",0x05),
    ("NtReadFile",0x06),("NtDeviceIoControlFile",0x07),
    ("NtWriteFile",0x08),("NtRemoveIoCompletion",0x09),
    ("NtReleaseSemaphore",0x0A),("NtReplyWaitReceivePort",0x0B),
    ("NtReplyPort",0x0C),("NtSetInformationThread",0x0D),
    ("NtSetEvent",0x0E),("NtClose",0x0F),
    ("NtQueryObject",0x10),("NtQueryInformationFile",0x11),
    ("NtOpenKey",0x12),("NtEnumerateValueKey",0x13),
    ("NtFindAtom",0x14),("NtQueryDefaultLocale",0x15),
    ("NtQueryKey",0x16),("NtQueryValueKey",0x17),
    ("NtAllocateVirtualMemory",0x18),("NtQueryInformationProcess",0x19),
    ("NtWaitForMultipleObjects32",0x1A),("NtWriteFileGather",0x1B),
    ("NtSetInformationProcess",0x1C),("NtCreateKey",0x1D),
    ("NtFreeVirtualMemory",0x1E),("NtImpersonateClientOfPort",0x1F),
    ("NtReleaseMutant",0x20),("NtQueryInformationToken",0x21),
    ("NtRequestWaitReplyPort",0x22),("NtQueryVirtualMemory",0x23),
    ("NtOpenThreadToken",0x24),("NtQueryInformationThread",0x25),
    ("NtOpenProcess",0x26),("NtSetInformationFile",0x27),
    ("NtMapViewOfSection",0x28),("NtAccessCheckAndAuditAlarm",0x29),
    ("NtUnmapViewOfSection",0x2A),("NtReplyWaitReceivePortEx",0x2B),
    ("NtTerminateProcess",0x2C),("NtSetEventBoostPriority",0x2D),
    ("NtReadFileScatter",0x2E),("NtOpenThreadTokenEx",0x2F),
    ("NtOpenProcessTokenEx",0x30),("NtQueryPerformanceCounter",0x31),
    ("NtEnumerateKey",0x32),("NtOpenFile",0x33),
    ("NtDelayExecution",0x34),("NtQueryDirectoryFile",0x35),
    ("NtQuerySystemInformation",0x36),("NtOpenSection",0x37),
    ("NtQueryTimer",0x38),("NtFsControlFile",0x39),
    ("NtWriteVirtualMemory",0x3A),("NtCloseObjectAuditAlarm",0x3B),
    ("NtDuplicateObject",0x3C),("NtQueryAttributesFile",0x3D),
# ... previous NtXxx syscalls ...
    ("NtClearEvent",0x3E),("NtReadVirtualMemory",0x3F),
    ("NtOpenEvent",0x40),("NtAdjustPrivilegesToken",0x41),
    ("NtDuplicateToken",0x42),("NtContinue",0x43),
]

# 1. Fix the loop that was truncated
for name, val in nt_sys:
    d(f"WINNT_SYS_{name}", str(val))

# 2. Add the missing #endif for the header guard
s()
s("#endif // EMIT_DICTIONARY_H")

# 3. Write the stored lines to the header file
output_filename = "emit_dictionary.h"
with open(output_filename, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")

print(f"Successfully generated {output_filename} with {len(lines)} lines.")

    