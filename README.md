Temporary AI defined readme.....will be replaced in later updates to be more accurate and better defined.
---

The Preprocessed Symbolic Binary Composer (Early edition many changes will likely be made)

A format-agnostic, two-pass engine for authoring structured binary files through symbolic labels, compile-time expressions, and C-style preprocessor logic.
Technical Definition

The Composer is a metadata-driven binary synthesis tool. It bridges the gap between raw hex editing and high-level systems programming by providing a logical framework for byte-stream arrangement. It is uniquely system-agnostic, meaning it contains no hard-coded knowledge of specific ISAs (like x86 or ARM) or file formats (like ELF or PE). Instead, it provides the mathematical and symbolic primitives necessary to define those formats via external dictionaries.
Core Engine Capabilities (Verified by Source)
1. Full-Featured C-Style Preprocessing

The engine implements a robust preprocessing pass (preprocess()) that supports:

    Multi-Token Macros: #define supports complex, multi-token bodies for macro expansion.

    Conditional Compilation: Full #ifdef, #ifndef, #else, and #endif logic using an internal ifdefStack.

    Token-Splice Inclusion: #include and #import perform recursive token-level splicing, allowing the engine to ingest C-compatible .h files containing constants and macros.

    Macro Undefinition: Support for #undef to manage the definition namespace.

2. Symbolic Label & Forward Reference System

The engine handles the "addressing problem" through a two-pass resolution system:

    Labeling: Define arbitrary points in the binary using LABEL.

    Forward Reference Patching: resolveForwardReferences() automatically calculates and patches 32-bit and 64-bit offsets for labels defined later in the stream.

    Relative Displacement: LEA_REL and JUMP_REL automatically calculate PC-relative distances (Target−Current), essential for position-independent code (PIC).

    Range Calculation: EMIT_SIZE calculates the distance between two labels at compile-time.

3. Recursive Composition (PLACE_EMIT)

The unique PLACE_EMIT directive allows for template-driven development. It triggers a nested parse-pass on external files, splicing the resulting token stream into the current context. This enables the use of "Boilerplate Templates" (e.g., standard ELF or PE headers) without polluting the main logic.
4. Agnostic Emission & Data Widths

    Signed/Unsigned Integers: Native support for u8, u16, u32, u64 and signed i8, i16, i32, i64.

    Expression Evaluator: A recursive-descent evalExpr handler that supports arithmetic and bitwise operations: + - * / | & ^ << >>.

    Alignment & Padding: Explicit ALIGN and PAD logic for page-alignment and structure-padding requirements.

Project Architecture

    emitter.cpp / emitter.h: The core engine. It manages the byteStream, the symbolTable (labels), and the preprocessor logic.

    emit_dictionary.h: The standard library. It defines the "language" of specific formats (ELF magic, JPEG markers, x86-64 syscall macros) using the engine’s preprocessor.

    main.cpp: The CLI driver that orchestrates the load-parse-write lifecycle.

Workflow Comparison
Feature	Traditional Assembler	Symbolic Binary Composer
ISA Knowledge	Hard-coded (e.g., x86 instructions)	Agnostic (User-defined via macros)
File Format	Specific (Outputs .o, .obj)	Universal (Outputs raw binary truth)
Labels	Memory addresses	Symbolic Offsets
Logic	Instruction-focused	Structure-focused
Usage Synopsis

By describing your file in .emit syntax, you can generate a working Linux ELF executable, a valid PNG image, or a custom bootloader. The engine handles the math, the alignment, and the relative jumps; you provide the architectural blueprint.
