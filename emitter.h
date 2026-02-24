#pragma once
// ============================================================
//  emitter.h  —  The Emit Language Engine
//  Supports: C-style comments, multi-token #define macros,
//  #else, #include, signed types, emit_dictionary.h imports,
//  expression evaluation, and clean forward-reference patching.
// ============================================================

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <functional>
#include <cstdint>

using Byte       = uint8_t;
using ByteStream = std::vector<Byte>;   // alias kept for main.cpp compatibility

// ============================================================
//  Token Types
// ============================================================
enum class TokenType {
    // --- Emit core keywords ---
    EMIT,
    EMIT_SIZE,
    EMIT_STR,          // NEW: null-terminated string emit
    PLACE_EMIT,
    LABEL,
    STRING_DATA,
    JUMP_TO,
    JUMP_REL,
    LEA_REL,
    ALIGN,

    // --- Data width types ---
    U8, U16, U32, U64,
    I8, I16, I32, I64,   // NEW: signed variants

    // --- Preprocessor directives ---
    DEFINE,
    INCLUDE,           // #include
    IMPORT,            // #import (alias for #include)
    IFDEF,
    IFNDEF,
    ELSE_DIR,          // NEW: #else
    ENDIF,
    UNDEF,

    // --- C-like language constructs ---
    STRUCT,
    ENUM,
    CONST,
    TYPEDEF,
    FUNC,
    RETURN,
    IF,
    ELSE,
    WHILE,
    FOR,
    BREAK,
    CONTINUE,

    // --- Literals ---
    NUMBER,
    HEX_NUMBER,
    STRING,
    IDENTIFIER,

    // --- Operators ---
    EQ,         // ==
    NEQ,        // !=
    LTE,        // <=
    GTE,        // >=
    LSHIFT,     // <<
    RSHIFT,     // >>
    AND,        // &&
    OR,         // ||
    ARROW,      // ->

    ASSIGN,     // =
    PLUS,       // +
    MINUS,      // -
    STAR,       // *
    SLASH,      // /
    PERCENT,    // %
    AMPERSAND,  // &
    PIPE,       // |
    CARET,      // ^
    TILDE,      // ~
    NOT,        // !
    LT,         // <
    GT,         // >

    // --- Punctuation ---
    LBRACE,     // {
    RBRACE,     // }
    LBRACKET,   // [
    RBRACKET,   // ]
    LPAREN,     // (
    RPAREN,     // )
    SEMICOLON,  // ;
    COMMA,      // ,
    DOT,        // .
    COLON,      // :

    // --- Special ---
    NEWLINE,
    END_OF_FILE,

    // --- Custom / user-registered ---
    CUSTOM_KEYWORD
};

// ============================================================
//  Token
// ============================================================
struct Token {
    TokenType   type;
    std::string value;
    size_t      line   = 0;
    size_t      column = 0;
};

// ============================================================
//  Value  (used by definitions / preprocessor)
// ============================================================
class Value {
public:
    enum class Type { NONE, INT, STRING };

    Type type = Type::NONE;

    Value() = default;
    explicit Value(int64_t v)           : type(Type::INT),    intVal(v)  {}
    explicit Value(const std::string& s): type(Type::STRING), strVal(s)  {}

    int64_t            asInt()    const { return intVal; }
    const std::string& asString() const { return strVal; }

private:
    int64_t     intVal = 0;
    std::string strVal;
};

// ============================================================
//  Definition  (stores both simple values AND multi-token bodies)
// ============================================================
struct Definition {
    std::string        name;
    Value              value;           // Used when body is empty (simple #define FOO 42)
    std::vector<Token> body;            // Multi-token body for real macro expansion
    bool               isFunction = false;
    std::vector<std::string> params;
};

// ============================================================
//  Label
// ============================================================
struct Label {
    std::string name;
    size_t      offset  = 0;
    bool        defined = false;
};

// ============================================================
//  ForwardRef
// ============================================================
struct ForwardRef {
    std::string labelName;
    std::string targetLabel2;   // Used for EMIT_SIZE end-label
    size_t      location  = 0;
    size_t      size      = 4;
    bool        relative  = false;
    bool        isSizeCalc= false;
};

// ============================================================
//  Struct / Enum defs  (reserved for future parse features)
// ============================================================
struct StructField {
    std::string name;
    TokenType   type;
    size_t      count = 1;
};

struct StructDef {
    std::string            name;
    std::vector<StructField> fields;
};

struct EnumDef {
    std::string                     name;
    std::map<std::string, int64_t>  values;
};

// ============================================================
//  Emitter
// ============================================================
using KeywordHandler = std::function<bool()>;

class Emitter {
public:
    Emitter();

    // --- Public API ---
    bool loadSource(const std::string& filename);
    bool loadSourceFromString(const std::string& src);   // NEW: inline source
    bool parseAndEmit();
    bool writeOutput(const std::string& filename);
    void tokenize();   // exposed so sub-emitters can use it

    const std::string& getError()        const { return lastError; }
    const ByteStream&  getBytes()        const { return byteStream; }
    const ByteStream&  getByteStream()   const { return byteStream; }          // main.cpp compat
    size_t             getCurrentOffset() const { return byteStream.size(); }  // main.cpp compat

    // --- Custom keyword registration ---
    void registerKeyword(const std::string& keyword,
                         TokenType          tokenType,
                         KeywordHandler     handler);

    // --- Expose for sub-emitters (PLACE_EMIT) ---
    std::vector<Token> tokens;
    size_t             currentToken = 0;

private:
    // ---- Source & stream state ----
    std::string        sourceCode;
    ByteStream         byteStream;
    std::string        lastError;

    // ---- Tokenizer helpers ----
    TokenType getTokenType(const std::string& str);

    bool isWhitespace(char c);
    bool isDigit(char c);
    bool isHexDigit(char c);
    bool isAlpha(char c);
    bool isAlphaNum(char c);

    // ---- Preprocessor ----
    void preprocess();
    bool currentlySkipping() const;

    std::vector<bool> ifdefStack;
    std::vector<bool> ifdefWasTaken;   // NEW: track whether the if-branch was taken

    // ---- Definitions / macros ----
    std::map<std::string, Definition> definitions;
    void  addDefinition(const std::string& name, const Value& value);
    void  addDefinitionBody(const std::string& name, std::vector<Token> body);  // NEW
    bool  hasDefinition(const std::string& name) const;
    Value getDefinition(const std::string& name) const;
    bool  removeDefinition(const std::string& name);  // for #undef

    // ---- Expression evaluator for #define math ----
    int64_t evalExpr(const std::vector<Token>& toks, size_t& i);
    int64_t evalOr(const std::vector<Token>& toks, size_t& i);
    int64_t evalAnd(const std::vector<Token>& toks, size_t& i);
    int64_t evalBitOr(const std::vector<Token>& toks, size_t& i);
    int64_t evalBitXor(const std::vector<Token>& toks, size_t& i);
    int64_t evalBitAnd(const std::vector<Token>& toks, size_t& i);
    int64_t evalShift(const std::vector<Token>& toks, size_t& i);
    int64_t evalAdd(const std::vector<Token>& toks, size_t& i);
    int64_t evalMul(const std::vector<Token>& toks, size_t& i);
    int64_t evalUnary(const std::vector<Token>& toks, size_t& i);
    int64_t evalPrimary(const std::vector<Token>& toks, size_t& i);

    // ---- Labels & forward refs ----
    std::map<std::string, Label> labels;
    std::vector<ForwardRef>      forwardRefs;

    void defineLabel(const std::string& name);
    void addForwardRef(const std::string& labelName, size_t size, bool relative = false);
    bool resolveForwardReferences();

    // ---- Struct / enum storage ----
    std::map<std::string, StructDef> structs;
    std::map<std::string, EnumDef>   enums;
    void addStruct(const std::string& name, const StructDef& def);
    void addEnum(const std::string& name, const EnumDef& def);

    // ---- Custom keywords ----
    std::unordered_map<std::string, TokenType> customKeywords;
    std::map<TokenType, KeywordHandler> keywordHandlers;

    // ---- Parser ----
    bool parseStatement();
    bool parseEmit();
    bool parseEmitSize();
    bool parseEmitStr();       // NEW
    bool parsePlaceEmit();
    bool parseLabel();
    bool parseStringData();
    bool parseJumpTo();
    bool parseLeaRel();
    bool parseAlign();

    // ---- Emit helpers ----
    void emitByte(Byte b);
    void emitBytes(const std::vector<Byte>& bytes);
    void emitU16(uint16_t val, bool littleEndian = true);
    void emitU32(uint32_t val, bool littleEndian = true);
    void emitU64(uint64_t val, bool littleEndian = true);
    void emitString(const std::string& str, bool nullTerminate = false);
    void align(size_t boundary, Byte fillByte = 0x00);

    // ---- Token navigation ----
    Token& peek(int offset = 0);
    Token& advance();
    bool   expect(TokenType type);
    bool   match(TokenType type);
    void   skipNewlines();

    uint64_t parseNumber(const std::string& str);
    bool     isNumericToken(TokenType t) const;

    // ---- Error helpers ----
    void setError(const std::string& msg);
    std::string tokenTypeName(TokenType t) const;
    std::string expectError(TokenType expected, const Token& got) const;
};