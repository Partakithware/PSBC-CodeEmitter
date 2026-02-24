// ============================================================
//  emitter.cpp  —  The Emit Language Engine Implementation
//
//  Improvements over original:
//   • // line comments  and  /* */ block comments
//   • Clean # preprocessor detection (no hacky char checks)
//   • Multi-token #define bodies (real C-preprocessor macro expansion)
//   • #else support
//   • #include / #import processed at preprocess time (token splice)
//   • #undef
//   • i8 / i16 / i32 / i64 signed emit types
//   • EMIT_STR for null-terminated strings
//   • Simple expression evaluator for #define math (+ - * / | & ^ << >>)
//   • peek(offset) for lookahead
//   • Optional semicolons / commas between values
//   • Clear "Expected X, got Y at line L:C" error messages
//   • loadSourceFromString for inline source
// ============================================================

#include "emitter.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <cassert>

// ============================================================
//  Constructor
// ============================================================
Emitter::Emitter() : currentToken(0) {}

// ============================================================
//  Source Loading
// ============================================================
bool Emitter::loadSource(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        setError("Could not open file: " + filename);
        return false;
    }
    std::stringstream buf;
    buf << file.rdbuf();
    sourceCode = buf.str();
    return true;
}

bool Emitter::loadSourceFromString(const std::string& src) {
    sourceCode = src;
    return true;
}

// ============================================================
//  Tokenizer helpers
// ============================================================
bool Emitter::isWhitespace(char c) { return c == ' ' || c == '\t' || c == '\r'; }
bool Emitter::isDigit(char c)      { return c >= '0' && c <= '9'; }
bool Emitter::isAlpha(char c)      { return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'; }
bool Emitter::isAlphaNum(char c)   { return isAlpha(c) || isDigit(c); }
bool Emitter::isHexDigit(char c) {
    return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');
}
bool Emitter::isNumericToken(TokenType t) const {
    return t == TokenType::NUMBER || t == TokenType::HEX_NUMBER;
}

// ============================================================
//  getTokenType  —  keyword table
// ============================================================
TokenType Emitter::getTokenType(const std::string& s) {
    // Custom keywords take priority
    auto it = customKeywords.find(s);
    if (it != customKeywords.end()) return it->second;

    // Preprocessor directives
    if (s == "#define")  return TokenType::DEFINE;
    if (s == "#include") return TokenType::INCLUDE;
    if (s == "#import")  return TokenType::IMPORT;
    if (s == "#ifdef")   return TokenType::IFDEF;
    if (s == "#ifndef")  return TokenType::IFNDEF;
    if (s == "#else")    return TokenType::ELSE_DIR;
    if (s == "#endif")   return TokenType::ENDIF;
    if (s == "#undef")   return TokenType::UNDEF;

    // Emit keywords
    if (s == "EMIT")        return TokenType::EMIT;
    if (s == "EMIT_SIZE")   return TokenType::EMIT_SIZE;
    if (s == "EMIT_STR")    return TokenType::EMIT_STR;
    if (s == "PLACE_EMIT")  return TokenType::PLACE_EMIT;
    if (s == "LABEL")       return TokenType::LABEL;
    if (s == "STRING_DATA") return TokenType::STRING_DATA;
    if (s == "JUMP_TO")     return TokenType::JUMP_TO;
    if (s == "JUMP_REL")    return TokenType::JUMP_REL;
    if (s == "LEA_REL")     return TokenType::LEA_REL;
    if (s == "ALIGN")       return TokenType::ALIGN;

    // Unsigned integer widths
    if (s == "u8")  return TokenType::U8;
    if (s == "u16") return TokenType::U16;
    if (s == "u32") return TokenType::U32;
    if (s == "u64") return TokenType::U64;

    // Signed integer widths
    if (s == "i8")  return TokenType::I8;
    if (s == "i16") return TokenType::I16;
    if (s == "i32") return TokenType::I32;
    if (s == "i64") return TokenType::I64;

    // C-like keywords
    if (s == "struct")    return TokenType::STRUCT;
    if (s == "enum")      return TokenType::ENUM;
    if (s == "const")     return TokenType::CONST;
    if (s == "typedef")   return TokenType::TYPEDEF;
    if (s == "func")      return TokenType::FUNC;
    if (s == "return")    return TokenType::RETURN;
    if (s == "if")        return TokenType::IF;
    if (s == "else")      return TokenType::ELSE;
    if (s == "while")     return TokenType::WHILE;
    if (s == "for")       return TokenType::FOR;
    if (s == "break")     return TokenType::BREAK;
    if (s == "continue")  return TokenType::CONTINUE;

    return TokenType::IDENTIFIER;
}

// ============================================================
//  Tokenizer
// ============================================================
void Emitter::tokenize() {
    tokens.clear();
    size_t pos    = 0;
    size_t line   = 1;
    size_t column = 1;
    const size_t len = sourceCode.length();

    auto cur  = [&]() -> char   { return pos < len ? sourceCode[pos] : '\0'; };
    auto next = [&]() -> char   { return pos+1 < len ? sourceCode[pos+1] : '\0'; };

    while (pos < len) {
        char c = cur();

        // ---- Whitespace (non-newline) ----
        if (c == ' ' || c == '\t' || c == '\r') {
            pos++; column++;
            continue;
        }

        // ---- Newline ----
        if (c == '\n') {
            tokens.push_back({TokenType::NEWLINE, "\n", line, column});
            pos++; line++; column = 1;
            continue;
        }

        // ---- C++ style // line comment ----
        if (c == '/' && next() == '/') {
            while (pos < len && cur() != '\n') { pos++; }
            continue;
        }

        // ---- C style /* block comment */ ----
        if (c == '/' && next() == '*') {
            pos += 2; column += 2;
            while (pos < len) {
                if (cur() == '\n') {
                    tokens.push_back({TokenType::NEWLINE, "\n", line, column});
                    line++; column = 1; pos++;
                } else if (cur() == '*' && next() == '/') {
                    pos += 2; column += 2;
                    break;
                } else {
                    column++; pos++;
                }
            }
            continue;
        }

        // ---- # character: either a preprocessor directive or a line comment ----
        if (c == '#') {
            // Peek ahead to see if it's a known directive keyword
            size_t peekPos = pos + 1;
            while (peekPos < len && (sourceCode[peekPos]==' '||sourceCode[peekPos]=='\t'))
                peekPos++;

            // Collect what follows '#'
            size_t kwStart = peekPos;
            while (peekPos < len && isAlpha(sourceCode[peekPos])) peekPos++;
            std::string kw = "#" + sourceCode.substr(kwStart, peekPos - kwStart);

            TokenType tt = getTokenType(kw);
            if (tt != TokenType::IDENTIFIER) {
                // It's a real directive — emit its token
                size_t colStart = column;
                pos = peekPos;
                column += (pos - (pos - kw.size() + 1)); // rough
                tokens.push_back({tt, kw, line, colStart});
            } else {
                // It's a comment — skip to end of line
                while (pos < len && cur() != '\n') { pos++; }
            }
            continue;
        }

        // ---- String literal ----
        if (c == '"') {
            std::string str;
            size_t startCol = column;
            pos++; column++;
            while (pos < len && cur() != '"') {
                if (cur() == '\\' && pos+1 < len) {
                    pos++; column++;
                    char e = cur();
                    switch (e) {
                        case 'n': str += '\n'; break;
                        case 't': str += '\t'; break;
                        case 'r': str += '\r'; break;
                        case '\\': str += '\\'; break;
                        case '"': str += '"'; break;
                        case '0': str += '\0'; break;
                        default: str += e; break;
                    }
                } else {
                    str += cur();
                }
                pos++; column++;
            }
            if (pos < len) { pos++; column++; } // closing "
            tokens.push_back({TokenType::STRING, str, line, startCol});
            continue;
        }

        // ---- Identifier / keyword ----
        if (isAlpha(c)) {
            std::string id;
            size_t startCol = column;
            while (pos < len && isAlphaNum(cur())) {
                id += cur(); pos++; column++;
            }
            TokenType tt = getTokenType(id);
            // Bare hex identifiers like "FF", "4D" → HEX_NUMBER
            if (tt == TokenType::IDENTIFIER && id.size() >= 1 && id.size() <= 2) {
                bool allHex = true;
                for (char ch : id) if (!isHexDigit(ch)) { allHex = false; break; }
                if (allHex) tt = TokenType::HEX_NUMBER;
            }
            tokens.push_back({tt, id, line, startCol});
            continue;
        }

        // ---- Numbers ----
        if (isDigit(c)) {
            std::string val;
            size_t startCol = column;
            bool hex = false;
            if (c == '0' && (next() == 'x' || next() == 'X')) {
                hex = true;
                val = "0x"; pos += 2; column += 2;
                while (pos < len && isHexDigit(cur())) { val += cur(); pos++; column++; }
            } else {
                while (pos < len && isHexDigit(cur())) { val += cur(); pos++; column++; }
                // Decide: if all chars are valid decimal digits → NUMBER, else HEX_NUMBER
                bool allDec = true;
                for (char ch : val) if (ch > '9') { allDec = false; break; }
                if (!allDec) {
                    tokens.push_back({TokenType::HEX_NUMBER, val, line, startCol});
                    continue;
                }
            }
            tokens.push_back({hex ? TokenType::HEX_NUMBER : TokenType::NUMBER, val, line, startCol});
            continue;
        }

        // ---- Two-character operators ----
        auto twoChar = [&](char c2, TokenType tt, const char* sym) -> bool {
            if (c == c2 && next() == sym[1]) {
                tokens.push_back({tt, sym, line, column});
                pos += 2; column += 2; return true;
            }
            return false;
        };
        (void)twoChar; // suppress warning if unused

        if (c == '=' && next() == '=') { tokens.push_back({TokenType::EQ,"==",line,column}); pos+=2;column+=2;continue; }
        if (c == '!' && next() == '=') { tokens.push_back({TokenType::NEQ,"!=",line,column}); pos+=2;column+=2;continue; }
        if (c == '<' && next() == '=') { tokens.push_back({TokenType::LTE,"<=",line,column}); pos+=2;column+=2;continue; }
        if (c == '>' && next() == '=') { tokens.push_back({TokenType::GTE,">=",line,column}); pos+=2;column+=2;continue; }
        if (c == '<' && next() == '<') { tokens.push_back({TokenType::LSHIFT,"<<",line,column}); pos+=2;column+=2;continue; }
        if (c == '>' && next() == '>') { tokens.push_back({TokenType::RSHIFT,">>",line,column}); pos+=2;column+=2;continue; }
        if (c == '&' && next() == '&') { tokens.push_back({TokenType::AND,"&&",line,column}); pos+=2;column+=2;continue; }
        if (c == '|' && next() == '|') { tokens.push_back({TokenType::OR,"||",line,column}); pos+=2;column+=2;continue; }
        if (c == '-' && next() == '>') { tokens.push_back({TokenType::ARROW,"->",line,column}); pos+=2;column+=2;continue; }

        // ---- Single-character tokens ----
        {
            TokenType tt = TokenType::END_OF_FILE;
            std::string sym(1, c);
            switch (c) {
                case '=': tt = TokenType::ASSIGN;    break;
                case '+': tt = TokenType::PLUS;      break;
                case '-': tt = TokenType::MINUS;     break;
                case '*': tt = TokenType::STAR;      break;
                case '/': tt = TokenType::SLASH;     break;
                case '%': tt = TokenType::PERCENT;   break;
                case '&': tt = TokenType::AMPERSAND; break;
                case '|': tt = TokenType::PIPE;      break;
                case '^': tt = TokenType::CARET;     break;
                case '~': tt = TokenType::TILDE;     break;
                case '!': tt = TokenType::NOT;       break;
                case '<': tt = TokenType::LT;        break;
                case '>': tt = TokenType::GT;        break;
                case '{': tt = TokenType::LBRACE;    break;
                case '}': tt = TokenType::RBRACE;    break;
                case '[': tt = TokenType::LBRACKET;  break;
                case ']': tt = TokenType::RBRACKET;  break;
                case '(': tt = TokenType::LPAREN;    break;
                case ')': tt = TokenType::RPAREN;    break;
                case ';': tt = TokenType::SEMICOLON; break;
                case ',': tt = TokenType::COMMA;     break;
                case '.': tt = TokenType::DOT;       break;
                case ':': tt = TokenType::COLON;     break;
                default: pos++; column++; continue; // skip unknown
            }
            tokens.push_back({tt, sym, line, column});
            pos++; column++;
        }
    }
    tokens.push_back({TokenType::END_OF_FILE, "", line, column});
}

// ============================================================
//  Expression evaluator for #define constant math
//  Handles: || && | ^ & << >> + - * / % unary - ~ !
// ============================================================
int64_t Emitter::evalPrimary(const std::vector<Token>& toks, size_t& i) {
    if (i >= toks.size()) return 0;
    const Token& t = toks[i];

    if (t.type == TokenType::LPAREN) {
        i++;
        int64_t v = evalExpr(toks, i);
        if (i < toks.size() && toks[i].type == TokenType::RPAREN) i++;
        return v;
    }
    if (t.type == TokenType::NUMBER || t.type == TokenType::HEX_NUMBER) {
        i++;
        return (int64_t)parseNumber(t.value);
    }
    if (t.type == TokenType::IDENTIFIER) {
        i++;
        if (hasDefinition(t.value)) {
            Value v = getDefinition(t.value);
            if (v.type == Value::Type::INT) return v.asInt();
        }
        return 0;
    }
    return 0;
}

int64_t Emitter::evalUnary(const std::vector<Token>& toks, size_t& i) {
    if (i < toks.size()) {
        if (toks[i].type == TokenType::MINUS) { i++; return -evalPrimary(toks, i); }
        if (toks[i].type == TokenType::TILDE) { i++; return ~evalPrimary(toks, i); }
        if (toks[i].type == TokenType::NOT)   { i++; return !evalPrimary(toks, i); }
    }
    return evalPrimary(toks, i);
}

int64_t Emitter::evalMul(const std::vector<Token>& toks, size_t& i) {
    int64_t v = evalUnary(toks, i);
    while (i < toks.size()) {
        if (toks[i].type == TokenType::STAR)    { i++; v *= evalUnary(toks, i); }
        else if (toks[i].type == TokenType::SLASH && toks[i].value == "/")   {
            i++; int64_t r = evalUnary(toks, i); v = r ? v/r : 0;
        }
        else if (toks[i].type == TokenType::PERCENT) { i++; int64_t r=evalUnary(toks,i); v=r?v%r:0; }
        else break;
    }
    return v;
}

int64_t Emitter::evalAdd(const std::vector<Token>& toks, size_t& i) {
    int64_t v = evalMul(toks, i);
    while (i < toks.size()) {
        if (toks[i].type == TokenType::PLUS)  { i++; v += evalMul(toks, i); }
        else if (toks[i].type == TokenType::MINUS) { i++; v -= evalMul(toks, i); }
        else break;
    }
    return v;
}

int64_t Emitter::evalShift(const std::vector<Token>& toks, size_t& i) {
    int64_t v = evalAdd(toks, i);
    while (i < toks.size()) {
        if (toks[i].type == TokenType::LSHIFT) { i++; v <<= evalAdd(toks, i); }
        else if (toks[i].type == TokenType::RSHIFT) { i++; v >>= evalAdd(toks, i); }
        else break;
    }
    return v;
}

int64_t Emitter::evalBitAnd(const std::vector<Token>& toks, size_t& i) {
    int64_t v = evalShift(toks, i);
    while (i < toks.size() && toks[i].type == TokenType::AMPERSAND) { i++; v &= evalShift(toks, i); }
    return v;
}

int64_t Emitter::evalBitXor(const std::vector<Token>& toks, size_t& i) {
    int64_t v = evalBitAnd(toks, i);
    while (i < toks.size() && toks[i].type == TokenType::CARET) { i++; v ^= evalBitAnd(toks, i); }
    return v;
}

int64_t Emitter::evalBitOr(const std::vector<Token>& toks, size_t& i) {
    int64_t v = evalBitXor(toks, i);
    while (i < toks.size() && toks[i].type == TokenType::PIPE) { i++; v |= evalBitXor(toks, i); }
    return v;
}

int64_t Emitter::evalAnd(const std::vector<Token>& toks, size_t& i) {
    int64_t v = evalBitOr(toks, i);
    while (i < toks.size() && toks[i].type == TokenType::AND) { i++; v = v && evalBitOr(toks, i); }
    return v;
}

int64_t Emitter::evalOr(const std::vector<Token>& toks, size_t& i) {
    int64_t v = evalAnd(toks, i);
    while (i < toks.size() && toks[i].type == TokenType::OR) { i++; v = v || evalAnd(toks, i); }
    return v;
}

int64_t Emitter::evalExpr(const std::vector<Token>& toks, size_t& i) {
    return evalOr(toks, i);
}

// ============================================================
//  Preprocessor
//  Handles: #define (multi-token bodies), #include/#import,
//           #ifdef, #ifndef, #else, #endif, #undef
//           + macro expansion with token splicing
// ============================================================

// Helper: load and tokenize a file, returning its tokens (minus EOF)
static std::vector<Token> loadAndTokenizeFile(const std::string& filename) {
    Emitter sub;
    if (!sub.loadSource(filename)) {
        return {};
    }
    sub.tokenize();
    // strip final EOF
    if (!sub.tokens.empty() && sub.tokens.back().type == TokenType::END_OF_FILE)
        sub.tokens.pop_back();
    return sub.tokens;
}

void Emitter::preprocess() {
    ifdefStack.clear();
    ifdefWasTaken.clear();

    // We process in multiple passes to handle #include splicing:
    // Use an index-based loop so we can splice in new tokens.
    std::vector<Token> out;
    out.reserve(tokens.size());

    for (size_t i = 0; i < tokens.size(); ) {
        Token& t = tokens[i];

        // ---- #define ----
        if (t.type == TokenType::DEFINE) {
            if (currentlySkipping()) { i++; continue; }
            i++; // skip #define

            // Consume any newlines / spaces around the name
            while (i < tokens.size() && tokens[i].type == TokenType::NEWLINE) i++;

            if (i >= tokens.size() || tokens[i].type == TokenType::END_OF_FILE) {
                setError("#define without a name");
                return;
            }
            std::string name = tokens[i].value;
            i++; // skip name

            // Collect body tokens until newline (may be empty = "defined" flag)
            std::vector<Token> body;
            while (i < tokens.size() &&
                   tokens[i].type != TokenType::NEWLINE &&
                   tokens[i].type != TokenType::END_OF_FILE) {
                body.push_back(tokens[i++]);
            }

            if (body.empty()) {
                // #define FLAG  (no value — just "is defined")
                addDefinition(name, Value(int64_t(1)));
            } else {
                // Try to evaluate as a pure constant expression first
                size_t ei = 0;
                // Check if all tokens are numeric / operators (pure expression)
                bool pureExpr = true;
                for (auto& bt : body) {
                    if (bt.type == TokenType::STRING) { pureExpr = false; break; }
                    // If we have emit keywords in the body, it's a token-body macro
                    if (bt.type == TokenType::EMIT || bt.type == TokenType::U8  ||
                        bt.type == TokenType::U16  || bt.type == TokenType::U32 ||
                        bt.type == TokenType::U64  || bt.type == TokenType::I8  ||
                        bt.type == TokenType::I16  || bt.type == TokenType::I32 ||
                        bt.type == TokenType::I64  || bt.type == TokenType::HEX_NUMBER) {
                        // Could still be an expression if it's just numbers
                        if (bt.type == TokenType::EMIT) { pureExpr = false; break; }
                    }
                }

                if (pureExpr && body.size() == 1 && body[0].type == TokenType::STRING) {
                    addDefinition(name, Value(body[0].value));
                } else if (pureExpr) {
                    // Try evaluating as expression
                    try {
                        int64_t val = evalExpr(body, ei);
                        if (ei == body.size()) {
                            addDefinition(name, Value(val));
                        } else {
                            // Not fully consumed — store as token body
                            addDefinitionBody(name, body);
                        }
                    } catch (...) {
                        addDefinitionBody(name, body);
                    }
                } else {
                    // Multi-token / emit-style macro body
                    addDefinitionBody(name, body);
                }
            }
            continue;
        }

        // ---- #undef ----
        if (t.type == TokenType::UNDEF) {
            if (currentlySkipping()) { i++; continue; }
            i++;
            while (i < tokens.size() && tokens[i].type == TokenType::NEWLINE) i++;
            if (i < tokens.size()) { removeDefinition(tokens[i].value); i++; }
            continue;
        }

        // ---- #include / #import ----
        if (t.type == TokenType::INCLUDE || t.type == TokenType::IMPORT) {
            if (currentlySkipping()) { i++; continue; }
            i++;
            while (i < tokens.size() && tokens[i].type == TokenType::NEWLINE) i++;
            if (i >= tokens.size() || tokens[i].type != TokenType::STRING) {
                setError("#include requires a filename string");
                return;
            }
            std::string filename = tokens[i].value;
            i++;

            // Load and splice the file's tokens in-place into our token stream
            std::vector<Token> subTokens = loadAndTokenizeFile(filename);
            if (!subTokens.empty()) {
                // Insert after current position i (we'll process them next iteration)
                tokens.insert(tokens.begin() + i, subTokens.begin(), subTokens.end());
            }
            continue;
        }

        // ---- #ifdef ----
        if (t.type == TokenType::IFDEF) {
            i++;
            while (i < tokens.size() && tokens[i].type == TokenType::NEWLINE) i++;
            std::string name = (i < tokens.size()) ? tokens[i].value : "";
            if (i < tokens.size()) i++;
            bool def = hasDefinition(name);
            bool skip = currentlySkipping();
            ifdefStack.push_back(skip ? false : def);
            ifdefWasTaken.push_back(skip ? false : def);
            continue;
        }

        // ---- #ifndef ----
        if (t.type == TokenType::IFNDEF) {
            i++;
            while (i < tokens.size() && tokens[i].type == TokenType::NEWLINE) i++;
            std::string name = (i < tokens.size()) ? tokens[i].value : "";
            if (i < tokens.size()) i++;
            bool def = hasDefinition(name);
            bool skip = currentlySkipping();
            ifdefStack.push_back(skip ? false : !def);
            ifdefWasTaken.push_back(skip ? false : !def);
            continue;
        }

        // ---- #else ----
        if (t.type == TokenType::ELSE_DIR) {
            i++;
            if (ifdefStack.empty()) {
                setError("#else without matching #ifdef");
                return;
            }
            // Flip only if the parent context is active
            bool parentActive = true;
            for (size_t s = 0; s + 1 < ifdefStack.size(); s++)
                if (!ifdefStack[s]) { parentActive = false; break; }

            if (parentActive) {
                // Enter else branch only if we haven't already taken the if branch
                bool wasTaken = ifdefWasTaken.back();
                ifdefStack.back() = !wasTaken;
            }
            continue;
        }

        // ---- #endif ----
        if (t.type == TokenType::ENDIF) {
            i++;
            if (ifdefStack.empty()) { setError("#endif without matching #ifdef"); return; }
            ifdefStack.pop_back();
            ifdefWasTaken.pop_back();
            continue;
        }

        // ---- Skip tokens if in false block ----
        if (currentlySkipping()) {
            i++;
            continue;
        }

        // ---- Macro expansion (IDENTIFIER that has a definition) ----
        if (t.type == TokenType::IDENTIFIER && hasDefinition(t.value)) {
            Definition& def = definitions[t.value];
            i++;

            if (!def.body.empty()) {
                // Multi-token body macro: splice body tokens in at position i
                tokens.insert(tokens.begin() + i, def.body.begin(), def.body.end());
                // Don't advance i — let the next iteration re-process from here
            } else {
                // Simple value macro
                if (def.value.type == Value::Type::INT) {
                    out.push_back({TokenType::NUMBER,
                                   std::to_string(def.value.asInt()),
                                   t.line, t.column});
                } else if (def.value.type == Value::Type::STRING) {
                    out.push_back({TokenType::STRING,
                                   def.value.asString(),
                                   t.line, t.column});
                }
            }
            continue;
        }

        // ---- Pass token through ----
        out.push_back(t);
        i++;
    }

    tokens = std::move(out);
}

bool Emitter::currentlySkipping() const {
    for (bool b : ifdefStack) if (!b) return true;
    return false;
}

// ============================================================
//  Definition management
// ============================================================
void Emitter::addDefinition(const std::string& name, const Value& value) {
    definitions[name] = {name, value, {}, false, {}};
}

void Emitter::addDefinitionBody(const std::string& name, std::vector<Token> body) {
    definitions[name] = {name, Value(), body, false, {}};
}

bool Emitter::hasDefinition(const std::string& name) const {
    return definitions.find(name) != definitions.end();
}

Value Emitter::getDefinition(const std::string& name) const {
    auto it = definitions.find(name);
    return (it != definitions.end()) ? it->second.value : Value();
}

bool Emitter::removeDefinition(const std::string& name) {
    return definitions.erase(name) > 0;
}

// ============================================================
//  Custom keyword registration
// ============================================================
void Emitter::registerKeyword(const std::string& keyword,
                               TokenType tokenType,
                               KeywordHandler handler) {
    customKeywords[keyword] = tokenType;
    keywordHandlers[tokenType] = handler;
}

// ============================================================
//  Struct / Enum storage
// ============================================================
void Emitter::addStruct(const std::string& name, const StructDef& def) { structs[name] = def; }
void Emitter::addEnum(const std::string& name, const EnumDef& def)     { enums[name]   = def; }

// ============================================================
//  Main parse-and-emit loop
// ============================================================
bool Emitter::parseAndEmit() {
    tokenize();
    preprocess();
    currentToken = 0;
    byteStream.clear();
    labels.clear();
    forwardRefs.clear();

    while (peek().type != TokenType::END_OF_FILE) {
        if (peek().type == TokenType::NEWLINE    ||
            peek().type == TokenType::SEMICOLON  ||
            peek().type == TokenType::COMMA) {
            advance();
            continue;
        }
        if (peek().type == TokenType::END_OF_FILE) break;
        if (!parseStatement()) return false;
    }
    return resolveForwardReferences();
}

// ============================================================
//  parseStatement  —  dispatcher
// ============================================================
bool Emitter::parseStatement() {
    Token& t = peek();

    switch (t.type) {
        case TokenType::EMIT:       return parseEmit();
        case TokenType::EMIT_SIZE:  return parseEmitSize();
        case TokenType::EMIT_STR:   return parseEmitStr();
        case TokenType::PLACE_EMIT: return parsePlaceEmit();
        case TokenType::LABEL:      return parseLabel();
        case TokenType::STRING_DATA:return parseStringData();
        case TokenType::JUMP_TO:    return parseJumpTo();
        case TokenType::JUMP_REL:   return parseJumpTo();
        case TokenType::ALIGN:      return parseAlign();
        case TokenType::LEA_REL:    return parseLeaRel();

        // Raw hex/number bytes — emit directly as u8 stream
        case TokenType::HEX_NUMBER:
        case TokenType::NUMBER: {
            while (isNumericToken(peek().type)) {
                uint64_t v = parseNumber(peek().value);
                emitByte(static_cast<Byte>(v));
                advance();
                // Allow optional commas / spaces between raw bytes
                while (peek().type == TokenType::COMMA) advance();
            }
            return true;
        }

        // Custom keyword handlers
        default: {
            auto it = keywordHandlers.find(t.type);
            if (it != keywordHandlers.end()) {
                advance();
                return it->second();
            }
            setError("Unexpected token '" + t.value +
                     "' at line " + std::to_string(t.line) +
                     ":" + std::to_string(t.column));
            return false;
        }
    }
}

// ============================================================
//  parseEmit
// ============================================================
bool Emitter::parseEmit() {
    advance(); // skip EMIT

    // Allow optional opening brace: EMIT { ... }
    bool brace = false;
    if (peek().type == TokenType::LBRACE) { brace = true; advance(); }

    // Bare string: EMIT "hello"
    if (peek().type == TokenType::STRING) {
        emitString(peek().value, false);
        advance();
        if (brace) expect(TokenType::RBRACE);
        return true;
    }

    // Determine the data type
    TokenType dataType = peek().type;
    bool isSigned = (dataType == TokenType::I8  || dataType == TokenType::I16 ||
                     dataType == TokenType::I32  || dataType == TokenType::I64);
    bool isTyped  = (dataType == TokenType::U8   || dataType == TokenType::U16 ||
                     dataType == TokenType::U32   || dataType == TokenType::U64 || isSigned);

    if (!isTyped) {
        setError("EMIT expects u8/u16/u32/u64/i8/i16/i32/i64 or a string literal at line "
                 + std::to_string(peek().line));
        return false;
    }
    advance(); // skip type token

    // Array fill syntax: EMIT u8[count] fillValue
    if (peek().type == TokenType::LBRACKET) {
        advance();
        if (!isNumericToken(peek().type)) {
            setError("Expected count inside [...] at line " + std::to_string(peek().line));
            return false;
        }
        uint64_t count = parseNumber(peek().value);
        advance();
        if (!expect(TokenType::RBRACKET)) return false;

        if (!isNumericToken(peek().type)) {
            setError("Expected fill value after EMIT type[count] at line " +
                     std::to_string(peek().line));
            return false;
        }
        uint64_t val = parseNumber(peek().value);
        advance();

        for (uint64_t k = 0; k < count; k++) {
            switch (dataType) {
                case TokenType::U8:  case TokenType::I8:  emitByte(static_cast<Byte>(val)); break;
                case TokenType::U16: case TokenType::I16: emitU16(static_cast<uint16_t>(val)); break;
                case TokenType::U32: case TokenType::I32: emitU32(static_cast<uint32_t>(val)); break;
                case TokenType::U64: case TokenType::I64: emitU64(val); break;
                default: break;
            }
        }
        if (brace) expect(TokenType::RBRACE);
        return true;
    }

    // Also allow: EMIT u8 "string"  (emits raw bytes of string)
    if (dataType == TokenType::U8 && peek().type == TokenType::STRING) {
        emitString(peek().value, false);
        advance();
        if (brace) expect(TokenType::RBRACE);
        return true;
    }

    // Stream of values: EMIT u8 0x01 0x02 0x03  (commas optional)
    bool gotAny = false;
    while (isNumericToken(peek().type)) {
        gotAny = true;
        uint64_t val = parseNumber(peek().value);
        advance();
        switch (dataType) {
            case TokenType::U8:  case TokenType::I8:  emitByte(static_cast<Byte>(val)); break;
            case TokenType::U16: case TokenType::I16: emitU16(static_cast<uint16_t>(val)); break;
            case TokenType::U32: case TokenType::I32: emitU32(static_cast<uint32_t>(val)); break;
            case TokenType::U64: case TokenType::I64: emitU64(val); break;
            default: break;
        }
        // Allow optional comma between values
        while (peek().type == TokenType::COMMA) advance();
    }

    if (!gotAny) {
        setError("EMIT: no values provided at line " + std::to_string(peek().line));
        return false;
    }
    if (brace) expect(TokenType::RBRACE);
    return true;
}

// ============================================================
//  parseEmitStr  —  EMIT_STR "text"  emits null-terminated string
// ============================================================
bool Emitter::parseEmitStr() {
    advance(); // skip EMIT_STR
    if (peek().type != TokenType::STRING) {
        setError("EMIT_STR expects a quoted string at line " + std::to_string(peek().line));
        return false;
    }
    emitString(peek().value, true); // true = null-terminate
    advance();
    return true;
}

// ============================================================
//  parseEmitSize
// ============================================================
bool Emitter::parseEmitSize() {
    advance(); // skip EMIT_SIZE
    if (peek().type != TokenType::IDENTIFIER) {
        setError("EMIT_SIZE: expected start label at line " + std::to_string(peek().line));
        return false;
    }
    std::string startLabel = peek().value; advance();

    if (peek().type != TokenType::IDENTIFIER) {
        setError("EMIT_SIZE: expected end label at line " + std::to_string(peek().line));
        return false;
    }
    std::string endLabel = peek().value; advance();

    ForwardRef ref;
    ref.labelName    = startLabel;
    ref.targetLabel2 = endLabel;
    ref.location     = byteStream.size();
    ref.size         = 4;
    ref.isSizeCalc   = true;
    forwardRefs.push_back(ref);
    emitU32(0); // placeholder
    return true;
}

// ============================================================
//  parsePlaceEmit  —  inline-include an .emit file at parse time
// ============================================================
bool Emitter::parsePlaceEmit() {
    advance(); // skip PLACE_EMIT
    if (peek().type != TokenType::STRING) {
        setError("PLACE_EMIT: expected filename string at line " + std::to_string(peek().line));
        return false;
    }
    std::string filename = peek().value; advance();

    Emitter temp;
    if (!temp.loadSource(filename)) {
        setError("PLACE_EMIT failed: " + temp.getError());
        return false;
    }
    temp.tokenize();
    temp.preprocess();

    if (!temp.tokens.empty() && temp.tokens.back().type == TokenType::END_OF_FILE)
        temp.tokens.pop_back();

    tokens.insert(tokens.begin() + currentToken,
                  temp.tokens.begin(), temp.tokens.end());
    return true;
}

// ============================================================
//  parseAlign
// ============================================================
bool Emitter::parseAlign() {
    advance(); // skip ALIGN
    if (!isNumericToken(peek().type)) {
        setError("ALIGN: expected boundary number at line " + std::to_string(peek().line));
        return false;
    }
    uint64_t boundary = parseNumber(peek().value); advance();

    Byte fill = 0x00;
    if (isNumericToken(peek().type)) {
        fill = static_cast<Byte>(parseNumber(peek().value));
        advance();
    }
    align(boundary, fill);
    return true;
}

// ============================================================
//  parseLabel
// ============================================================
bool Emitter::parseLabel() {
    advance(); // skip LABEL
    if (peek().type != TokenType::IDENTIFIER) {
        setError("LABEL: expected identifier at line " + std::to_string(peek().line));
        return false;
    }
    defineLabel(peek().value);
    advance();
    return true;
}

// ============================================================
//  parseStringData
// ============================================================
bool Emitter::parseStringData() {
    advance(); // skip STRING_DATA
    if (peek().type != TokenType::STRING) {
        setError("STRING_DATA: expected quoted string at line " + std::to_string(peek().line));
        return false;
    }
    for (char c : peek().value) emitByte(static_cast<Byte>(c));
    advance();
    return true;
}

// ============================================================
//  parseJumpTo / parseLeaRel
// ============================================================
bool Emitter::parseJumpTo() {
    bool relative = (peek().type == TokenType::JUMP_REL);
    advance(); // skip keyword

    if (peek().type != TokenType::IDENTIFIER) {
        setError("JUMP_TO/JUMP_REL: expected label name at line " + std::to_string(peek().line));
        return false;
    }
    std::string labelName = peek().value; advance();

    addForwardRef(labelName, 4, relative);
    emitU32(0xDEADBEEF);
    return true;
}

bool Emitter::parseLeaRel() {
    advance(); // skip LEA_REL
    // Emit LEA RSI, [RIP+disp32]  opcode: 48 8D 35
    emitByte(0x48); emitByte(0x8D); emitByte(0x35);
    if (peek().type != TokenType::IDENTIFIER) {
        setError("LEA_REL: expected label name at line " + std::to_string(peek().line));
        return false;
    }
    std::string labelName = peek().value; advance();
    addForwardRef(labelName, 4, true);
    emitU32(0xDEADBEEF);
    return true;
}

// ============================================================
//  Token navigation
// ============================================================
Token& Emitter::peek(int offset) {
    size_t idx = currentToken + offset;
    if (idx >= tokens.size()) return tokens.back();
    return tokens[idx];
}

Token& Emitter::advance() {
    if (currentToken < tokens.size()) currentToken++;
    return tokens[currentToken - 1];
}

bool Emitter::expect(TokenType type) {
    if (peek().type != type) {
        setError("Expected " + tokenTypeName(type) +
                 ", got '" + peek().value + "' at line " +
                 std::to_string(peek().line) + ":" +
                 std::to_string(peek().column));
        return false;
    }
    advance();
    return true;
}

bool Emitter::match(TokenType type) {
    return peek().type == type;
}

void Emitter::skipNewlines() {
    while (peek().type == TokenType::NEWLINE) advance();
}

uint64_t Emitter::parseNumber(const std::string& s) {
    if (s.size() >= 2 && (s[0] == '0') && (s[1] == 'x' || s[1] == 'X'))
        return std::stoull(s, nullptr, 16);
    // Attempt base-16 for bare hex identifiers
    bool allHex = !s.empty();
    for (char c : s) if (!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))) { allHex=false; break; }
    if (allHex && s.size() <= 8) {
        // Could be decimal that happens to have no a-f chars, or explicit hex.
        // If > 9 only, treat as decimal; otherwise prefer decimal unless non-decimal chars present.
        bool hasHexChar = false;
        for (char c : s) if (c>'9') { hasHexChar=true; break; }
        if (hasHexChar) return std::stoull(s, nullptr, 16);
    }
    return std::stoull(s, nullptr, 10);
}

// ============================================================
//  Emission
// ============================================================
void Emitter::emitByte(Byte b)                        { byteStream.push_back(b); }
void Emitter::emitBytes(const std::vector<Byte>& bs)  { byteStream.insert(byteStream.end(), bs.begin(), bs.end()); }

void Emitter::emitU16(uint16_t v, bool le) {
    if (le) { emitByte(v&0xFF); emitByte((v>>8)&0xFF); }
    else    { emitByte((v>>8)&0xFF); emitByte(v&0xFF); }
}

void Emitter::emitU32(uint32_t v, bool le) {
    if (le) {
        emitByte(v&0xFF); emitByte((v>>8)&0xFF);
        emitByte((v>>16)&0xFF); emitByte((v>>24)&0xFF);
    } else {
        emitByte((v>>24)&0xFF); emitByte((v>>16)&0xFF);
        emitByte((v>>8)&0xFF);  emitByte(v&0xFF);
    }
}

void Emitter::emitU64(uint64_t v, bool le) {
    if (le) { for (int i=0;i<8;i++) emitByte((v>>(i*8))&0xFF); }
    else    { for (int i=7;i>=0;i--) emitByte((v>>(i*8))&0xFF); }
}

void Emitter::emitString(const std::string& s, bool nullTerm) {
    for (char c : s) emitByte(static_cast<Byte>(c));
    if (nullTerm) emitByte(0x00);
}

void Emitter::align(size_t boundary, Byte fill) {
    if (boundary == 0) return;
    size_t cur = byteStream.size();
    size_t pad = (boundary - (cur % boundary)) % boundary;
    for (size_t i = 0; i < pad; i++) emitByte(fill);
}

// ============================================================
//  Labels & forward reference resolution
// ============================================================
void Emitter::defineLabel(const std::string& name) {
    labels[name] = {name, byteStream.size(), true};
}

void Emitter::addForwardRef(const std::string& labelName, size_t size, bool relative) {
    forwardRefs.push_back({labelName, "", byteStream.size(), size, relative, false});
}

bool Emitter::resolveForwardReferences() {
    for (const auto& ref : forwardRefs) {
        auto it = labels.find(ref.labelName);
        if (it == labels.end()) {
            setError("Undefined label: '" + ref.labelName + "'");
            return false;
        }

        uint64_t finalValue = 0;

        if (ref.isSizeCalc) {
            auto it2 = labels.find(ref.targetLabel2);
            if (it2 == labels.end()) {
                setError("Undefined end label for EMIT_SIZE: '" + ref.targetLabel2 + "'");
                return false;
            }
            finalValue = it2->second.offset - it->second.offset;
        } else {
            uint64_t address = it->second.offset;
            if (ref.relative) {
                finalValue = static_cast<uint64_t>(
                    static_cast<int64_t>(address) -
                    static_cast<int64_t>(ref.location + ref.size));
            } else {
                finalValue = address;
            }
        }

        for (size_t i = 0; i < ref.size; i++)
            byteStream[ref.location + i] = (finalValue >> (i * 8)) & 0xFF;
    }
    return true;
}

// ============================================================
//  Output
// ============================================================
bool Emitter::writeOutput(const std::string& filename) {
    std::ofstream f(filename, std::ios::binary);
    if (!f.is_open()) {
        setError("Could not open output file: " + filename);
        return false;
    }
    f.write(reinterpret_cast<const char*>(byteStream.data()), byteStream.size());
    return true;
}

// ============================================================
//  Error helpers
// ============================================================
void Emitter::setError(const std::string& msg) {
    lastError = msg;
    std::cerr << "[emit error] " << msg << std::endl;
}

std::string Emitter::tokenTypeName(TokenType t) const {
    switch (t) {
        case TokenType::NUMBER:     return "NUMBER";
        case TokenType::HEX_NUMBER: return "HEX_NUMBER";
        case TokenType::STRING:     return "STRING";
        case TokenType::IDENTIFIER: return "IDENTIFIER";
        case TokenType::LBRACKET:   return "'['";
        case TokenType::RBRACKET:   return "']'";
        case TokenType::LBRACE:     return "'{'";
        case TokenType::RBRACE:     return "'}'";
        case TokenType::LPAREN:     return "'('";
        case TokenType::RPAREN:     return "')'";
        case TokenType::SEMICOLON:  return "';'";
        case TokenType::COMMA:      return "','";
        case TokenType::NEWLINE:    return "NEWLINE";
        case TokenType::END_OF_FILE:return "EOF";
        default: return "TOKEN";
    }
}
