// Package query parses and compiles Basalt Query Language (BQL), a piped
// search language, into ClickHouse SQL.
package query

import (
	"fmt"
	"strings"
	"unicode"
)

type tokKind int

const (
	tEOF tokKind = iota
	tWord
	tString
	tNum
	tOp
)

type token struct {
	kind tokKind
	text string
	// quoted marks a single-quoted identifier in expression mode.
	quoted bool
	pos    int
}

func (t token) is(kind tokKind, text string) bool { return t.kind == kind && t.text == text }

// keyword reports whether the token is a bare word equal to kw, ignoring case.
func (t token) keyword(kw string) bool {
	return t.kind == tWord && !t.quoted && strings.EqualFold(t.text, kw)
}

// splitPipes splits a query on top-level pipes, ignoring pipes inside quotes.
func splitPipes(q string) ([]string, error) {
	var parts []string
	var cur strings.Builder
	quote := byte(0)
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case quote != 0:
			cur.WriteByte(c)
			if c == '\\' && i+1 < len(q) {
				i++
				cur.WriteByte(q[i])
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
			cur.WriteByte(c)
		case c == '|':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	return append(parts, cur.String()), nil
}

func readString(s string, i int, quote byte) (string, int, error) {
	var b strings.Builder
	for j := i + 1; j < len(s); j++ {
		c := s[j]
		if c == '\\' && j+1 < len(s) {
			n := s[j+1]
			switch n {
			case quote, '\\':
				b.WriteByte(n)
			default:
				// Keep unknown escapes intact so regular expressions survive.
				b.WriteByte('\\')
				b.WriteByte(n)
			}
			j++
			continue
		}
		if c == quote {
			return b.String(), j + 1, nil
		}
		b.WriteByte(c)
	}
	return "", 0, fmt.Errorf("unterminated string at position %d", i)
}

// lexSearch tokenizes search-style arguments, where words may contain
// almost any character (paths, IPs, wildcards, dashes).
func lexSearch(s string) ([]token, error) {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '"':
			str, next, err := readString(s, i, '"')
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: tString, text: str, pos: i})
			i = next
		case c == '(' || c == ')' || c == ',':
			out = append(out, token{kind: tOp, text: string(c), pos: i})
			i++
		case c == '=':
			if i+1 < len(s) && s[i+1] == '=' {
				out = append(out, token{kind: tOp, text: "=", pos: i})
				i += 2
			} else {
				out = append(out, token{kind: tOp, text: "=", pos: i})
				i++
			}
		case c == '!' && i+1 < len(s) && s[i+1] == '=':
			out = append(out, token{kind: tOp, text: "!=", pos: i})
			i += 2
		case c == '<' || c == '>':
			op := string(c)
			if i+1 < len(s) && s[i+1] == '=' {
				op += "="
			}
			out = append(out, token{kind: tOp, text: op, pos: i})
			i += len(op)
		default:
			start := i
			for i < len(s) {
				c = s[i]
				if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '(' || c == ')' ||
					c == ',' || c == '=' || c == '<' || c == '>' || c == '"' ||
					(c == '!' && i+1 < len(s) && s[i+1] == '=') {
					break
				}
				i++
			}
			out = append(out, token{kind: tWord, text: s[start:i], pos: start})
		}
	}
	return append(out, token{kind: tEOF, pos: len(s)}), nil
}

func isIdentStart(r byte) bool {
	return r == '_' || r == '@' || r < 0x80 && unicode.IsLetter(rune(r))
}

func isIdentChar(r byte) bool {
	return isIdentStart(r) || r >= '0' && r <= '9' || r == '.' || r == ':' || r == '{' || r == '}'
}

// lexExpr tokenizes eval and where expressions.
func lexExpr(s string) ([]token, error) {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '"':
			str, next, err := readString(s, i, '"')
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: tString, text: str, pos: i})
			i = next
		case c == '\'':
			str, next, err := readString(s, i, '\'')
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: tWord, text: str, quoted: true, pos: i})
			i = next
		case c >= '0' && c <= '9' || c == '.' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9':
			start := i
			for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
				i++
			}
			if i < len(s) && (s[i] == 'e' || s[i] == 'E') && i+1 < len(s) &&
				(s[i+1] >= '0' && s[i+1] <= '9' || (s[i+1] == '-' || s[i+1] == '+') && i+2 < len(s) && s[i+2] >= '0' && s[i+2] <= '9') {
				i += 2
				for i < len(s) && s[i] >= '0' && s[i] <= '9' {
					i++
				}
			}
			if i < len(s) && isIdentStart(s[i]) {
				// A number followed by a unit (5m, 1h) is a duration
				// literal, which expressions do not support. Reject it
				// instead of silently treating it as a field lookup.
				return nil, fmt.Errorf("duration literal %q is not supported in expressions; use a number or a quoted string", s[start:i])
			}
			out = append(out, token{kind: tNum, text: s[start:i], pos: start})
		case isIdentStart(c):
			start := i
			for i < len(s) && isIdentChar(s[i]) {
				i++
			}
			out = append(out, token{kind: tWord, text: s[start:i], pos: start})
		default:
			two := ""
			if i+1 < len(s) {
				two = s[i : i+2]
			}
			switch two {
			case "==", "!=", "<=", ">=":
				out = append(out, token{kind: tOp, text: two, pos: i})
				i += 2
				continue
			}
			if strings.ContainsRune("=<>()+-*/%,.!", rune(c)) {
				op := string(c)
				if op == "==" {
					op = "="
				}
				out = append(out, token{kind: tOp, text: op, pos: i})
				i++
				continue
			}
			return nil, fmt.Errorf("unexpected character %q at position %d", c, i)
		}
	}
	return append(out, token{kind: tEOF, pos: len(s)}), nil
}

type stream struct {
	toks []token
	i    int
}

func (s *stream) peek() token { return s.toks[s.i] }
func (s *stream) peekN(n int) token {
	if s.i+n < len(s.toks) {
		return s.toks[s.i+n]
	}
	return s.toks[len(s.toks)-1]
}
func (s *stream) next() token {
	t := s.toks[s.i]
	if t.kind != tEOF {
		s.i++
	}
	return t
}
func (s *stream) eof() bool { return s.peek().kind == tEOF }
func (s *stream) accept(kind tokKind, text string) bool {
	if s.peek().is(kind, text) {
		s.next()
		return true
	}
	return false
}
func (s *stream) expect(kind tokKind, text string) error {
	if !s.accept(kind, text) {
		return fmt.Errorf("expected %q near %q", text, s.peek().text)
	}
	return nil
}
