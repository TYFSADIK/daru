package query

import (
	"fmt"
	"strconv"
	"strings"
)

type kind int

const (
	kUnknown kind = iota
	kNum
	kStr
	kBool
)

type sqlExpr struct {
	sql  string
	kind kind
}

// compileExpr turns an eval/where expression into a ClickHouse expression.
func compileExpr(n eNode, rel *relation) (sqlExpr, error) {
	switch v := n.(type) {
	case *eNum:
		return sqlExpr{strconv.FormatFloat(v.V, 'f', -1, 64), kNum}, nil
	case *eStr:
		return sqlExpr{chStr(v.V), kStr}, nil
	case *eField:
		return sqlExpr{resolveStr(v.Name, rel), kUnknown}, nil
	case *eUn:
		return compileUnary(v, rel)
	case *eBin:
		return compileBinary(v, rel)
	case *eIn:
		return compileIn(v, rel)
	case *eCall:
		return compileCall(v, rel)
	}
	return sqlExpr{}, fmt.Errorf("bad expression")
}

func asNum(e sqlExpr) string {
	if e.kind == kNum {
		return e.sql
	}
	if e.kind == kBool {
		return "toFloat64(" + e.sql + ")"
	}
	return "toFloat64OrNull(toString(" + e.sql + "))"
}

func asStr(e sqlExpr) string {
	if e.kind == kStr {
		return e.sql
	}
	return "toString(" + e.sql + ")"
}

func asBool(e sqlExpr) string {
	switch e.kind {
	case kBool:
		return e.sql
	case kNum:
		return "(" + e.sql + " != 0)"
	case kStr:
		return "(" + e.sql + " != '')"
	}
	return "(toString(" + e.sql + ") != '')"
}

func compileUnary(v *eUn, rel *relation) (sqlExpr, error) {
	x, err := compileExpr(v.X, rel)
	if err != nil {
		return sqlExpr{}, err
	}
	if v.Op == "-" {
		return sqlExpr{"(-" + asNum(x) + ")", kNum}, nil
	}
	return sqlExpr{"(NOT " + asBool(x) + ")", kBool}, nil
}

func compileBinary(v *eBin, rel *relation) (sqlExpr, error) {
	l, err := compileExpr(v.L, rel)
	if err != nil {
		return sqlExpr{}, err
	}
	r, err := compileExpr(v.R, rel)
	if err != nil {
		return sqlExpr{}, err
	}
	switch v.Op {
	case "+", "-", "*", "/", "%":
		op := v.Op
		if op == "%" {
			return sqlExpr{fmt.Sprintf("modulo(%s, %s)", asNum(l), asNum(r)), kNum}, nil
		}
		if op == "/" {
			return sqlExpr{fmt.Sprintf("divide(%s, %s)", asNum(l), asNum(r)), kNum}, nil
		}
		return sqlExpr{fmt.Sprintf("(%s %s %s)", asNum(l), op, asNum(r)), kNum}, nil
	case ".":
		return sqlExpr{fmt.Sprintf("concat(%s, %s)", asStr(l), asStr(r)), kStr}, nil
	case "AND":
		return sqlExpr{fmt.Sprintf("(%s AND %s)", asBool(l), asBool(r)), kBool}, nil
	case "OR":
		return sqlExpr{fmt.Sprintf("(%s OR %s)", asBool(l), asBool(r)), kBool}, nil
	case "=", "!=", "<", "<=", ">", ">=":
		return compileComparison(v.Op, l, r), nil
	}
	return sqlExpr{}, fmt.Errorf("bad operator %q", v.Op)
}

func compileComparison(op string, l, r sqlExpr) sqlExpr {
	numeric := l.kind == kNum || r.kind == kNum
	if numeric {
		return sqlExpr{fmt.Sprintf("(%s %s %s)", asNum(l), op, asNum(r)), kBool}
	}
	return sqlExpr{fmt.Sprintf("(%s %s %s)", asStr(l), op, asStr(r)), kBool}
}

func compileIn(v *eIn, rel *relation) (sqlExpr, error) {
	x, err := compileExpr(v.X, rel)
	if err != nil {
		return sqlExpr{}, err
	}
	var parts []string
	for _, item := range v.List {
		e, err := compileExpr(item, rel)
		if err != nil {
			return sqlExpr{}, err
		}
		parts = append(parts, compileComparison("=", x, e).sql)
	}
	expr := "(" + strings.Join(parts, " OR ") + ")"
	if v.Not {
		expr = "(NOT " + expr + ")"
	}
	return sqlExpr{expr, kBool}, nil
}

func compileCall(v *eCall, rel *relation) (sqlExpr, error) {
	args := make([]sqlExpr, len(v.Args))
	for i, a := range v.Args {
		e, err := compileExpr(a, rel)
		if err != nil {
			return sqlExpr{}, err
		}
		args[i] = e
	}
	need := func(n int) error {
		if len(args) != n {
			return fmt.Errorf("%s() takes %d argument(s), got %d", v.Name, n, len(args))
		}
		return nil
	}

	switch v.Name {
	case "true":
		return sqlExpr{"1", kBool}, nil
	case "false":
		return sqlExpr{"0", kBool}, nil
	case "null":
		return sqlExpr{"NULL", kUnknown}, nil
	case "now":
		return sqlExpr{"toFloat64(toUnixTimestamp(now()))", kNum}, nil
	case "tonumber", "tonum":
		if err := need(1); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{asNum(args[0]), kNum}, nil
	case "tostring":
		if err := need(1); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{asStr(args[0]), kStr}, nil
	case "abs", "sqrt", "exp", "ln":
		if err := need(1); err != nil {
			return sqlExpr{}, err
		}
		fn := map[string]string{"abs": "abs", "sqrt": "sqrt", "exp": "exp", "ln": "log"}[v.Name]
		return sqlExpr{fmt.Sprintf("%s(%s)", fn, asNum(args[0])), kNum}, nil
	case "log":
		if len(args) == 1 {
			return sqlExpr{fmt.Sprintf("log10(%s)", asNum(args[0])), kNum}, nil
		}
		if err := need(2); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("(log(%s)/log(%s))", asNum(args[0]), asNum(args[1])), kNum}, nil
	case "pow":
		if err := need(2); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("pow(%s, %s)", asNum(args[0]), asNum(args[1])), kNum}, nil
	case "round":
		if len(args) == 1 {
			return sqlExpr{fmt.Sprintf("round(%s)", asNum(args[0])), kNum}, nil
		}
		if err := need(2); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("round(%s, toInt32(%s))", asNum(args[0]), asNum(args[1])), kNum}, nil
	case "ceiling", "ceil":
		if err := need(1); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("ceil(%s)", asNum(args[0])), kNum}, nil
	case "floor":
		if err := need(1); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("floor(%s)", asNum(args[0])), kNum}, nil
	case "len":
		if err := need(1); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("lengthUTF8(%s)", asStr(args[0])), kNum}, nil
	case "lower":
		if err := need(1); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("lowerUTF8(%s)", asStr(args[0])), kStr}, nil
	case "upper":
		if err := need(1); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("upperUTF8(%s)", asStr(args[0])), kStr}, nil
	case "trim", "ltrim", "rtrim":
		if err := need(1); err != nil {
			return sqlExpr{}, err
		}
		fn := map[string]string{"trim": "trimBoth", "ltrim": "trimLeft", "rtrim": "trimRight"}[v.Name]
		return sqlExpr{fmt.Sprintf("%s(%s)", fn, asStr(args[0])), kStr}, nil
	case "substr":
		if len(args) == 2 {
			return sqlExpr{fmt.Sprintf("substringUTF8(%s, toInt32(%s))", asStr(args[0]), asNum(args[1])), kStr}, nil
		}
		if err := need(3); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("substringUTF8(%s, toInt32(%s), toInt32(%s))", asStr(args[0]), asNum(args[1]), asNum(args[2])), kStr}, nil
	case "replace":
		if err := need(3); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("replaceRegexpAll(%s, %s, %s)", asStr(args[0]), asStr(args[1]), asStr(args[2])), kStr}, nil
	case "like":
		if err := need(2); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("(%s LIKE %s)", asStr(args[0]), asStr(args[1])), kBool}, nil
	case "match":
		if err := need(2); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("match(%s, %s)", asStr(args[0]), asStr(args[1])), kBool}, nil
	case "if":
		if err := need(3); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("if(%s, %s, %s)", asBool(args[0]), asStr(args[1]), asStr(args[2])), kStr}, nil
	case "coalesce":
		if len(args) == 0 {
			return sqlExpr{}, fmt.Errorf("coalesce() needs at least one argument")
		}
		var parts []string
		for _, a := range args {
			parts = append(parts, fmt.Sprintf("nullIf(%s, '')", asStr(a)))
		}
		return sqlExpr{fmt.Sprintf("coalesce(%s)", strings.Join(parts, ", ")), kStr}, nil
	case "case":
		if len(args) < 2 || len(args)%2 != 0 {
			return sqlExpr{}, fmt.Errorf("case() takes pairs of condition, value")
		}
		var b strings.Builder
		b.WriteString("multiIf(")
		for i := 0; i < len(args); i += 2 {
			b.WriteString(asBool(args[i]))
			b.WriteString(", ")
			b.WriteString(asStr(args[i+1]))
			b.WriteString(", ")
		}
		b.WriteString("NULL)")
		return sqlExpr{b.String(), kStr}, nil
	case "isnull":
		if err := need(1); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("(%s IS NULL OR toString(%s) = '')", args[0].sql, args[0].sql), kBool}, nil
	case "isnotnull":
		if err := need(1); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("(%s IS NOT NULL AND toString(%s) != '')", args[0].sql, args[0].sql), kBool}, nil
	case "min", "max":
		if len(args) < 1 {
			return sqlExpr{}, fmt.Errorf("%s() needs at least one argument", v.Name)
		}
		var nums []string
		for _, a := range args {
			nums = append(nums, asNum(a))
		}
		fn := "least"
		if v.Name == "max" {
			fn = "greatest"
		}
		expr := nums[0]
		for i := 1; i < len(nums); i++ {
			expr = fmt.Sprintf("%s(%s, %s)", fn, expr, nums[i])
		}
		return sqlExpr{expr, kNum}, nil
	case "strftime":
		if err := need(2); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("formatDateTime(toDateTime64(%s, 3, 'UTC'), %s, 'UTC')", asNum(args[0]), asStr(args[1])), kStr}, nil
	case "urldecode":
		if err := need(1); err != nil {
			return sqlExpr{}, err
		}
		return sqlExpr{fmt.Sprintf("decodeURLComponent(%s)", asStr(args[0])), kStr}, nil
	case "md5", "sha1", "sha256":
		if err := need(1); err != nil {
			return sqlExpr{}, err
		}
		fn := map[string]string{"md5": "MD5", "sha1": "SHA1", "sha256": "SHA256"}[v.Name]
		return sqlExpr{fmt.Sprintf("lower(hex(%s(%s)))", fn, asStr(args[0])), kStr}, nil
	}
	return sqlExpr{}, fmt.Errorf("unknown function %q", v.Name)
}

func compileWhereExpr(n eNode, rel *relation) (string, error) {
	e, err := compileExpr(n, rel)
	if err != nil {
		return "", err
	}
	return asBool(e), nil
}
