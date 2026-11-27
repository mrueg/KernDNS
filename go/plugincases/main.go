// Command plugincases extracts the table tests of CoreDNS plugins
// (`cargo xtask plugin-cases`).
//
// For every plugin it parses the package's *_test.go files and finds the
// tables: composite literals of slice, array or map type, and test.Case
// literals, assigned to a package-level variable or to a local variable
// inside a function. It copies each table's source, together with the
// type and constant declarations and literal assignments in scope before
// it, into a function in a generated test file that is added to the
// package with `go test -overlay`, so every identifier resolves exactly as
// in the original test. A generated test then evaluates each table in the
// real package and writes it as JSON, with DNS records in presentation
// format. Package-level string constants and variables (zone files, zone
// names) are written too.
//
// Tables that don't compile outside their function (they use local
// variables, closures over test state, ...) are listed in the output with
// the compiler's message instead of being dropped silently.
//
// Nothing inside the CoreDNS checkout is modified: generated files live in
// a temporary directory and are only seen through the overlay.
package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed runtime.go.in
var runtimeSrc string

type table struct {
	File    string
	Func    string // "" at package level
	Name    string
	Line    int
	Prelude []string // statements that make the table's identifiers resolve
	Expr    string
	Dropped string // compiler error that excluded it
	genLo   int    // line range in the generated file
	genHi   int
}

type srcFile struct {
	Base    string
	Pkg     string
	Imports []imp
	Tables  []*table
	Strings []string
	Locals  [][2]string // Func/name, literal source
	strLo   int
}

type imp struct {
	Name string // alias or ""
	Path string
}

func main() {
	coredns := flag.String("coredns", "", "CoreDNS checkout")
	out := flag.String("out", "", "output directory for <plugin>.json")
	plugins := flag.String("plugins", "", "comma-separated plugin names")
	flag.Parse()
	if *coredns == "" || *out == "" || *plugins == "" {
		fmt.Fprintln(os.Stderr, "usage: plugincases -coredns DIR -out DIR -plugins a,b,c")
		os.Exit(2)
	}
	work, err := os.MkdirTemp("", "kerndns-plugincases-")
	check(err)
	defer os.RemoveAll(work)
	failed := false
	for _, p := range strings.Split(*plugins, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if err := run(*coredns, p, filepath.Join(work, p), *out); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", p, err)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(coredns, plugin, work, outDir string) error {
	dir := filepath.Join(coredns, "plugin", plugin)
	files, err := parseDir(dir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no test files in %s", dir)
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return err
	}
	absOut, err := filepath.Abs(filepath.Join(outDir, plugin+".json"))
	if err != nil {
		return err
	}
	pkgPath := "./plugin/" + plugin + "/"
	unused := map[string]map[string]bool{} // file -> import path -> unused
	for pass := 0; ; pass++ {
		overlay, err := generate(dir, work, plugin, files, unused)
		if err != nil {
			return err
		}
		cmd := exec.Command("go", "test", "-c", "-o", os.DevNull, "-gcflags=-e", "-overlay", overlay, pkgPath)
		cmd.Dir = coredns
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if cmd.Run() == nil {
			break
		}
		if pass > 50 || !applyErrors(stderr.String(), files, unused) {
			return fmt.Errorf("compiling the generated tables failed:\n%s", stderr.String())
		}
	}
	overlay, err := generate(dir, work, plugin, files, unused)
	if err != nil {
		return err
	}
	cmd := exec.Command("go", "test", "-count=1", "-run", "^TestKernDNSTables$", "-overlay", overlay, pkgPath)
	cmd.Dir = coredns
	cmd.Env = append(os.Environ(), "KERNDNS_PLUGIN_CASES="+absOut)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running the generated test: %w", err)
	}
	fmt.Println("wrote", absOut)
	return nil
}

func parseDir(dir string) ([]*srcFile, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var out []*srcFile
	for _, name := range names {
		if strings.HasPrefix(filepath.Base(name), "kerndns_") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(f.Name.Name, "_test") {
			// external test package: can't see the plugin's internals,
			// and none of the covered plugins has one
			fmt.Fprintf(os.Stderr, "skipping %s: external test package\n", name)
			continue
		}
		sf := &srcFile{Base: filepath.Base(name), Pkg: f.Name.Name}
		for _, i := range f.Imports {
			p, _ := strconv.Unquote(i.Path.Value)
			n := ""
			if i.Name != nil {
				n = i.Name.Name
			}
			sf.Imports = append(sf.Imports, imp{n, p})
		}
		src := func(n ast.Node) string {
			var b bytes.Buffer
			printer.Fprint(&b, fset, n)
			return b.String()
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				if d.Tok != token.VAR && d.Tok != token.CONST {
					continue
				}
				for _, s := range d.Specs {
					vs := s.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if n.Name == "_" {
							continue
						}
						if i < len(vs.Values) && isTable(vs.Values[i]) {
							sf.Tables = append(sf.Tables, &table{File: sf.Base, Name: n.Name, Line: fset.Position(n.Pos()).Line, Expr: n.Name})
						} else {
							sf.Strings = append(sf.Strings, n.Name)
						}
					}
				}
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				name := d.Name.Name
				if d.Recv != nil || !strings.HasPrefix(name, "Test") {
					// helpers and benchmarks aren't tests
					continue
				}
				// local string literals (hosts files, zones) as Func/name
				seen := map[string]bool{}
				local := func(n *ast.Ident, v ast.Expr) {
					key := name + "/" + n.Name
					if isStringLit(v) && !seen[key] {
						seen[key] = true
						sf.Locals = append(sf.Locals, [2]string{key, src(v)})
					}
				}
				ast.Inspect(d.Body, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.GenDecl:
						if n.Tok == token.CONST || n.Tok == token.VAR {
							for _, s := range n.Specs {
								vs := s.(*ast.ValueSpec)
								for i, id := range vs.Names {
									if i < len(vs.Values) {
										local(id, vs.Values[i])
									}
								}
							}
						}
					case *ast.AssignStmt:
						if n.Tok == token.DEFINE && len(n.Lhs) == 1 && len(n.Rhs) == 1 {
							if id, ok := n.Lhs[0].(*ast.Ident); ok {
								local(id, n.Rhs[0])
							}
						}
					}
					return true
				})
				walkBlock(d.Body.List, nil, func(n *ast.Ident, rhs ast.Expr, prelude []stmt) {
					sf.Tables = append(sf.Tables, &table{
						File: sf.Base, Func: name, Name: n.Name, Line: fset.Position(n.Pos()).Line,
						Prelude: needed(prelude, rhs), Expr: src(rhs),
					})
				}, src)
			}
		}
		out = append(out, sf)
	}
	// string literals of the package itself (test zones such as
	// file's exampleOrgSigned live in non-test files)
	srcs, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	sort.Strings(srcs)
	for _, name := range srcs {
		if strings.HasSuffix(name, "_test.go") || len(out) == 0 {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil || f.Name.Name != out[0].Pkg {
			continue
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) && isStringLit(vs.Values[i]) {
						out[0].Strings = append(out[0].Strings, n.Name)
					}
				}
			}
		}
	}
	return out, nil
}

func isStringLit(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.BasicLit:
		return e.Kind == token.STRING
	case *ast.BinaryExpr:
		return isStringLit(e.X) && isStringLit(e.Y)
	}
	return false
}

// isTable: a slice, array or map literal, or a test.Case.
func isTable(e ast.Expr) bool {
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = u.X
	}
	cl, ok := e.(*ast.CompositeLit)
	if !ok {
		return false
	}
	switch t := cl.Type.(type) {
	case *ast.ArrayType, *ast.MapType:
		return true
	case *ast.SelectorExpr:
		if x, ok := t.X.(*ast.Ident); ok && x.Name == "test" && t.Sel.Name == "Case" {
			return true
		}
	}
	return false
}

// stmt is a local declaration a table may depend on.
type stmt struct {
	defs []string
	refs map[string]bool
	src  []string
}

func idents(n ast.Node) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(n, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			out[id.Name] = true
		}
		return true
	})
	return out
}

// needed returns the source of the prelude statements expr depends on,
// directly or through other prelude statements, in order.
func needed(prelude []stmt, expr ast.Expr) []string {
	want := idents(expr)
	use := make([]bool, len(prelude))
	for i := len(prelude) - 1; i >= 0; i-- {
		for _, d := range prelude[i].defs {
			if want[d] {
				use[i] = true
			}
		}
		if use[i] {
			for r := range prelude[i].refs {
				want[r] = true
			}
		}
	}
	var out []string
	for i, s := range prelude {
		if use[i] {
			out = append(out, s.src...)
		}
	}
	return out
}

// walkBlock visits the statements of a block in order. Local type,
// constant and variable declarations and single-value assignments become
// the prelude of later tables in the same or nested blocks; a table only
// gets the ones it depends on.
func walkBlock(stmts []ast.Stmt, prelude []stmt, emit func(*ast.Ident, ast.Expr, []stmt), src func(ast.Node) string) {
	prelude = append([]stmt(nil), prelude...)
	for _, st := range stmts {
		switch s := st.(type) {
		case *ast.AssignStmt:
			if len(s.Lhs) == 1 && len(s.Rhs) == 1 {
				if id, ok := s.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
					if isTable(s.Rhs[0]) {
						emit(id, s.Rhs[0], prelude)
					}
					if s.Tok == token.DEFINE {
						prelude = append(prelude, stmt{[]string{id.Name}, idents(s.Rhs[0]), []string{src(s), "_ = " + id.Name}})
					}
				}
			}
		case *ast.DeclStmt:
			gd, ok := s.Decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			var defs []string
			for _, sp := range gd.Specs {
				switch sp := sp.(type) {
				case *ast.TypeSpec:
					defs = append(defs, sp.Name.Name)
				case *ast.ValueSpec:
					for i, n := range sp.Names {
						if n.Name == "_" {
							continue
						}
						defs = append(defs, n.Name)
						if gd.Tok == token.VAR && i < len(sp.Values) && isTable(sp.Values[i]) {
							emit(n, sp.Values[i], prelude)
						}
					}
				}
			}
			code := []string{src(s)}
			if gd.Tok == token.VAR {
				for _, d := range defs {
					code = append(code, "_ = "+d)
				}
			}
			refs := idents(gd)
			for _, d := range defs {
				delete(refs, d)
			}
			prelude = append(prelude, stmt{defs, refs, code})
		case *ast.BlockStmt:
			walkBlock(s.List, prelude, emit, src)
		case *ast.IfStmt:
			walkBlock(s.Body.List, prelude, emit, src)
		case *ast.ForStmt:
			walkBlock(s.Body.List, prelude, emit, src)
		case *ast.RangeStmt:
			walkBlock(s.Body.List, prelude, emit, src)
		case *ast.ExprStmt:
			// t.Run("name", func(t *testing.T) { ... })
			if c, ok := s.X.(*ast.CallExpr); ok {
				for _, a := range c.Args {
					if fl, ok := a.(*ast.FuncLit); ok {
						walkBlock(fl.Body.List, prelude, emit, src)
					}
				}
			}
		}
	}
}

// generate writes the generated files and the overlay; it returns the
// overlay's path.
func generate(dir, work, plugin string, files []*srcFile, unused map[string]map[string]bool) (string, error) {
	replace := map[string]string{}
	pkg := files[0].Pkg
	rt := strings.Replace(runtimeSrc, "package PKG", "package "+pkg, 1)
	rt = strings.Replace(rt, `"PLUGIN"`, strconv.Quote(plugin), 1)
	rtPath := filepath.Join(work, "kerndns_runtime_test.go")
	if err := os.WriteFile(rtPath, []byte(rt), 0o644); err != nil {
		return "", err
	}
	replace[filepath.Join(dir, "kerndns_runtime_test.go")] = rtPath
	for _, f := range files {
		var b strings.Builder
		line := 1
		w := func(s string) {
			b.WriteString(s)
			b.WriteString("\n")
			line += strings.Count(s, "\n") + 1
		}
		w("// Code generated by go/plugincases; DO NOT EDIT.")
		w("")
		w("package " + f.Pkg)
		w("")
		w("import (")
		for _, i := range f.Imports {
			if unused[f.Base][i.Path] {
				continue
			}
			w("\t" + strings.TrimSpace(i.Name+" "+strconv.Quote(i.Path)))
		}
		w("\tkerndnsTesting \"testing\"")
		w(")")
		w("")
		w("var _ = kerndnsTesting.Verbose")
		w("")
		w("func init() {")
		f.strLo = line
		for _, s := range f.Strings {
			w(fmt.Sprintf("\tkerndnsString(%q, %s)", s, s))
		}
		for _, l := range f.Locals {
			w(fmt.Sprintf("\tkerndnsString(%q, %s)", l[0], l[1]))
		}
		for _, t := range f.Tables {
			if t.Dropped != "" {
				continue
			}
			t.genLo = line
			w(fmt.Sprintf("\tkerndnsTable(%q, %q, %q, %d, func(t *kerndnsTesting.T) any {", t.File, t.Func, t.Name, t.Line))
			w("\t\t_ = t")
			for _, p := range t.Prelude {
				w(p)
			}
			w("\t\treturn " + t.Expr)
			w("\t})")
			t.genHi = line - 1
		}
		for _, t := range f.Tables {
			if t.Dropped != "" {
				w(fmt.Sprintf("\tkerndnsDropped(%q, %q, %q, %d, %q)", t.File, t.Func, t.Name, t.Line, t.Dropped))
			}
		}
		w("}")
		name := "kerndns_gen_" + f.Base
		p := filepath.Join(work, name)
		if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
			return "", err
		}
		replace[filepath.Join(dir, name)] = p
	}
	ov := filepath.Join(work, "overlay.json")
	data, _ := json.Marshal(map[string]any{"Replace": replace})
	return ov, os.WriteFile(ov, data, 0o644)
}

var errRe = regexp.MustCompile(`(?m)^[^\s:]*kerndns_gen_([^:]+):(\d+):\d+: (.*)$`)
var importRe = regexp.MustCompile(`^"([^"]+)" imported (as \S+ )?and not used`)
var stringRe = regexp.MustCompile(`kerndnsString\("([^"]+)"`)

// applyErrors drops the tables (and unused imports, and non-value package
// identifiers) the compiler complained about. It reports whether anything
// changed.
func applyErrors(stderr string, files []*srcFile, unused map[string]map[string]bool) bool {
	changed := false
	byBase := map[string]*srcFile{}
	for _, f := range files {
		byBase[f.Base] = f
	}
	for _, m := range errRe.FindAllStringSubmatch(stderr, -1) {
		f := byBase[m[1]]
		if f == nil {
			continue
		}
		line, _ := strconv.Atoi(m[2])
		msg := m[3]
		if im := importRe.FindStringSubmatch(msg); im != nil {
			if unused[f.Base] == nil {
				unused[f.Base] = map[string]bool{}
			}
			if !unused[f.Base][im[1]] {
				unused[f.Base][im[1]] = true
				changed = true
			}
			continue
		}
		hit := false
		for _, t := range f.Tables {
			if t.Dropped == "" && line >= t.genLo && line <= t.genHi {
				t.Dropped = msg
				changed, hit = true, true
			}
		}
		if hit {
			continue
		}
		// a package-level name that isn't a value (generic, ...)
		src := genLine(f, line)
		if sm := stringRe.FindStringSubmatch(src); sm != nil {
			for i, s := range f.Strings {
				if s == sm[1] {
					f.Strings = append(f.Strings[:i], f.Strings[i+1:]...)
					changed = true
					break
				}
			}
		}
	}
	return changed
}

// genLine is the kerndnsString call on line n of f's generated file.
func genLine(f *srcFile, n int) string {
	idx := n - f.strLo
	if idx >= 0 && idx < len(f.Strings) {
		return fmt.Sprintf("kerndnsString(%q", f.Strings[idx])
	}
	return ""
}
