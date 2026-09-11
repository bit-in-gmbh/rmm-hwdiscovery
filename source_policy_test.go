package hwdiscovery

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestProductionSourceDoesNotLaunchProcesses(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		checkNoProcessLaunch(t, entry.Name())
	}
}

func checkNoProcessLaunch(t *testing.T, path string) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	aliases := make(map[string]string)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("parse import in %s: %v", path, err)
		}
		if importPath == "os/exec" {
			t.Errorf("%s imports forbidden package os/exec", path)
		}
		name := filepath.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		aliases[name] = importPath
	}

	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		importPath := aliases[identifier.Name]
		forbidden := (importPath == "os" && selector.Sel.Name == "StartProcess") ||
			(importPath == "syscall" && selector.Sel.Name == "StartProcess") ||
			(importPath == "golang.org/x/sys/windows" && selector.Sel.Name == "CreateProcess")
		if forbidden {
			t.Errorf("%s calls forbidden process-launch API %s.%s", path, identifier.Name, selector.Sel.Name)
		}
		return true
	})
}
