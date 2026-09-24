package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"sort"
	"strconv"
)

// checkImports applies the import policy to every package of the module that
// ends up in the client. A companion may import the contract, the protocol
// and a short list of standard packages; a source a wider list, because it
// has to read the simulator. Anything else needs a reason in the manifest.
func checkImports(r *Report, o Options, pkgs []*pkg) {
	pol := o.Policy.ImportsFor(o.Manifest.Kind)
	if pol == nil {
		return
	}
	std := toSet(pol.Std)
	allowed := map[string]bool{}
	for _, a := range o.Manifest.ImportsAllow {
		allowed[a.Value] = true
	}
	deps := map[string]bool{}
	for _, d := range o.Manifest.Dependencies {
		deps[d.Value] = true
	}
	byPath := map[string]*pkg{}
	for _, p := range pkgs {
		byPath[p.ImportPath] = p
	}
	problems := map[string]bool{}
	for _, p := range pkgs {
		if !p.inModule(o.Manifest.Module) {
			continue
		}
		for _, imp := range p.Imports {
			dep := byPath[imp]
			switch {
			case dep == nil:
				problems[fmt.Sprintf("%s imports %s, which go list did not describe", p.ImportPath, imp)] = true
			case dep.inModule(o.Manifest.Module):
			case dep.Standard:
				if !std[imp] && !allowed[imp] {
					problems[fmt.Sprintf("%s imports %s: not in the %s policy and not in imports_allow", p.ImportPath, imp, o.Manifest.Kind)] = true
				}
			case dep.Module != nil && o.Policy.IsContract(dep.Module.Path):
			case dep.Module != nil && deps[dep.Module.Path]:
			default:
				mod := imp
				if dep.Module != nil {
					mod = dep.Module.Path
				}
				problems[fmt.Sprintf("%s imports %s from module %s: not listed in dependencies", p.ImportPath, imp, mod)] = true
			}
		}
	}
	for _, msg := range sorted(problems) {
		r.add("imports", Fail, "%s", msg)
	}
	for _, a := range o.Manifest.ImportsAllow {
		r.add("imports", Warn, "imports_allow %s: %s", a.Value, a.Reason)
	}
	for _, d := range o.Manifest.Dependencies {
		r.add("imports", Warn, "dependency %s: %s", d.Value, d.Reason)
	}
	symbols := checkSymbols(o, pkgs, pol.DenySymbols)
	for _, msg := range symbols {
		r.add("symbols", Fail, "%s", msg)
	}
	if len(problems) == 0 && len(symbols) == 0 {
		r.add("imports", Info, "every import is within the %s policy", o.Manifest.Kind)
	}
}

// checkSymbols finds uses of the identifiers the policy denies whatever the
// import policy allows: the things that dial, listen or run a process. A
// companion imports net/http for the method constants and the Header type; it
// may not build an http.Client, because its only route out is the host.
func checkSymbols(o Options, pkgs []*pkg, deny map[string][]string) []string {
	if len(deny) == 0 {
		return nil
	}
	denied := map[string]map[string]bool{}
	for p, names := range deny {
		denied[p] = toSet(names)
	}
	allowed := map[string]bool{}
	for _, a := range o.Manifest.ImportsAllow {
		allowed[a.Value] = true
	}
	found := map[string]bool{}
	fset := token.NewFileSet()
	for _, p := range pkgs {
		if !p.inModule(o.Manifest.Module) {
			continue
		}
		for _, name := range p.GoFiles {
			file := path.Join(p.Dir, name)
			f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
			if err != nil {
				found[fmt.Sprintf("%s: %v", file, err)] = true
				continue
			}
			for msg := range symbolUses(fset, f, denied, allowed) {
				found[msg] = true
			}
		}
	}
	return sorted(found)
}

func symbolUses(fset *token.FileSet, f *ast.File, denied map[string]map[string]bool, allowed map[string]bool) map[string]bool {
	out := map[string]bool{}
	// Which local names refer to a denied package.
	local := map[string]string{}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || denied[p] == nil || allowed[p] {
			continue
		}
		name := path.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "." {
			out[fmt.Sprintf("%s: dot-import of %s hides what is used from it", fset.Position(imp.Pos()), p)] = true
			continue
		}
		if name == "_" {
			continue
		}
		local[name] = p
	}
	if len(local) == 0 && len(out) == 0 {
		return out
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if p, ok := local[id.Name]; ok && denied[p][sel.Sel.Name] {
			out[fmt.Sprintf("%s: %s.%s is not something a %s may use", fset.Position(sel.Pos()), id.Name, sel.Sel.Name, "client plugin")] = true
		}
		return true
	})
	return out
}

func toSet(list []string) map[string]bool {
	s := make(map[string]bool, len(list))
	for _, v := range list {
		s[v] = true
	}
	return s
}

func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
