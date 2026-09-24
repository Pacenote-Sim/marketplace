package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// hostRe finds things that look like host names inside a string literal. It is
// a heuristic: the check reports what it finds and the manifest says what is
// not a host, so a false positive costs one line with a reason.
var hostRe = regexp.MustCompile(`(?i)(?:^|[^a-z0-9.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?:[^a-z0-9.-]|$)`)

// commonTLDs decide a two-label candidate. "api.cartesia.ai" is a host on the
// strength of its three labels; "voice.speak", a request kind, and "lap.png",
// a file, are two labels whose last is no top-level domain anyone dials from
// a plugin. Three or more labels are always reported.
var commonTLDs = toSet([]string{
	"com", "net", "org", "io", "ai", "dev", "app", "tech", "cloud", "co", "me", "info", "biz", "xyz",
	"gg", "tv", "fm", "sh", "run", "live", "chat", "eu", "es", "uk", "de", "fr", "it", "nl", "pl", "pt",
	"se", "no", "fi", "dk", "be", "at", "ch", "cz", "ie", "ca", "us", "au", "nz", "jp", "kr", "br", "mx",
	"ro", "hu", "gr", "tr", "in", "sg", "za", "ar", "cl",
})

// notTLDs are last labels that make a candidate a file name or an identifier,
// not a host.
var notTLDs = toSet([]string{
	"go", "json", "jsonl", "yaml", "yml", "md", "txt", "html", "css", "js", "svg", "png", "jpg", "jpeg",
	"gif", "webp", "mp3", "wav", "ogg", "ibt", "exe", "dll", "zip", "gz", "tar", "log", "csv", "pdf",
	"toml", "sql", "proto", "tmpl", "gotmpl", "ttf", "woff", "woff2", "ico", "bin", "dat", "sh", "bat",
	"ps1", "so", "dylib", "sum", "mod", "work", "lock", "env", "ini", "cfg", "conf", "xml",
})

// checkHosts scans every string literal in the module's packages for host
// names and compares them with the calls the manifest declares. Undeclared is
// a failure; declared but never seen is a warning, since a host may be built
// from parts or arrive from configuration.
func checkHosts(r *Report, o Options, pkgs []*pkg) error {
	declared := toSet(o.Manifest.Calls)
	ignore := toSet(o.Manifest.NotHosts)
	for _, h := range o.Policy.KnownHosts {
		ignore[h] = true
	}
	seen := map[string][]string{}
	fset := token.NewFileSet()
	for _, p := range pkgs {
		if !p.inModule(o.Manifest.Module) {
			continue
		}
		for _, name := range p.GoFiles {
			file := path.Join(p.Dir, name)
			f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
			if err != nil {
				return fmt.Errorf("parse %s: %w", file, err)
			}
			for host, pos := range hostLiterals(fset, f) {
				seen[host] = append(seen[host], pos...)
			}
		}
	}
	undeclared := 0
	for _, host := range sortedKeys(seen) {
		if declared[host] || ignore[host] {
			continue
		}
		undeclared++
		where := seen[host]
		if len(where) > 3 {
			where = append(where[:3], fmt.Sprintf("and %d more", len(seen[host])-3))
		}
		r.add("hosts", Fail, "%s is not in calls: %s. Declare it, or list it under not_hosts with a reason if it is not dialled", host, strings.Join(where, ", "))
	}
	for _, host := range o.Manifest.Calls {
		if _, ok := seen[host]; !ok {
			r.add("hosts", Warn, "%s is declared in calls but no string literal names it; check where the host comes from", host)
		}
	}
	if undeclared == 0 {
		r.add("hosts", Info, "every host literal is declared or explained (%d declared)", len(o.Manifest.Calls))
	}
	return nil
}

// hostLiterals returns each candidate host in the file's string literals with
// the positions it appears at. Import paths are not literals in this sense.
func hostLiterals(fset *token.FileSet, f *ast.File) map[string][]string {
	out := map[string][]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.ImportSpec:
			return false
		case *ast.BasicLit:
			if n.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(n.Value)
			if err != nil {
				return true
			}
			for _, m := range hostRe.FindAllStringSubmatch(s, -1) {
				host := strings.ToLower(m[1])
				tld := host[strings.LastIndex(host, ".")+1:]
				if notTLDs[tld] || (strings.Count(host, ".") == 1 && !commonTLDs[tld]) {
					continue
				}
				out[host] = append(out[host], fset.Position(n.Pos()).String())
			}
		}
		return true
	})
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return keys
}
