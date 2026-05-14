package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"

	crs "github.com/corazawaf/coraza-coreruleset/v4"
)

type Rule struct {
	ID       int      `json:"id"`
	Msg      string   `json:"msg"`
	Severity string   `json:"severity"`
	Tags     []string `json:"tags"`
	File     string   `json:"file"`
}

var (
	idRe       = regexp.MustCompile(`(?i)\bid:'?(\d+)'?`)
	msgRe      = regexp.MustCompile(`(?i)\bmsg:'([^']+)'`)
	severityRe = regexp.MustCompile(`(?i)\bseverity:'?([A-Z]+)'?`)
	tagRe      = regexp.MustCompile(`(?i)\btag:'([^']+)'`)
)

func main() {
	out := []Rule{}
	err := fs.WalkDir(crs.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".conf") {
			return nil
		}
		b, err := fs.ReadFile(crs.FS, path)
		if err != nil {
			return err
		}
		// Coalesce backslash-continuation lines so id/msg/etc on the same
		// logical rule are visible to the per-line scanner.
		text := regexp.MustCompile(`\\\s*\n\s*`).ReplaceAllString(string(b), " ")
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "SecRule") && !strings.HasPrefix(line, "SecAction") {
				continue
			}
			m := idRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			id, _ := strconv.Atoi(m[1])
			r := Rule{ID: id, File: path}
			if mm := msgRe.FindStringSubmatch(line); mm != nil {
				r.Msg = mm[1]
			}
			if mm := severityRe.FindStringSubmatch(line); mm != nil {
				r.Severity = strings.ToLower(mm[1])
			}
			for _, mm := range tagRe.FindAllStringSubmatch(line, -1) {
				r.Tags = append(r.Tags, mm[1])
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
