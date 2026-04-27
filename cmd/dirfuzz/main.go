package main

import (
	"fmt"
	"os"
)

func main() {
	cfg := parseFlags()

	if !cfg.NoTUI {
		// Print a brief startup banner to stderr before the TUI takes over.
		// This is immediately replaced by the alt-screen, so it only flashes
		// briefly in terminals that support alt-screen. It gives users without
		// alt-screen support (e.g. piped output) a visible indication of what
		// is running.
		fmt.Fprintf(os.Stderr,
			"🦇 DirFuzz v%s  →  %s\n",
			cliVersion, cfg.Target,
		)
	}

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
