package tui

import (
	"testing"

	"dirfuzz/pkg/engine"
)

func TestCommandConfigChangesRefreshSnapshot(t *testing.T) {
	eng := engine.NewEngine(1, 1000, 0.01)
	model := NewModel(eng, make(chan engine.Result))

	runCommand := func(name, args string) {
		t.Helper()
		for _, cmd := range model.commands {
			if cmd.Name == name {
				cmd.Handler(&model, args)
				return
			}
		}
		t.Fatalf("command %q not found", name)
	}

	runCommand("fw", "3")
	runCommand("body", "id={PAYLOAD}")
	runCommand("saveraw", "on")

	snap := eng.RuntimeSnapshot()
	if snap.FilterWords != 3 {
		t.Fatalf("snapshot FilterWords = %d, want 3", snap.FilterWords)
	}
	if snap.RequestBody != "id={PAYLOAD}" {
		t.Fatalf("snapshot RequestBody = %q", snap.RequestBody)
	}
	if !snap.SaveRaw {
		t.Fatal("snapshot SaveRaw was not enabled")
	}
}
