package dnp3_test

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/cB-Sigma/dnp3"
)

// Covers: SIG-IPE-1596
func TestIEEE1815FileTransfer(t *testing.T) {
	sim := startSim(t)
	content := bytes.Repeat([]byte("0123456789"), 30) // 300 octets: five 64-octet blocks
	sim.PutFile("logs/", nil)
	sim.PutFile("logs/events.csv", content)
	sim.PutFile("logs/old.csv", []byte("x"))
	m := dial(t, sim, nil, nil)
	ctx := context.Background()
	fc := &dnp3.FileClient{M: m, MaxBlock: 128}
	// Read: open (block size negotiated down to 64), blocks 0..4, close.
	got, err := fc.ReadFile(ctx, "logs/events.csv")
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("read %d octets: %v", len(got), err)
	}
	if sim.OpenFiles() != 0 {
		t.Error("the file was left open")
	}
	// Information and directory listing.
	d, err := fc.Info(ctx, "logs/events.csv")
	if err != nil || d.Size != 300 || d.Type != 1 || d.Name != "logs/events.csv" {
		t.Fatalf("%+v %v", d, err)
	}
	if _, err := fc.Info(ctx, "nope"); err == nil || !strings.Contains(err.Error(), "file-not-found") {
		t.Fatalf("missing file: %v", err)
	}
	ents, err := fc.List(ctx, "logs/")
	if err != nil || len(ents) != 2 {
		t.Fatalf("%+v %v", ents, err)
	}
	// Write, then delete.
	if err := fc.WriteFile(ctx, "cfg/new.bin", bytes.Repeat([]byte{7}, 150)); err != nil {
		t.Fatal(err)
	}
	if b, ok := sim.File("cfg/new.bin"); !ok || len(b) != 150 {
		t.Fatalf("written %d octets", len(b))
	}
	if err := fc.Delete(ctx, "cfg/new.bin"); err != nil {
		t.Fatal(err)
	}
	if _, ok := sim.File("cfg/new.bin"); ok {
		t.Fatal("not deleted")
	}
	// Delayed answers: null responses, then the objects as class 3 events
	// (5.3.3); a password is needed (5.3.1).
	sim.DelayFileAnswers(true)
	sim.RequireFilePassword("zebra")
	if _, err := fc.ReadFile(ctx, "logs/old.csv"); err == nil || !strings.Contains(err.Error(), "permission-denied") {
		t.Fatalf("without the password: %v", err)
	}
	fc.User, fc.Password = "scada", "zebra"
	if got, err := fc.ReadFile(ctx, "logs/old.csv"); err != nil || string(got) != "x" {
		t.Fatalf("delayed read: %q %v", got, err)
	}
	if !slices.Contains(sim.Requests(), "AUTHENTICATE_FILE g70v2") || !slices.Contains(sim.Requests(), "READ g60v2 g60v3 g60v4") {
		t.Errorf("requests %q", sim.Requests())
	}
}
