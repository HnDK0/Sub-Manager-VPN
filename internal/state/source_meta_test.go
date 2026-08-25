package state

import (
	"path/filepath"
	"testing"
)

func TestSourceMeta(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, ok := st.GetSourceMeta("https://x/sub"); ok {
		t.Fatal("expected no meta for fresh source")
	}

	want := SourceMeta{ETag: `"abc"`, LastModified: "Wed, 01 Jan 2025", BodySHA: "deadbeef"}
	if err := st.SetSourceMeta("https://x/sub", want); err != nil {
		t.Fatalf("set: %v", err)
	}

	got, ok := st.GetSourceMeta("https://x/sub")
	if !ok {
		t.Fatal("expected meta present")
	}
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
}
