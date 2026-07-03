package cmd

import "testing"

func TestVersionNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v0.2.0", "v0.1.0", true},
		{"v0.1.1", "v0.1.0", true},
		{"v1.0.0", "v0.9.9", true},
		{"v0.1.0", "v0.1.0", false},
		{"v0.1.0", "v0.2.0", false},
		{"v0.1.0", "v0.1.0-3-gabc123", false},       // local build ahead of the tag -> no nag
		{"v0.1.0", "v0.1.0-3-gabc123-dirty", false}, // suffix ignored; treated as == v0.1.0
		{"v0.2.0", "v0.1.0-3-gabc123", true},        // a real newer release does nag
		{"v0.1.0", "dev", true},               // unparsable current -> offer the release
		{"", "v0.1.0", false},                 // no release info -> no nag
	}
	for _, c := range cases {
		if got := versionNewer(c.latest, c.current); got != c.want {
			t.Errorf("versionNewer(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func TestExpectedSum(t *testing.T) {
	sums := []byte(
		"abc123  confide_linux_amd64\n" +
			"def456  confide_darwin_arm64\n" +
			"999888  SHA256SUMS.txt\n")

	got, err := expectedSum(sums, "confide_darwin_arm64")
	if err != nil || got != "def456" {
		t.Fatalf("expectedSum darwin_arm64 = %q, %v; want def456", got, err)
	}
	if _, err := expectedSum(sums, "confide_windows_amd64.exe"); err == nil {
		t.Errorf("expected error for missing asset, got nil")
	}
}
