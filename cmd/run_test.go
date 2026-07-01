package cmd

import "testing"

func TestEnvKey(t *testing.T) {
	cases := map[string]string{
		"db-password":  "DB_PASSWORD",
		"API Key":      "API_KEY",
		"already_ok":   "ALREADY_OK",
		"3rd-party":    "_3RD_PARTY",
		"weird.name!":  "WEIRD_NAME_",
		"":             "_",
	}
	for in, want := range cases {
		if got := envKey(in); got != want {
			t.Errorf("envKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("a'b"); got != `'a'\''b'` {
		t.Errorf("shellQuote = %q", got)
	}
}
