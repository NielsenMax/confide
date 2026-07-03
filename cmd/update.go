package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/NielsenMax/confide/internal/config"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// repoSlug is the GitHub owner/repo that publishes confide releases.
const repoSlug = "NielsenMax/confide"

// updateCheckInterval bounds how often the background notice hits the GitHub API.
const updateCheckInterval = 24 * time.Hour

var httpClient = &http.Client{Timeout: 5 * time.Minute}

var updateForce bool

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update confide to the latest release",
	Long: `update downloads the latest release binary for your OS/arch from
GitHub, verifies its SHA-256 checksum, and replaces the running binary in place.

It updates the CLI itself — not your vault or any secrets.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		fmt.Println("Checking for the latest release...")
		tag, err := latestReleaseTag(ctx)
		if err != nil {
			return fmt.Errorf("check latest release: %w", err)
		}
		if !updateForce && !versionNewer(tag, version) {
			fmt.Printf("confide %s is already up to date (latest is %s).\n", version, tag)
			return nil
		}

		asset := assetName()
		base := fmt.Sprintf("https://github.com/%s/releases/download/%s/", repoSlug, tag)

		fmt.Printf("Downloading %s (%s)...\n", asset, tag)
		bin, err := httpGet(ctx, base+asset)
		if err != nil {
			return fmt.Errorf("download %s: %w", asset, err)
		}

		sums, err := httpGet(ctx, base+"SHA256SUMS.txt")
		if err != nil {
			return fmt.Errorf("download checksums: %w", err)
		}
		want, err := expectedSum(sums, asset)
		if err != nil {
			return err
		}
		got := sha256.Sum256(bin)
		if !strings.EqualFold(hex.EncodeToString(got[:]), want) {
			return fmt.Errorf("checksum mismatch for %s — refusing to install a corrupted download", asset)
		}

		if err := replaceSelf(bin); err != nil {
			return err
		}
		fmt.Printf("Updated confide %s -> %s.\n", version, tag)
		return nil
	},
}

// assetName is the release asset for the running OS/arch, matching the names
// produced by .github/workflows/release.yml.
func assetName() string {
	n := fmt.Sprintf("confide_%s_%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		n += ".exe"
	}
	return n
}

// latestReleaseTag returns the tag_name of the latest published release.
func latestReleaseTag(ctx context.Context) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repoSlug)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "confide/"+version)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api returned %s", resp.Status)
	}
	var body struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", err
	}
	if body.TagName == "" {
		return "", fmt.Errorf("no release found")
	}
	return body.TagName, nil
}

// httpGet fetches a URL and returns its body, following redirects.
func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "confide/"+version)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// expectedSum finds the hex SHA-256 for asset in a `sha256sum`-style file.
func expectedSum(sums []byte, asset string) (string, error) {
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == asset {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("no checksum listed for %s", asset)
}

// replaceSelf overwrites the running executable with newBin atomically.
func replaceSelf(newBin []byte) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)

	tmp, err := os.CreateTemp(dir, ".confide-update-*")
	if err != nil {
		return fmt.Errorf("write to %s (need write permission there): %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(newBin); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}

	// A running executable can't be replaced by rename on Windows, so move it
	// aside first. On Unix, rename-over swaps the inode and the running process
	// keeps its open copy.
	if runtime.GOOS == "windows" {
		_ = os.Remove(exe + ".old")
		if err := os.Rename(exe, exe+".old"); err != nil {
			return fmt.Errorf("move old binary aside: %w", err)
		}
	}
	if err := os.Rename(tmpName, exe); err != nil {
		return fmt.Errorf("replace %s: %w", exe, err)
	}
	return nil
}

// --- version comparison ---

// versionNewer reports whether latest is a strictly newer release than current.
// Both are parsed as vMAJOR.MINOR.PATCH (any -prerelease/+build suffix ignored).
// If either can't be parsed (e.g. a "dev" build), it falls back to reporting
// that any non-empty, differing latest is newer.
func versionNewer(latest, current string) bool {
	l, lok := parseVersion(latest)
	c, cok := parseVersion(current)
	if !lok || !cok {
		return strings.TrimSpace(latest) != "" && latest != current
	}
	for i := 0; i < 3; i++ {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// --- best-effort "new version available" notice ---

type updateCache struct {
	CheckedAt int64  `json:"checked_at"`
	Latest    string `json:"latest"`
}

func updateCachePath() string {
	dir, err := config.Dir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "update-check.json")
}

// maybeNotifyUpdate prints a one-line notice to stderr when a newer release
// exists. It is best-effort: silent for dev builds, non-interactive sessions,
// and any error; it checks the network at most once per updateCheckInterval.
func maybeNotifyUpdate(cmd *cobra.Command) {
	if version == "dev" || version == "" {
		return
	}
	if os.Getenv("CONFIDE_NO_UPDATE_CHECK") != "" {
		return
	}
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		return
	}
	switch cmd.Name() {
	case "update", "version", "help":
		return
	}

	latest := cachedOrFetchLatest(cmd.Context())
	if latest != "" && versionNewer(latest, version) {
		fmt.Fprintf(os.Stderr,
			"\nA new version of confide is available: %s (you have %s).\n"+
				"Run `confide update` to upgrade.\n", latest, version)
	}
}

// cachedOrFetchLatest returns the latest known tag, using the on-disk cache when
// fresh and otherwise refreshing it with a short timeout.
func cachedOrFetchLatest(ctx context.Context) string {
	p := updateCachePath()
	var cache updateCache
	if p != "" {
		if data, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(data, &cache)
		}
	}
	if cache.CheckedAt > 0 && time.Since(time.Unix(cache.CheckedAt, 0)) < updateCheckInterval {
		return cache.Latest
	}

	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tag, err := latestReleaseTag(cctx)
	if err != nil {
		// Back off for the interval even on failure, keeping the last known tag,
		// so we don't hit the API on every command while offline.
		cache.CheckedAt = time.Now().Unix()
		writeUpdateCache(p, cache)
		return cache.Latest
	}
	writeUpdateCache(p, updateCache{CheckedAt: time.Now().Unix(), Latest: tag})
	return tag
}

func writeUpdateCache(p string, c updateCache) {
	if p == "" {
		return
	}
	if data, err := json.Marshal(c); err == nil {
		_ = os.WriteFile(p, data, 0o600)
	}
}

func init() {
	updateCmd.Flags().BoolVar(&updateForce, "force", false, "reinstall even if already on the latest version")
	rootCmd.AddCommand(updateCmd)

	// After any successful command, nudge interactive users toward a newer
	// release. No subcommand overrides PersistentPostRun, so this always runs.
	rootCmd.PersistentPostRun = func(cmd *cobra.Command, args []string) {
		maybeNotifyUpdate(cmd)
	}
}
