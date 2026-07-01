package drive

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/maxinielsen/secret-share/internal/config"
	"github.com/maxinielsen/secret-share/internal/keystore"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	driveapi "google.golang.org/api/drive/v3"
)

// Scope requests full Drive access. Full scope is required to read/write a
// shared folder or Shared Drive created by another member; the least-privilege
// drive.file scope cannot see files it did not itself create.
const Scope = driveapi.DriveScope

// buildClientID and buildClientSecret are the OAuth client credentials baked
// into the binary at build time:
//
//	go build -ldflags "\
//	  -X github.com/maxinielsen/secret-share/internal/drive.buildClientID=<id> \
//	  -X github.com/maxinielsen/secret-share/internal/drive.buildClientSecret=<secret>"
//
// A Google "Desktop app" client secret is NOT confidential — Google documents
// that installed apps cannot keep it secret, and PKCE (used in Login) is what
// actually secures the flow. Embedding it means the only artifact you distribute
// to teammates is the binary itself; nobody needs a separate credentials.json.
var (
	buildClientID     string
	buildClientSecret string
)

// configFrom builds an OAuth2 config from explicit client credentials.
func configFrom(clientID, clientSecret, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  redirectURL,
		Scopes:       []string{Scope},
	}
}

// loadOAuthConfig resolves OAuth client credentials in order of precedence:
//
//  1. GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET env vars (override),
//  2. a Google Desktop-app credentials.json at <configdir> (override),
//  3. the credentials baked into the binary at build time (default).
//
// The common case for distributed binaries is (3): zero configuration.
func loadOAuthConfig(redirectURL string) (*oauth2.Config, error) {
	if id := os.Getenv("GOOGLE_OAUTH_CLIENT_ID"); id != "" {
		return configFrom(id, os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"), redirectURL), nil
	}

	dir, dirErr := config.Dir()
	if dirErr == nil {
		if data, err := os.ReadFile(filepath.Join(dir, "credentials.json")); err == nil {
			cfg, err := google.ConfigFromJSON(data, Scope)
			if err != nil {
				return nil, fmt.Errorf("parse credentials.json: %w", err)
			}
			cfg.RedirectURL = redirectURL
			return cfg, nil
		}
	}

	if buildClientID != "" {
		return configFrom(buildClientID, buildClientSecret, redirectURL), nil
	}

	return nil, fmt.Errorf("this build has no embedded OAuth credentials; " +
		"rebuild with -ldflags (see README), set GOOGLE_OAUTH_CLIENT_ID/SECRET, " +
		"or place a Google Desktop-app credentials.json in the config dir")
}

// Login runs the browser-based OAuth loopback flow with PKCE and stores the
// resulting token in the keystore.
func Login(ctx context.Context, ks *keystore.Keystore) error {
	// Bind a loopback listener on a random port for the redirect target.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("open loopback listener: %w", err)
	}
	defer ln.Close()
	redirectURL := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)

	cfg, err := loadOAuthConfig(redirectURL)
	if err != nil {
		return err
	}

	// PKCE + CSRF state.
	verifier := oauth2.GenerateVerifier()
	state := oauth2.GenerateVerifier() // reuse the random generator for state
	authURL := cfg.AuthCodeURL(state,
		oauth2.AccessTypeOffline, // request a refresh token
		oauth2.S256ChallengeOption(verifier),
	)

	type result struct {
		code string
		err  error
	}
	resCh := make(chan result, 1)
	srv := &http.Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			http.Error(w, "Authorization failed: "+e, http.StatusBadRequest)
			resCh <- result{err: fmt.Errorf("authorization denied: %s", e)}
			return
		}
		if q.Get("state") != state {
			http.Error(w, "State mismatch", http.StatusBadRequest)
			resCh <- result{err: fmt.Errorf("state mismatch (possible CSRF)")}
			return
		}
		fmt.Fprintln(w, "Authorization complete. You can close this tab and return to the terminal.")
		resCh <- result{code: q.Get("code")}
	})
	srv.Handler = mux
	go srv.Serve(ln)
	defer srv.Close()

	fmt.Println("Opening your browser to authorize Google Drive access...")
	fmt.Printf("If it doesn't open, visit:\n\n  %s\n\n", authURL)
	_ = browser.OpenURL(authURL)

	var res result
	select {
	case res = <-resCh:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("timed out waiting for authorization")
	}
	if res.err != nil {
		return res.err
	}

	tok, err := cfg.Exchange(ctx, res.code, oauth2.VerifierOption(verifier))
	if err != nil {
		return fmt.Errorf("exchange code for token: %w", err)
	}
	return saveToken(ks, tok)
}

func saveToken(ks *keystore.Keystore, tok *oauth2.Token) error {
	data, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	return ks.SetToken(data)
}

func loadToken(ks *keystore.Keystore) (*oauth2.Token, error) {
	data, err := ks.GetToken()
	if err != nil {
		return nil, err
	}
	var tok oauth2.Token
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, fmt.Errorf("parse stored token: %w", err)
	}
	return &tok, nil
}

// persistingTokenSource writes refreshed tokens back to the keystore.
type persistingTokenSource struct {
	src  oauth2.TokenSource
	ks   *keystore.Keystore
	last *oauth2.Token
}

func (p *persistingTokenSource) Token() (*oauth2.Token, error) {
	tok, err := p.src.Token()
	if err != nil {
		return nil, err
	}
	if p.last == nil || tok.AccessToken != p.last.AccessToken {
		_ = saveToken(p.ks, tok)
		p.last = tok
	}
	return tok, nil
}

// tokenSource returns an auto-refreshing, persisting token source, or an error
// if the user is not logged in.
func tokenSource(ctx context.Context, ks *keystore.Keystore) (oauth2.TokenSource, error) {
	tok, err := loadToken(ks)
	if err != nil {
		return nil, fmt.Errorf("not logged in (run `secret-share login`): %w", err)
	}
	cfg, err := loadOAuthConfig("http://127.0.0.1/callback")
	if err != nil {
		return nil, err
	}
	return &persistingTokenSource{src: cfg.TokenSource(ctx, tok), ks: ks}, nil
}
