package drive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/maxinielsen/secret-share/internal/config"
	"github.com/maxinielsen/secret-share/internal/keystore"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	driveapi "google.golang.org/api/drive/v3"
)

const folderMIME = "application/vnd.google-apps.folder"

// ErrNotFound indicates a path does not exist in the store.
var ErrNotFound = errors.New("drive: not found")

// Client is a path-addressed view of the vault store on Drive. Paths are
// slash-separated and resolved relative to the configured root folder, e.g.
// "myvault/secrets/abc.age".
type Client struct {
	svc        *driveapi.Service
	cfg        *config.Config
	folderIDs  map[string]string // path -> folder ID cache ("" = root)
}

// New builds a Drive client using stored OAuth credentials.
func New(ctx context.Context, ks *keystore.Keystore, cfg *config.Config) (*Client, error) {
	ts, err := tokenSource(ctx, ks)
	if err != nil {
		return nil, err
	}
	svc, err := driveapi.NewService(ctx, option.WithTokenSource(ts))
	if err != nil {
		return nil, fmt.Errorf("create drive service: %w", err)
	}
	c := &Client{svc: svc, cfg: cfg, folderIDs: map[string]string{"": cfg.RootFolderID}}
	return c, nil
}

// sharedDrive reports whether the store lives on a Shared Drive.
func (c *Client) sharedDrive() bool { return c.cfg.DriveID != "" }

// applyDriveScope adds Shared Drive parameters to a files list call.
func (c *Client) listCall(q string) *driveapi.FilesListCall {
	call := c.svc.Files.List().Q(q).
		Fields("files(id,name,mimeType,modifiedTime,size)").
		SupportsAllDrives(true).
		IncludeItemsFromAllDrives(true)
	if c.sharedDrive() {
		call = call.Corpora("drive").DriveId(c.cfg.DriveID)
	}
	return call
}

// findChild returns the ID of a child named name under parentID, or "".
func (c *Client) findChild(parentID, name string) (string, string, error) {
	q := fmt.Sprintf("name = %s and %s in parents and trashed = false",
		quote(name), quote(parentID))
	res, err := c.listCall(q).Do()
	if err != nil {
		return "", "", fmt.Errorf("list children: %w", err)
	}
	if len(res.Files) == 0 {
		return "", "", nil
	}
	return res.Files[0].Id, res.Files[0].MimeType, nil
}

// EnsureRootFolder finds or creates the top-level store folder named name and
// records its ID in cfg. Call once during init.
func (c *Client) EnsureRootFolder(name string) error {
	parent := c.cfg.DriveID // root of a Shared Drive, or "" for My Drive
	if parent == "" {
		parent = "root"
	}
	id, _, err := c.findChild(parent, name)
	if err != nil {
		return err
	}
	if id == "" {
		id, err = c.createFolder(parent, name)
		if err != nil {
			return err
		}
	}
	c.cfg.RootFolderID = id
	c.folderIDs[""] = id
	return nil
}

func (c *Client) createFolder(parentID, name string) (string, error) {
	f := &driveapi.File{Name: name, MimeType: folderMIME, Parents: []string{parentID}}
	created, err := c.svc.Files.Create(f).SupportsAllDrives(true).Fields("id").Do()
	if err != nil {
		return "", fmt.Errorf("create folder %q: %w", name, err)
	}
	return created.Id, nil
}

// resolveFolder walks/creates the folder chain for a slash path (no filename).
func (c *Client) resolveFolder(dir string, create bool) (string, error) {
	dir = strings.Trim(dir, "/")
	if id, ok := c.folderIDs[dir]; ok {
		return id, nil
	}
	if c.cfg.RootFolderID == "" {
		return "", fmt.Errorf("store not initialized (run `secret-share init`)")
	}
	parentID := c.folderIDs[""]
	cur := ""
	for _, part := range strings.Split(dir, "/") {
		if part == "" {
			continue
		}
		cur = strings.TrimPrefix(cur+"/"+part, "/")
		if id, ok := c.folderIDs[cur]; ok {
			parentID = id
			continue
		}
		id, mime, err := c.findChild(parentID, part)
		if err != nil {
			return "", err
		}
		if id == "" {
			if !create {
				return "", ErrNotFound
			}
			if id, err = c.createFolder(parentID, part); err != nil {
				return "", err
			}
		} else if mime != folderMIME {
			return "", fmt.Errorf("%q is not a folder", cur)
		}
		c.folderIDs[cur] = id
		parentID = id
	}
	return parentID, nil
}

// splitPath separates a path into its directory and filename.
func splitPath(path string) (dir, name string) {
	path = strings.Trim(path, "/")
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return "", path
	}
	return path[:i], path[i+1:]
}

// WriteFile creates or overwrites the file at path with data.
func (c *Client) WriteFile(path string, data []byte) error {
	dir, name := splitPath(path)
	parentID, err := c.resolveFolder(dir, true)
	if err != nil {
		return err
	}
	existingID, _, err := c.findChild(parentID, name)
	if err != nil {
		return err
	}
	media := bytes.NewReader(data)
	if existingID != "" {
		_, err = c.svc.Files.Update(existingID, &driveapi.File{}).
			Media(media).SupportsAllDrives(true).Fields("id").Do()
		if err != nil {
			return fmt.Errorf("update %q: %w", path, err)
		}
		return nil
	}
	f := &driveapi.File{Name: name, Parents: []string{parentID}}
	_, err = c.svc.Files.Create(f).Media(media).SupportsAllDrives(true).Fields("id").Do()
	if err != nil {
		return fmt.Errorf("create %q: %w", path, err)
	}
	return nil
}

// ReadFile returns the contents of the file at path, or ErrNotFound.
func (c *Client) ReadFile(path string) ([]byte, error) {
	dir, name := splitPath(path)
	parentID, err := c.resolveFolder(dir, false)
	if err != nil {
		return nil, err
	}
	id, _, err := c.findChild(parentID, name)
	if err != nil {
		return nil, err
	}
	if id == "" {
		return nil, ErrNotFound
	}
	return c.Download(id)
}

// Download fetches a file's contents by its Drive file ID.
func (c *Client) Download(id string) ([]byte, error) {
	resp, err := c.svc.Files.Get(id).SupportsAllDrives(true).Download()
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", id, err)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// Entry describes a child of a folder.
type Entry struct {
	Name     string
	ID       string
	IsDir    bool
	Modified string // RFC3339 modifiedTime, when available
	Size     int64  // content size in bytes; 0 marks a soft-deleted tombstone
}

// List returns the entries of the folder at dir. A missing folder yields nil.
func (c *Client) List(dir string) ([]Entry, error) {
	parentID, err := c.resolveFolder(dir, false)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	q := fmt.Sprintf("%s in parents and trashed = false", quote(parentID))
	var entries []Entry
	pageToken := ""
	for {
		call := c.listCall(q)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		res, err := call.Do()
		if err != nil {
			return nil, fmt.Errorf("list %q: %w", dir, err)
		}
		for _, f := range res.Files {
			entries = append(entries, Entry{
				Name:     f.Name,
				ID:       f.Id,
				IsDir:    f.MimeType == folderMIME,
				Modified: f.ModifiedTime,
				Size:     f.Size,
			})
		}
		if res.NextPageToken == "" {
			break
		}
		pageToken = res.NextPageToken
	}
	return entries, nil
}

// Remove deletes the file or folder at path. A missing path is not an error.
func (c *Client) Remove(path string) error {
	dir, name := splitPath(path)
	parentID, err := c.resolveFolder(dir, false)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	id, _, err := c.findChild(parentID, name)
	if err != nil {
		return err
	}
	if id == "" {
		return nil
	}
	if err := c.svc.Files.Delete(id).SupportsAllDrives(true).Do(); err != nil {
		var gerr *googleapi.Error
		if errors.As(err, &gerr) {
			if gerr.Code == 404 {
				return nil
			}
			if gerr.Code == 403 {
				// We have Editor but not ownership of this file (a teammate created
				// it in a shared My Drive folder), so we can't hard-delete it. Fall
				// back to a soft delete: truncate the content to an empty tombstone,
				// which an Editor is permitted to do. Callers treat size-0 files as
				// deleted.
				if terr := c.emptyFile(id); terr != nil {
					return fmt.Errorf("delete %q: not the file owner and tombstone failed: %w", path, terr)
				}
				delete(c.folderIDs, strings.Trim(path, "/"))
				return nil
			}
		}
		return fmt.Errorf("delete %q: %w", path, err)
	}
	// Invalidate any cached folder id we just removed.
	delete(c.folderIDs, strings.Trim(path, "/"))
	return nil
}

// HardDeleteByID permanently deletes a file by ID. A 403 (not the owner) is
// reported as deleted=false with no error so callers can skip it; 404 counts as
// already deleted.
func (c *Client) HardDeleteByID(id string) (bool, error) {
	err := c.svc.Files.Delete(id).SupportsAllDrives(true).Do()
	if err == nil {
		return true, nil
	}
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		if gerr.Code == 404 {
			return true, nil
		}
		if gerr.Code == 403 {
			return false, nil
		}
	}
	return false, fmt.Errorf("delete %s: %w", id, err)
}

// emptyFile truncates a file's content to zero bytes, marking it a tombstone.
func (c *Client) emptyFile(id string) error {
	_, err := c.svc.Files.Update(id, &driveapi.File{}).
		Media(bytes.NewReader(nil)).
		SupportsAllDrives(true).
		Fields("id").
		Do()
	if err != nil {
		return fmt.Errorf("truncate %s: %w", id, err)
	}
	return nil
}

// RootFolderID returns the configured store folder ID.
func (c *Client) RootFolderID() string { return c.cfg.RootFolderID }

// ShareFolder grants a Google account access to the store folder so their CLI
// can read and write it. role is typically "writer".
func (c *Client) ShareFolder(folderID, email, role string) error {
	perm := &driveapi.Permission{Type: "user", Role: role, EmailAddress: email}
	_, err := c.svc.Permissions.Create(folderID, perm).
		SupportsAllDrives(true).
		SendNotificationEmail(true).
		Do()
	if err != nil {
		return fmt.Errorf("share folder with %s: %w", email, err)
	}
	return nil
}

// quote renders a string as a Drive query literal.
func quote(s string) string {
	return "'" + strings.NewReplacer("\\", "\\\\", "'", "\\'").Replace(s) + "'"
}
