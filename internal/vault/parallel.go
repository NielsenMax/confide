package vault

import (
	"strings"

	"github.com/maxinielsen/secret-share/internal/drive"
	"golang.org/x/sync/errgroup"
)

// fetchConcurrency bounds simultaneous Drive downloads. Drive tolerates modest
// parallelism well; this turns an O(N) sequential wait into ~N/limit.
const fetchConcurrency = 12

// files returns only the non-directory entries.
func files(entries []drive.Entry) []drive.Entry {
	out := entries[:0:0]
	for _, e := range entries {
		if !e.IsDir {
			out = append(out, e)
		}
	}
	return out
}

// ageFiles returns only non-directory entries ending in ".age".
func ageFiles(entries []drive.Entry) []drive.Entry {
	out := entries[:0:0]
	for _, e := range entries {
		if !e.IsDir && strings.HasSuffix(e.Name, ".age") {
			out = append(out, e)
		}
	}
	return out
}

// parallelFetch downloads each entry by ID concurrently and maps it through fn,
// preserving input order. The first error aborts and is returned.
func parallelFetch[T any](dc Store, entries []drive.Entry, fn func(drive.Entry, []byte) (T, error)) ([]T, error) {
	results := make([]T, len(entries))
	var g errgroup.Group
	g.SetLimit(fetchConcurrency)
	for i, e := range entries {
		i, e := i, e
		g.Go(func() error {
			data, err := dc.Download(e.ID)
			if err != nil {
				return err
			}
			r, err := fn(e, data)
			if err != nil {
				return err
			}
			results[i] = r
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return results, nil
}

// parallelDo runs fn(entry) for each entry concurrently, bounded by the same
// limit. Used for parallel writes (e.g. rotation re-encryption).
func parallelDo[T any](items []T, fn func(T) error) error {
	var g errgroup.Group
	g.SetLimit(fetchConcurrency)
	for _, it := range items {
		it := it
		g.Go(func() error { return fn(it) })
	}
	return g.Wait()
}
