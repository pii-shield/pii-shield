package store

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"

	"github.com/pii-shield/pii-shield/rules/internal/storetest"
)

// Two server processes on one Postgres database: concurrent appends and
// publishes from both get distinct numbers and none fails.
func TestPostgresTwoInstancesRace(t *testing.T) {
	if os.Getenv(storetest.EnvPostgres) == "" {
		t.Skip("set " + storetest.EnvPostgres + " to run against Postgres")
	}
	ctx := context.Background()
	dsn := storetest.DSN(t)
	a, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	// The second process applies the schema again over the first's.
	b, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	org, _ := a.CreateOrg(ctx, "acme", "")
	set, _ := a.CreateSet(ctx, org.ID, "payments", "")
	stores := []*Store{a, b}

	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	var revs []int64
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := stores[i%2].CreateVersion(ctx, set.ID, "", "", canon(fmt.Sprintf(`{"a": %d}`, i)))
			if err != nil {
				t.Errorf("version %d: %v", i, err)
				return
			}
			mu.Lock()
			revs = append(revs, v.Revision)
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	sort.Slice(revs, func(i, j int) bool { return revs[i] < revs[j] })
	for i, r := range revs {
		if r != int64(i+1) {
			t.Fatalf("revisions = %v, want 1..%d", revs, n)
		}
	}

	var seqs []int64
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, err := stores[i%2].Publish(ctx, set.ID, PublishRequest{Revision: int64(i%n + 1)})
			if err != nil {
				t.Errorf("publish %d: %v", i, err)
				return
			}
			mu.Lock()
			seqs = append(seqs, p.Seq)
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for i, s := range seqs {
		if s != int64(i+1) {
			t.Fatalf("publications = %v, want 1..%d", seqs, n)
		}
	}
	// What one process wrote the other reads.
	if latest, err := b.LatestPublication(ctx, set.ID); err != nil || latest.Seq != n {
		t.Errorf("latest publication through the other store: %+v %v", latest, err)
	}
}
