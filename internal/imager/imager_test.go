package imager

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"testing"

	"github.com/shanurwan/barerelic/internal/rescuemap"
	"github.com/shanurwan/barerelic/internal/testutil"
)

func randomData(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// assertImage checks that every rescued byte equals the source and that every
// bad sector is recorded as such in the map.
func assertImage(t *testing.T, disk *testutil.FaultyDisk, img []byte, m *rescuemap.Map, bad []int64) {
	t.Helper()
	ss := int64(disk.Sector)
	badSet := map[int64]bool{}
	for _, s := range bad {
		badSet[s] = true
	}
	for s := int64(0); s*ss < disk.Size(); s++ {
		lo, hi := s*ss, min((s+1)*ss, disk.Size())
		miss := m.Unrescued(lo, hi-lo)
		switch {
		case badSet[s] && miss != hi-lo:
			t.Fatalf("sector %d is bad but map shows %d/%d bytes rescued", s, (hi-lo)-miss, hi-lo)
		case !badSet[s] && miss != 0:
			t.Fatalf("sector %d is good but map shows %d bytes unrescued", s, miss)
		case !badSet[s] && !bytes.Equal(img[lo:hi], disk.Data[lo:hi]):
			t.Fatalf("sector %d content mismatch", s)
		}
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRescueWithBadAndFlakySectors(t *testing.T) {
	const ss = 512
	data := randomData(4<<20+300, 7) // deliberately not a whole number of sectors
	disk := testutil.NewFaultyDisk(data, ss)
	bad := []int64{0, 1, 100, 101, 102, 2048, 5000, 8191, 8192}
	disk.Bad(bad...)
	disk.Flaky(300, 1)  // recovered during trim/scrape
	disk.Flaky(3000, 2) // recovered during retry
	img := &testutil.MemImage{Data: make([]byte, len(data))}
	m := rescuemap.New(disk.Size())

	var saves int
	res, err := Run(context.Background(), disk, img, m, Options{
		BlockSize: 64 << 10, Retries: 2,
		Save: func(*rescuemap.Map) error { saves++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	assertImage(t, disk, img.Data, m, bad)
	// Sector 8192 is the final, partial sector (300 bytes).
	if want := int64(len(bad)-1)*ss + 300; res.BadSector != want {
		t.Fatalf("bad bytes = %d, want %d", res.BadSector, want)
	}
	if res.Pending != 0 || res.Complete() {
		t.Fatalf("unexpected result %+v", res)
	}
	if saves == 0 || img.Syncs < saves {
		t.Fatalf("map saved %d times but image synced only %d times", saves, img.Syncs)
	}
}

func TestPerfectDiskSinglePass(t *testing.T) {
	data := randomData(1<<20, 3)
	disk := testutil.NewFaultyDisk(data, 4096)
	img := &testutil.MemImage{}
	m := rescuemap.New(disk.Size())
	res, err := Run(context.Background(), disk, img, m, Options{BlockSize: 128 << 10})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete() || m.CurrentPhase != rescuemap.PhaseFinished {
		t.Fatalf("expected complete rescue, got %+v phase %c", res, m.CurrentPhase)
	}
	if !bytes.Equal(img.Data, data) {
		t.Fatal("image differs from source")
	}
	if disk.Reads != 8 {
		t.Fatalf("healthy disk should be read exactly once per block, got %d reads", disk.Reads)
	}
}

// cancelAfter cancels the context after n reads, simulating Ctrl-C mid-rescue.
type cancelAfter struct {
	*testutil.FaultyDisk
	n      int
	cancel context.CancelFunc
}

func (c *cancelAfter) ReadAt(p []byte, off int64) (int, error) {
	c.n--
	if c.n == 0 {
		c.cancel()
	}
	return c.FaultyDisk.ReadAt(p, off)
}

func TestInterruptAndResume(t *testing.T) {
	data := randomData(2<<20, 11)
	disk := testutil.NewFaultyDisk(data, 512)
	bad := []int64{10, 11, 3333}
	disk.Bad(bad...)
	img := &testutil.MemImage{Data: make([]byte, len(data))}
	m := rescuemap.New(disk.Size())

	var saved []byte
	save := func(m *rescuemap.Map) error {
		var b bytes.Buffer
		_, err := m.WriteTo(&b)
		saved = b.Bytes()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, err := Run(ctx, &cancelAfter{FaultyDisk: disk, n: 5, cancel: cancel}, img, m, Options{BlockSize: 64 << 10, Save: save})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if saved == nil {
		t.Fatal("map was not checkpointed on cancellation")
	}

	// Resume from the persisted map, exactly as a new process would.
	resumed, err := rescuemap.Parse(bytes.NewReader(saved))
	if err != nil {
		t.Fatal(err)
	}
	before := resumed.Totals()[rescuemap.Finished]
	if before == 0 || before == resumed.Size() {
		t.Fatalf("interrupted map should be partial, has %d/%d", before, resumed.Size())
	}
	if _, err := Run(context.Background(), disk, img, resumed, Options{BlockSize: 64 << 10, Save: save}); err != nil {
		t.Fatal(err)
	}
	assertImage(t, disk, img.Data, resumed, bad)
}

func TestRejectsMismatchedMap(t *testing.T) {
	disk := testutil.NewFaultyDisk(make([]byte, 4096), 512)
	_, err := Run(context.Background(), disk, &testutil.MemImage{}, rescuemap.New(8192), Options{})
	if err == nil {
		t.Fatal("expected refusal for a map from a different-sized source")
	}
}

type failingWriter struct{ testutil.MemImage }

func (f *failingWriter) WriteAt([]byte, int64) (int, error) { return 0, errors.New("disk full") }

func TestDestinationFailureIsFatal(t *testing.T) {
	disk := testutil.NewFaultyDisk(make([]byte, 1<<20), 512)
	m := rescuemap.New(disk.Size())
	_, err := Run(context.Background(), disk, &failingWriter{}, m, Options{})
	if !errors.Is(err, ErrDestination) {
		t.Fatalf("expected ErrDestination, got %v", err)
	}
	if got := m.Totals()[rescuemap.Finished]; got != 0 {
		t.Fatalf("map claims %d rescued bytes that were never written", got)
	}
}
