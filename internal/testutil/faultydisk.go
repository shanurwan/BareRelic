// Package testutil provides fakes shared by tests. It is never linked into
// the barerelic binary.
package testutil

import (
	"errors"
	"io"
	"sync"
)

// ErrMedium mimics an unrecoverable read error (EIO / ERROR_CRC).
var ErrMedium = errors.New("simulated medium error")

// FaultyDisk is an in-memory disk with permanently bad sectors and flaky
// sectors that fail a set number of times before reading successfully.
type FaultyDisk struct {
	Data   []byte
	Sector int

	mu    sync.Mutex
	bad   map[int64]bool
	flaky map[int64]int
	Reads int
}

// NewFaultyDisk wraps data with the given logical sector size.
func NewFaultyDisk(data []byte, sector int) *FaultyDisk {
	return &FaultyDisk{Data: data, Sector: sector, bad: map[int64]bool{}, flaky: map[int64]int{}}
}

// Bad marks sectors as permanently unreadable.
func (d *FaultyDisk) Bad(sectors ...int64) {
	for _, s := range sectors {
		d.bad[s] = true
	}
}

// Flaky makes a sector fail its first n reads.
func (d *FaultyDisk) Flaky(sector int64, n int) { d.flaky[sector] = n }

func (d *FaultyDisk) Size() int64     { return int64(len(d.Data)) }
func (d *FaultyDisk) SectorSize() int { return d.Sector }

// ReadAt behaves like a real device: it returns the readable prefix up to the
// first failing sector together with ErrMedium.
func (d *FaultyDisk) ReadAt(p []byte, off int64) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Reads++
	if off >= int64(len(d.Data)) {
		return 0, io.EOF
	}
	end := min(off+int64(len(p)), int64(len(d.Data)))
	ss := int64(d.Sector)
	for s := off / ss; s*ss < end; s++ {
		failing := d.bad[s]
		if n := d.flaky[s]; n > 0 {
			d.flaky[s] = n - 1
			failing = true
		}
		if failing {
			good := max(s*ss-off, 0)
			copy(p, d.Data[off:off+good])
			return int(good), ErrMedium
		}
	}
	n := copy(p, d.Data[off:end])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// MemImage is an in-memory destination implementing io.WriterAt and Sync.
type MemImage struct {
	Data  []byte
	Syncs int
}

func (m *MemImage) WriteAt(p []byte, off int64) (int, error) {
	if need := off + int64(len(p)); need > int64(len(m.Data)) {
		m.Data = append(m.Data, make([]byte, need-int64(len(m.Data)))...)
	}
	return copy(m.Data[off:], p), nil
}

func (m *MemImage) Sync() error { m.Syncs++; return nil }
