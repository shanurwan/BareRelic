package evidence

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// GenesisHash is the "prev" value of the first journal entry.
var GenesisHash = hex.EncodeToString(make([]byte, sha256.Size))

// Entry is one line of the append-only, hash-chained journal. Prev is the
// SHA-256 of the previous line's exact bytes, so deleting, reordering or
// editing any entry breaks the chain from that point on.
type Entry struct {
	Seq  uint64          `json:"seq"`
	Time time.Time       `json:"time"`
	Kind string          `json:"kind"`
	Prev string          `json:"prev"`
	Data json.RawMessage `json:"data"`
}

// Journal appends entries durably.
type Journal struct {
	f    *os.File
	seq  uint64
	head string
}

func createJournal(path string) (*Journal, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &Journal{f: f, head: GenesisHash}, nil
}

// Append writes one entry and fsyncs it, so an entry is never reported as
// written unless it survives a crash.
func (j *Journal) Append(kind string, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("journal: marshal %s: %w", kind, err)
	}
	j.seq++
	line, err := json.Marshal(Entry{Seq: j.seq, Time: time.Now().UTC(), Kind: kind, Prev: j.head, Data: raw})
	if err != nil {
		return err
	}
	if _, err := j.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("journal: write: %w", err)
	}
	if err := j.f.Sync(); err != nil {
		return fmt.Errorf("journal: fsync: %w", err)
	}
	sum := sha256.Sum256(line)
	j.head = hex.EncodeToString(sum[:])
	return nil
}

// Head returns the hash of the last entry written.
func (j *Journal) Head() string { return j.head }

// Len returns the number of entries written.
func (j *Journal) Len() uint64 { return j.seq }

func (j *Journal) Close() error { return j.f.Close() }

// ErrChainBroken reports journal tampering or corruption.
var ErrChainBroken = errors.New("journal hash chain broken")

// ReadJournal parses and verifies a journal, returning its entries and head hash.
func ReadJournal(r io.Reader) ([]Entry, string, error) {
	br := bufio.NewReader(r)
	head := GenesisHash
	var entries []Entry
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if line[len(line)-1] != '\n' {
				return entries, head, fmt.Errorf("%w: entry %d is truncated (crash during write?)", ErrChainBroken, len(entries)+1)
			}
			line = bytes.TrimSuffix(line, []byte("\n"))
			var e Entry
			if jerr := json.Unmarshal(line, &e); jerr != nil {
				return entries, head, fmt.Errorf("%w: entry %d is not valid JSON: %v", ErrChainBroken, len(entries)+1, jerr)
			}
			if e.Seq != uint64(len(entries)+1) {
				return entries, head, fmt.Errorf("%w: expected seq %d, found %d", ErrChainBroken, len(entries)+1, e.Seq)
			}
			if e.Prev != head {
				return entries, head, fmt.Errorf("%w at seq %d: prev %s does not match %s", ErrChainBroken, e.Seq, e.Prev, head)
			}
			sum := sha256.Sum256(line)
			head = hex.EncodeToString(sum[:])
			entries = append(entries, e)
		}
		if err == io.EOF {
			return entries, head, nil
		}
		if err != nil {
			return entries, head, err
		}
	}
}
