# Limitations and roadmap

## Validation boundary

What has been demonstrated:

- Unit, property and fault-injection tests of every package; end-to-end CLI
  test on a synthetic MBR disk with FAT16 and NTFS partitions.
- Fuzzing of every parser of untrusted input (NTFS records and runlists, FAT
  boot sector and full directory walk, all carving validators, partition
  tables, mapfiles). Fuzzing found and fixed: a validator accepting a
  declared size larger than the available data, a mapfile phase byte that
  could not round-trip, and unbounded work on cyclic FAT chains and
  oversized declared metadata.
- `go vet`, staticcheck and govulncheck clean; cross-compiles for Linux,
  macOS, Windows and FreeBSD.

What has **not** been demonstrated yet:

- Recovery against real disk images produced by Windows, Linux, macOS,
  cameras and phones (the synthetic images follow the specifications, but
  real implementations have quirks).
- Imaging of real failing hardware, and the raw-device geometry code paths
  (they compile on every platform but were not executed against devices).
- Throughput and memory on multi-terabyte volumes.

A good next step is a regression corpus of public forensic test images
(e.g. NIST CFReDS, Digital Corpora) with expected-output manifests.

## Physical limits (no tool can overcome these)

- **Overwritten sectors** hold only the new data.
- **TRIM / discard** on SSDs, SD cards, eMMC and most phones: deleted blocks
  are unmapped and read back as zeros, usually within minutes.
- **Encryption** without the key (BitLocker, LUKS, FileVault, APFS, Android/iOS file-based encryption).
- **Hardware faults** beyond sector errors (dead PCB, seized motor, failed
  controller) need a clean-room lab; BareRelic starts once the device reads.

## Current software limits

| Area | Limit |
|---|---|
| File systems with metadata recovery | FAT12/16/32 and NTFS only. exFAT, ext2/3/4, HFS+, APFS, XFS, Btrfs, F2FS, ReFS are identified; recover their content with `carve` |
| FAT deleted files | the chain is erased on deletion, so contiguity is assumed (confidence ≤ medium for multi-cluster files). Some FAT32 drivers clear the high word of the start cluster |
| FAT timestamps | stored in local time without a zone; reported as-is (labelled UTC) |
| NTFS | LZNT1-compressed and EFS-encrypted streams are skipped with a note; `$UsnJrnl`/`$LogFile` are not parsed; resident-data extents in the journal point at the MFT record (provenance, not a byte-exact copy, because of fixups) |
| NTFS orphan records (`--deep`) | streams in extension records cannot be reassembled; cluster size of the previous file system is assumed unchanged |
| Carving | contiguous files only; PDF end detection is heuristic; ZIP64 archives are recognised through the central directory only; MP3, RAR, video formats other than ISO-BMFF/RIFF are not yet carved |
| Partition schemes | MBR/EBR and GPT. Apple partition map, BSD disklabels, LVM, Windows dynamic disks, Storage Spaces and RAID are not reassembled |
| Imaging | no direct I/O (`O_DIRECT`) or per-read timeout; reverse passes and head-skipping heuristics of ddrescue are not implemented |
| Case output | a case is written once; there is no incremental re-run into the same directory |

## Roadmap

1. Real-image regression corpus with expected manifests in CI.
2. exFAT and ext4 recovery (ext4 deleted-inode recovery via the journal).
3. `carve --unallocated`: restrict carving to free clusters using FAT/NTFS
   allocation data, and exclude files already recovered by `recover`.
4. Fragmented-file carving (bifragment gap carving for JPEG and ZIP).
5. LZNT1 decompression for NTFS compressed streams.
6. `image`: Linux `O_DIRECT`, reverse passes, per-read watchdog and
   SMART/health snapshot in the acquisition record.
7. E01 (Expert Witness) input support.
8. Signed release artifacts with SBOM and provenance attestations.
