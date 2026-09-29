# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `image`: resumable multi-phase rescue imaging (copy with exponential skip,
  copy skipped areas, trim, scrape, retry) with a GNU ddrescue-compatible
  mapfile, fsync-before-checkpoint durability, and an acquisition record
  covering every session and the final image SHA-256.
- `probe`: MBR/EBR and GPT parsing (CRC-validated, backup-GPT fallback,
  512/4096-byte sectors), identification of NTFS, FAT12/16/32, exFAT,
  ext2/3/4, XFS, Btrfs, APFS, HFS+, F2FS, ReFS, ISO 9660, BitLocker, LUKS,
  LVM2 and swap, and `--scan` lost-partition discovery from primary and
  backup structures.
- `recover`: deleted-file recovery for FAT12/16/32 (long-name reconstruction
  including the erased first character, deleted directories, `--deep`
  orphan directory scan) and NTFS (MFT walk with fixups, runlists, attribute
  lists, ADS, sparse/uninitialised data, sequence-aware path reconstruction,
  `$Bitmap` reallocation grading, `$MFTMirr` and backup boot sector
  fallbacks, `--deep` orphan MFT record scan).
- `carve`: structure-validated carving of JPEG, PNG, GIF, BMP, PDF, ZIP
  family (DOCX/XLSX/PPTX/ODT/ODS/ODP/EPUB/JAR/APK), GZIP, 7z, SQLite,
  OLE2 (DOC/XLS/PPT/MSG), RIFF (WAV/AVI/WebP), ISO-BMFF (MP4/MOV/HEIC/AVIF/3GP),
  PE and ELF.
- Evidence case directories with O_EXCL artifacts, path sanitising, a
  fsynced SHA-256 hash-chained journal, a pinned manifest, and `verify`.
- `hash` (MD5/SHA-1/SHA-256) and `version`.
- Fuzz targets for every parser of untrusted input; CI on Linux, macOS and
  Windows with race detector, staticcheck, govulncheck and cross builds.
