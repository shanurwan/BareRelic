# Operations

## Exit codes

| Code | Meaning | Typical action |
|---|---|---|
| `0` | Operation complete; nothing unreadable or unrecoverable | none |
| `1` | Operation failed (cannot open source, destination error, invalid metadata) | read the `level=ERROR` log line |
| `2` | Usage error | fix the invocation (`barerelic <cmd> -h`) |
| `3` | Partial: completed, but some bytes were unreadable, some items could not be recovered, or `verify` found problems | inspect `manifest.json` warnings / the journal; re-run `image` to retry |
| `130` | Interrupted by SIGINT/SIGTERM after checkpointing state | re-run the same command to resume (`image`) or start a new case |

Scripts should treat `0` and `3` as "results are usable" and branch on the
difference.

## Logs and output

- Human results go to **stdout**, logs to **stderr** (`log/slog`).
- `--log-format json` produces one JSON object per line for ingestion.
- `--log-level debug` logs each read error with its offset during imaging.
- Long operations log progress every 5–10 s: position, percentage, rate, ETA,
  and for imaging the rescued/bad/pending byte counts and read errors.

## Imaging: resumability and durability

`image` keeps three files next to each other:

| File | Contents |
|---|---|
| `<out>` | the image; unread areas are zero (sparse where the file system supports it) |
| `<out>.map` | GNU ddrescue mapfile: per-range status `+` rescued, `-` bad, `?`/`*`/`/` pending |
| `<out>.barerelic.json` | acquisition record: tool build, source identity, every session (start, end, bytes before/after, read errors, outcome), final image SHA-256 |

- The map is checkpointed every 30 s, at each phase boundary, and on
  interruption. The image is fsynced first, so the map never over-claims.
- Re-running the identical command resumes; phases already done are skipped
  because they operate on the statuses that remain in the map.
- A finished image re-run is a no-op that re-hashes and records a session.
- The map is compatible with `ddrescueview` (visual inspection) and
  `ddrescue` itself (e.g. to continue with `-d` direct I/O on Linux).

### Tuning for damaged media

| Situation | Setting |
|---|---|
| Drive degrading fast; get the bulk first | `--no-trim` first, then re-run without it |
| Many small scattered errors | smaller `--block-size` (e.g. `4096`) |
| Large damaged zones (head crash on one surface) | keep defaults; the exponential skip (up to `--skip-max`) jumps over them quickly |
| Error areas slowly respond on retry | `--retries 3` or more on a later run |

Reads that hang inside the kernel cannot be interrupted from user space; if
the drive stops responding, power-cycle it and re-run — the map preserves
everything rescued so far.

## Performance and sizing

- Throughput has not been benchmarked on real multi-terabyte media yet (see
  [limitations](limitations.md)). Imaging is expected to be device-bound.
  Carving with `--align 1` checks every byte offset rather than every
  sector start and costs correspondingly more CPU than the default `512`.
- Memory (estimates from the data structures, not measurements):
  - FAT: one FAT copy (≤ 4 bytes/cluster, e.g. 32 MiB for 32 GiB at 4 KiB clusters).
  - NTFS: a compact node per MFT record (~100 bytes; ~100 MB for 1 M records) plus `$Bitmap` (1 bit/cluster).
  - Carving: an 8 MiB window plus the candidate being validated.
- Output space: `recover`/`carve` write full copies; budget at least the
  size of the data you expect to recover, on a different device from the
  source.

## Running against raw devices

| OS | Device path | Notes |
|---|---|---|
| Linux | `/dev/sdb`, `/dev/nvme0n1` | `sudo`; size via `lseek`, sector size via `BLKSSZGET` |
| macOS | `/dev/rdisk2` | `sudo`; use the raw `rdisk` node; `diskutil unmountDisk` first |
| Windows | `\\.\PhysicalDrive1`, `\\.\E:` | elevated prompt; size via `IOCTL_DISK_GET_LENGTH_INFO`; reads are aligned automatically |

Identify the right device before running anything (`lsblk -o NAME,SIZE,MODEL,SERIAL`,
`diskutil list`, `Get-Disk`). Record the model and serial in your case notes.
