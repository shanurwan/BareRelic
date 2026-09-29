# Runbook: deleted files (recently or years ago)

**Goal:** recover deleted files with their names, folders and timestamps
where metadata survives, and their content by carving where it does not.

## Key facts

- On FAT and NTFS, deletion only marks metadata free. Names, sizes and
  (on NTFS) the exact cluster runs survive **until reused**.
- Age matters less than **activity since deletion**: a file deleted five
  years ago on a rarely used archive disk may be intact; one deleted an hour
  ago on a busy system disk may be gone.
- On SSDs and flash with TRIM, deleted content is usually zeroed quickly.
  Metadata may still list the file; its content will be zeros (check the
  recovered file — `low` confidence and all-zero content indicate TRIM).

## Procedure

1. **Stop writing to the device.** Unmount it; do not install recovery
   tools onto it or save recovered files back to it.
2. **Image it** (even if healthy — it makes everything repeatable):
   ```sh
   sudo barerelic image --out /mnt/dst/usb.img /dev/sdX
   ```
3. **Find the volumes:**
   ```sh
   barerelic probe /mnt/dst/usb.img
   ```
4. **Triage without writing:**
   ```sh
   barerelic recover --dry-run --partition 1 /mnt/dst/usb.img | grep -i -E 'docx|jpg'
   ```
5. **Recover:**
   ```sh
   barerelic recover --partition 1 --out cases/usb-deleted /mnt/dst/usb.img
   ```
   Add `--all` to also export live files (useful when the file system is
   damaged and cannot be mounted).
6. **Carve** for files whose metadata was reused:
   ```sh
   barerelic carve --types jpeg,png,pdf,docx,xlsx --out cases/usb-carved /mnt/dst/usb.img
   ```
   Carving the whole image also re-finds files `recover` already produced;
   compare SHA-256 values in the two journals to deduplicate.
7. **Verify** both case directories and hand over.

## Reading the results

| Field | Meaning |
|---|---|
| `state: deleted` | metadata was marked free |
| `state: orphan` | found by `--deep` / parent lost; original folder unknown |
| `confidence: high` | clusters are still free and structure checks passed |
| `confidence: medium` | contiguity or a heuristic was assumed |
| `confidence: low` | clusters reallocated or unreadable; expect damage |
| NTFS `$OrphanFiles/` | parent folder record was reused; name is still original |
| FAT name starting `_` | 8.3 name whose first character was erased and could not be recovered from a long name |
