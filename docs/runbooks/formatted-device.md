# Runbook: formatted device

**Goal:** recover data from a device that was formatted (accidentally, by a
camera/phone, or by an OS "you need to format this disk" prompt).

## What survives a format

| Format type | Effect | Recovery path |
|---|---|---|
| Quick format, same file system (the default on Windows) | new, empty FAT/root directory or a new small MFT is written at the start; the data area is untouched | `recover --deep` + `carve` |
| Quick format to a different file system | new metadata in different places; old metadata partly survives | `probe --scan` (old volume may still be detectable from backups) + `carve` |
| Full format (Windows Vista+) | every sector overwritten with zeros | nothing recoverable |
| Camera/phone "format" on SD cards | usually quick format; some devices also TRIM/erase | `recover --deep` + `carve`; results depend on the device |

## Procedure

1. Stop using the device; image it:
   ```sh
   sudo barerelic image --out /mnt/dst/sd.img /dev/sdX
   ```
2. Identify the current (new) file system:
   ```sh
   barerelic probe --scan /mnt/dst/sd.img
   ```
   `--scan` may also reveal the *previous* volume if it started at a
   different offset (reformatting with a different layout).
3. **Metadata deep scan** of the current volume:
   ```sh
   barerelic recover --deep --partition 1 --out cases/sd-deep /mnt/dst/sd.img
   ```
   - **FAT:** every cluster is checked for a `.`/`..` directory signature;
     subdirectories that the format orphaned are rebuilt with their files
     under `$OrphanDirs/dir_<cluster>/…`. Root-directory files are lost with
     the root (use carving).
   - **NTFS:** every record-aligned position outside the new MFT is checked
     for a valid `FILE` record (fixups must verify); records of the previous
     MFT are recovered under `$OrphanRecords/`. Small files (< ~700 bytes)
     are stored inside the record and come back exactly.
4. **Carve** everything else:
   ```sh
   barerelic carve --out cases/sd-carve /mnt/dst/sd.img
   ```
   For cameras, `--types jpeg,isobmff` (photos and MP4/MOV/HEIC videos).
5. Verify both cases.

## Expectations

- Folder structure below the root usually survives on FAT; root-level
  names do not.
- NTFS orphan records are graded at most `medium`: they assume the new
  format used the same cluster size (true for default quick formats).
