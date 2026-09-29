# Runbook: failing or physically damaged drive

**Symptoms:** clicking, very slow reads, I/O errors in `dmesg`/Event Viewer,
the OS hangs when the disk is attached, SMART reallocated/pending sectors.

**Goal:** get the maximum data off the device with the fewest reads, then
never touch it again.

## Before you start

- [ ] Stop using the device. Every power-on hour costs data.
- [ ] Do **not** run `chkdsk`, `fsck`, or "repair" tools on it: they write.
- [ ] Prevent auto-mount (Linux: don't open it in a file manager; Windows:
      `diskpart` → `automount disable`; macOS: `diskutil unmountDisk`).
- [ ] Attach through a write blocker if this is evidence.
- [ ] Destination has free space ≥ the device size, on a *different* disk.
- [ ] Identify the device precisely (`lsblk -o NAME,SIZE,MODEL,SERIAL`,
      `Get-Disk`, `diskutil list`) and note model and serial.
- [ ] If the drive makes mechanical noises (clicking, grinding, beeping) or
      is not detected at all, stop: it needs a clean-room lab. Software
      reads can destroy the platters.

## Procedure

1. **Fast first pass** to secure the healthy majority:
   ```sh
   sudo barerelic image --no-trim --out /mnt/dst/case.img --case C-1 /dev/sdX
   ```
   Exit `3` is expected on a failing drive. Watch the `progress` log lines:
   a falling `rate_bps` or rising `read_errors` means the drive is degrading;
   let the pass finish rather than restarting it.

2. **Full rescue** (trim, scrape, retry) by re-running without `--no-trim`:
   ```sh
   sudo barerelic image --retries 3 --out /mnt/dst/case.img /dev/sdX
   ```
   It resumes from the map; nothing already rescued is read again.

3. **If the drive stops responding:** Ctrl-C (the map is checkpointed),
   power-cycle the drive, re-run the same command. If a read hangs in the
   kernel, unplug the drive; at most the last 30 s of progress is re-done.

4. **Inspect the damage:** open `case.img.map` in `ddrescueview`, or read
   `case.img.barerelic.json` → `result.bad_sector`.

5. **Verify and continue on the image only:**
   ```sh
   barerelic verify /mnt/dst/case.img
   barerelic probe --scan /mnt/dst/case.img
   barerelic recover --all --map /mnt/dst/case.img.map --out cases/C-1 /mnt/dst/case.img
   ```
   Always pass `--map`: files that touch unreadable sectors are flagged
   `low` with the count of zero-filled bytes.

## Done when

- `image` exits `0`, or repeated retry runs stop reducing `bad_sector`.
- The acquisition record holds the image SHA-256 and every session.
- The device is disconnected and stored; all further work uses the image.
