# Runbook: deleted or lost partitions

**Symptoms:** the disk shows as "unallocated" or "not initialized", a
partition was deleted, the partition table was overwritten (e.g. by
installing another OS or by malware), or the disk appears as RAW.

## How BareRelic finds lost volumes

`probe --scan` reads every sector and looks for file-system structures,
including the **backup copies** that survive when the start of a volume is
destroyed, then reasons back to where the volume must have started:

| Structure found | Inferred start | Cross-check |
|---|---|---|
| NTFS boot sector | here, *or* here − volume size (backup copy in last sector) | `$MFT` record 0 must be at the declared cluster |
| FAT boot sector | here, *or* here − 6 sectors (FAT32 backup) | first FAT byte equals the media descriptor |
| exFAT boot sector | here (backup region, 12 sectors later, is ignored) | — |
| ext2/3/4 superblock | here − 1024, or from a backup superblock's group number | superblock field consistency |
| GPT (during normal `probe`) | backup header at the last LBA when the primary is damaged | header and partition-array CRC-32 |

## Procedure

1. Image the disk (`barerelic image`), then work on the image.
2. ```sh
   barerelic probe --scan /mnt/dst/disk.img
   ```
   Rows marked `lost` list the inferred start (in bytes), size, file system
   and the evidence used. `high` confidence means the cross-check passed.
3. Recover from a lost volume by offset:
   ```sh
   barerelic recover --all --offset 1048576 --out cases/lost-p1 /mnt/dst/disk.img
   ```
   `--all` exports live files too — on a lost partition, *everything* is lost
   from the user's point of view.
4. Volumes whose file system BareRelic identifies but cannot parse
   (ext4, exFAT, APFS, …): carve the range instead:
   ```sh
   barerelic carve --offset <start> --length <size> --out cases/lost-p2 /mnt/dst/disk.img
   ```

## Repairing the partition table (optional)

BareRelic never writes to disks. If you want the original disk to mount
again, recreate the partition entry with a partitioning tool using the start
and size reported by `probe --scan` — **on a clone, never on the original**.
