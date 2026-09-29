# Forensic principles and threat model

## Principles

1. **The source is never written.** Sources are opened with `os.Open`
   (`O_RDONLY` / `GENERIC_READ`) and the `source.Source` interface has no
   write method (a test asserts this). Commands refuse output paths that are
   the source itself.
   *This does not stop the operating system from writing.* Mounting a
   volume, Windows offering to "format" or "repair" a disk, journaled file
   systems replaying their journal, and SSD firmware garbage collection all
   modify media. Use a hardware write blocker for evidence, never mount the
   source read-write, and on Windows set the disk offline or read-only
   (`diskpart` → `attributes disk set readonly`) before connecting it.

2. **Image first, analyse the copy.** Every read of failing media risks
   further damage. `image` reads each healthy sector once, then spends
   effort on bad regions last. All other commands should run on the image.

3. **Every claim is traceable.** Each recovered file is journaled with the
   exact source extents it was assembled from, the method, the metadata
   location (directory entry offset or MFT record number, sequence and
   offset), timestamps, confidence and notes. Anyone can re-derive the file
   from the image.

4. **Tamper evidence.** The journal is append-only, each entry is fsynced
   and contains the SHA-256 of the previous entry's exact bytes. The manifest
   pins the final entry count and head hash. `verify` detects edited,
   removed, reordered or truncated entries and any modified artifact.
   The chain proves *internal* consistency; to prove a case was not
   regenerated wholesale, record the manifest's `journal.head_sha256` in your
   case notes or a system outside the examiner's control.

5. **No silent overwrites or mixing.** Artifacts are created with `O_EXCL`;
   name collisions get a `~N` suffix. A case directory must be new or empty.
   An image is only resumed together with its own map, and a map is refused
   if its size does not match the source.

6. **Honest uncertainty.** Recovery is inference. Confidence grades and
   notes say what was assumed. Files touching unreadable regions are flagged
   with the number of zero-filled bytes.

7. **Reproducibility.** Every record includes the tool version, VCS revision,
   Go toolchain, OS/architecture, host name, full command line and options.

## Threat model

BareRelic parses data that is damaged, adversarial, or both: a suspect's
disk may be crafted to crash or mislead analysis tools.

| Threat | Mitigation |
|---|---|
| Path traversal via recovered names (`../../etc/cron.d/x`, absolute paths, `C:`) | every component sanitised; `..`, separators, drive colons and control characters neutralised; `verify` rejects artifact paths outside `files/` |
| Windows device names and aliasing (`CON`, `NUL.txt`, trailing dots/spaces) | reserved names prefixed; trailing dots/spaces replaced |
| Resource exhaustion from size fields (huge FAT/MFT/bitmap/directory) | allocations bounded by bytes that physically exist and by format limits |
| Infinite loops (cyclic FAT chains, EBR loops, parent cycles, directory cycles) | Brent cycle detection, visited sets, depth limits |
| Decompression bombs during gzip validation | inflation capped at 64× the candidate size |
| Parser memory-safety bugs | Go bounds checking; fuzzing of all parsers |
| Misleading content (a file claiming to be larger than the disk) | lengths checked against available bytes; extents past the end fail loudly |
| Tampering with results after the fact | hash-chained journal, pinned manifest, `verify` |

Out of scope: defending against an attacker with write access to the
examiner's workstation, or firmware-level attacks by the storage device.
