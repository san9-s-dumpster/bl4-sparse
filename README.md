# BL4 Sparse

Experimental Windows tool for reclaiming disk space from superseded Borderlands 4
patch data. It reads Unreal Engine IoStore indexes and replaces selected older
payload ranges with NTFS sparse holes, preserving file lengths and offsets.

**The patch-priority assumption is not fully verified against the game's runtime.**
Hashes verify that retained bytes were preserved; they do not prove the game will
never request removed data. Keep the recovery backup while testing maps, saves,
quests and DLC. Savings vary by build and installation.

## Requirements

- Windows with the game installed on NTFS.
- Python 3.10 or newer, available as py, python, or python3.
- A supported stock IoStore layout: standard TOC version 8, unencrypted and
  unsigned, with one .ucas per .utoc and numeric _N_P patch names.
- Enough free space for an uncompressed backup of every selected byte range,
  plus a small reserve. The scan displays the required amount.

No third-party Python packages, AES keys, downloads, telemetry, administrator
session, or game-account credentials are needed. Normal permission to read and
write the selected files is required.

## Quick start: prompted PowerShell workflow

Download/extract this repository, open PowerShell in its folder, and run:

~~~powershell
py -3 .\bl4_sparse.py
~~~

If your installation exposes Python as python instead, run:

~~~powershell
python .\bl4_sparse.py
~~~

The guided workflow:

1. Enter the **game installation directory**, or its OakGame\Content\Paks folder.
   Paths containing spaces or brackets work; surrounding quotes are accepted.
2. Wait for the **read-only scan** and review the reported candidate space.
3. Enter a **new backup folder**. Its parent folder must already exist. Use
   another drive to free space on the drive holding the game.
   **Press Enter here to stop after the scan without modifying the game.**
4. Close the game and its launcher/updater. Read the notice, then type **APPLY**
   to create the backup and make the sparse holes.

Existing backup directories are never overwritten. The tool writes a uniquely
named plan in reports/. That folder is excluded from Git.

An optional PowerShell launcher locates a compatible Python installation:

~~~powershell
.\bl4-sparse.ps1
~~~

If your PowerShell execution policy blocks .ps1 files, use the Python command
above. The tool does not change your execution policy. Both entry points use
the same prompts and behavior.

### Scan only

~~~powershell
.\bl4-sparse.ps1 -Mode Audit
~~~

This prompts for the game folder and creates a report without changing the game.
The Python equivalent is:

~~~powershell
py -3 .\bl4_sparse.py audit
~~~

### Restore

Close the game and launcher/updater, then run:

~~~powershell
.\bl4-sparse.ps1 -Mode Restore
~~~

Enter the backup directory or its restore.json file when prompted. The Python
equivalent also prompts:

~~~powershell
py -3 .\bl4_sparse.py restore
~~~

Keep the **entire** backup folder, including restore.json and all .ranges.bin
files. The backup can be moved to another drive: its range-file references are
relative to the manifest. The recorded game installation path must still be valid.

Recovery checks the index hashes, file lengths, retained bytes and backup hashes
before writing, then verifies restored bytes afterward. File contents return to
their pre-optimization state; the sparse attribute may remain set.

If interrupted, keep the backup folder and run Restore. All range backups are
completed and verified before any holes are made. If a game update has changed
indexes or retained bytes, restoration refuses to mix old ranges into that build.
Use the launcher's repair function or your original installation backup instead.

## Understanding the space report

- **Logical size** is the file length seen by the game and Explorer's Size.
- **Allocated size** is the storage currently occupied, shown as Size on disk.
- **Candidate bytes** include selected older blocks and short alignment padding.
- **Whole 64-KiB regions** provide an allocation estimate, not a guaranteed result.
- After applying, **Container allocation reclaimed** reports the measured change.

To check manually, right-click the game's Paks folder in Explorer, choose
**Properties**, and compare **Size** with **Size on disk**.

**A backup on the same drive can consume more space than the optimization frees.**
Keep it on another drive, or move the entire folder there afterward. Net drive
savings depend on the backup's location. Do not delete the backup until you are
comfortable losing the ability to restore those original bytes.

The tool leaves language packs alone. If you remove languages or change any
container files, generate a fresh audit before applying. Every game update also
requires a fresh audit; repair/update tools may restore the removed data.

## Scope and limitations

The tool considers a chunk superseded only when the **same complete chunk ID**
exists in a **higher numeric patch of the same pakchunk family**. This follows
the numeric-priority model used by the public retoc reader. It does not establish
all Borderlands 4 mounting rules, DLC conditions, or direct-container reads.

Only asset/bulk chunk types 1, 2 and 3 are eligible. A compression block is retained
if any retained chunk uses it. Physical overlaps with protected blocks are excluded.
Up to 15 bytes of interblock alignment padding may be included when the next
known block starts at that aligned boundary.

The tool preserves .pak and .utoc contents, the global container, headers,
scripts, shaders, memory-mapped bulk data and unknown/unreferenced blocks.
It does not prune legacy .pak payloads or automatically delete language packs.

Unknown/mod containers, Paks subdirectories, encryption, signatures, partitioned
containers, unusual headers and unsupported TOC versions are refused. Supported
layout checks do not establish runtime safety for every game build.

Sparse holes read back as zeros. This operation discards original payload bytes;
the separate backup provides recovery. Kept-byte hashing checks preservation of
everything outside the selected ranges. It is not a validation of the underlying
supersession assumption.

## Advanced command-line use

All path parameters can be supplied explicitly. These examples use placeholders,
not fixed installation locations:

~~~powershell
py -3 .\bl4_sparse.py audit "<game-directory>" --out "<new-plan.json>"
py -3 .\bl4_sparse.py apply "<plan.json>" --backup "<new-backup-folder>"
py -3 .\bl4_sparse.py restore "<backup-folder>"
~~~

The apply command prompts for confirmation. For a deliberately unattended run,
supply --accept-unverified-patch-order as an explicit acceptance of the runtime
assumption. Omitted apply paths are prompted for. Reports are not overwritten.

Do not reuse a stale plan after changing game files. The tool rebuilds and
compares the plan, then holds file locks on the existing containers while working.

## Development and tests

Run the standard-library test suite from the repository root:

~~~powershell
py -3 -m unittest discover -s tests -v
~~~

Tests create synthetic containers in temporary folders. They cover range
selection, shared/aliased block protection, alignment padding, rejected layouts,
edited plans, the prompted workflow, Windows file locks, sparse writes,
interruption recovery and byte-for-byte restoration. Windows integration tests
are skipped on other platforms. No installed game is modified by the tests.

## Publishing and privacy

This repository contains only source code, documentation, synthetic tests and
repository configuration. There are no bundled game files, personal installation
paths, precomputed plans, recovery manifests, or local scan reports.

Generated JSON plans/manifests contain local paths. Binary range backups contain
game data. The .gitignore excludes those files, reports/, common backup folders,
game containers, Python caches and local environments. Keep generated data out of
commits and issue attachments. When reporting a problem, share a redacted error
message and general layout details.

To publish your own copy, create an empty public repository on your Git hosting
service, then run from this project's folder:

~~~powershell
git init --initial-branch=main
git add .
git commit -m "Initial release"
git remote add origin <your-repository-url>
git push -u origin main
~~~

The prepared local folder uses branch main. The source ZIP excludes .git, so
the initialization command also works after extracting the ZIP. No remote,
personal author identity, commit, or hosted repository is supplied by this project.

## References

- [Microsoft: sparse file operations](https://learn.microsoft.com/en-us/windows/win32/fileio/sparse-file-operations)
- [Microsoft: FSCTL_SET_ZERO_DATA](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_zero_data)
- [CUE4Parse: IoStore header layout](https://github.com/FabianFG/CUE4Parse/blob/master/CUE4Parse/UE4/IO/Objects/FIoStoreTocHeader.cs)
- [CUE4Parse: chunk offsets and lengths](https://github.com/FabianFG/CUE4Parse/blob/master/CUE4Parse/UE4/IO/Objects/FIoOffsetAndLength.cs)
- [CUE4Parse: compression-block layout](https://github.com/FabianFG/CUE4Parse/blob/master/CUE4Parse/UE4/IO/Objects/FIoStoreTocCompressedBlockEntry.cs)
- [retoc: container priority and lookup](https://github.com/trumank/retoc/blob/master/retoc/src/iostore.rs)

## License

MIT; see [LICENSE](LICENSE). This is an independent community tool, unaffiliated
with Gearbox, 2K or Epic Games. No game assets or engine source are distributed.
