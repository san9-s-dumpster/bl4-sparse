#!/usr/bin/env python3
"""BL4 sparse patch experiment. Python 3.10+, no third-party packages.
Audit is read-only. Apply requires a backup and acknowledgement of unverified
runtime patch precedence. Only .ucas files change; .pak/.utoc remain intact.
"""
import argparse
import contextlib
import ctypes
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys

MAGIC = b"-==--==--==--==-"
NAME = re.compile(r"^(pakchunk\d+-Windows)_(\d+)_P\.utoc$", re.I)
BUFFER = 8 * 1024 * 1024

def require(ok, message):
    if not ok:
        raise ValueError(message)

def merge(ranges):
    out = []
    for a, b in sorted(ranges):
        if a == b:
            continue
        require(0 <= a < b, "Invalid interval")
        if out and a <= out[-1][1]:
            out[-1][1] = max(b, out[-1][1])
        else:
            out.append([a, b])
    return out

def subtract(ranges, protected):
    protected = merge(protected)
    out, j = [], 0
    for a, b in merge(ranges):
        while j < len(protected) and protected[j][1] <= a:
            j += 1
        k, cursor = j, a
        while k < len(protected) and protected[k][0] < b:
            c, d = protected[k]
            if c > cursor:
                out.append([cursor, min(c, b)])
            cursor = max(cursor, d)
            k += 1
        if cursor < b:
            out.append([cursor, b])
    return out

def kept(size, holes):
    return subtract([[0, size]], holes)

def total(ranges):
    return sum(b-a for a,b in ranges)

def gib(n):
    return f"{n/2**30:,.2f} GiB"

def save_json(path, value):
    path = Path(path)
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8") as f:
        json.dump(value, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)

class Windows:
    def __init__(self):
        require(os.name == "nt", "Apply and restore require Windows and NTFS")
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k.CreateFileW.argtypes = [W.LPCWSTR,W.DWORD,W.DWORD,ctypes.c_void_p,W.DWORD,W.DWORD,W.HANDLE]
        self.k.CreateFileW.restype = W.HANDLE
        self.k.CloseHandle.argtypes = [W.HANDLE]
        self.k.DeviceIoControl.argtypes = [W.HANDLE,W.DWORD,ctypes.c_void_p,W.DWORD,
            ctypes.c_void_p,W.DWORD,ctypes.POINTER(W.DWORD),ctypes.c_void_p]
        self.k.DeviceIoControl.restype = W.BOOL
        self.k.GetCompressedFileSizeW.argtypes = [W.LPCWSTR,ctypes.POINTER(W.DWORD)]
        self.k.GetCompressedFileSizeW.restype = W.DWORD
        self.k.GetVolumePathNameW.argtypes = [W.LPCWSTR,W.LPWSTR,W.DWORD]
        self.k.GetVolumeInformationW.argtypes = [W.LPCWSTR,W.LPWSTR,W.DWORD,
            ctypes.POINTER(W.DWORD),ctypes.POINTER(W.DWORD),ctypes.POINTER(W.DWORD),W.LPWSTR,W.DWORD]

    def open(self, path, write=False):
        import msvcrt
        # Targets exclusive; all dependencies deny writes and deletion.
        handle = self.k.CreateFileW(str(path), 0x80000000 | (0x40000000 if write else 0),
                                   0 if write else 1, None, 3, 0x80, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_BINARY | (os.O_RDWR if write else os.O_RDONLY))
        except BaseException:
            self.k.CloseHandle(handle)
            raise
        return os.fdopen(fd, "r+b" if write else "rb", buffering=0)

    def ioctl(self, f, code, payload=b""):
        import msvcrt
        count = W.DWORD()
        data = ctypes.create_string_buffer(payload) if payload else None
        if not self.k.DeviceIoControl(msvcrt.get_osfhandle(f.fileno()),code,data,len(payload),
                                      None,0,ctypes.byref(count),None):
            raise ctypes.WinError(ctypes.get_last_error())

    def punch(self, f, ranges):
        self.ioctl(f, 0x900C4)  # FSCTL_SET_SPARSE
        for a,b in ranges:
            self.ioctl(f, 0x980C8, struct.pack("<qq",a,b))  # FSCTL_SET_ZERO_DATA
        os.fsync(f.fileno())

    def allocated(self, path):
        high = W.DWORD()
        ctypes.set_last_error(0)
        low = self.k.GetCompressedFileSizeW(str(path),ctypes.byref(high))
        if low == 0xffffffff and ctypes.get_last_error():
            raise ctypes.WinError(ctypes.get_last_error())
        return (high.value << 32) | low

    def ntfs(self, path):
        volume, fs = ctypes.create_unicode_buffer(32768), ctypes.create_unicode_buffer(256)
        flags = W.DWORD()
        if not self.k.GetVolumePathNameW(str(path),volume,len(volume)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not self.k.GetVolumeInformationW(volume.value,None,0,None,None,ctypes.byref(flags),fs,len(fs)):
            raise ctypes.WinError(ctypes.get_last_error())
        require(fs.value.upper()=="NTFS" and flags.value & 0x40, f"NTFS sparse support required; got {fs.value}")

def parse_toc(path):
    """Strict standard UE5 IoStore v8 reader. No AES key or decompressor needed."""
    data = path.read_bytes()
    require(len(data)>=144 and data[:16]==MAGIC, f"{path.name}: invalid TOC")
    u32 = lambda p: struct.unpack_from("<I",data,p)[0]
    require(data[16]==8 and u32(20)==144, f"{path.name}: only standard TOC v8 supported")
    count, nb, es = u32(24),u32(28),u32(32)
    nm, ml, bs = u32(36),u32(40),u32(44)
    require(data[80] & ~9 == 0, f"{path.name}: encrypted/signed/on-demand/unknown flags refused")
    require(u32(52)==1, f"{path.name}: partitioned containers unsupported")
    require(es==12 and bs>0, f"{path.name}: invalid block layout")
    require(not any(data[104:144]), f"{path.name}: custom header extension refused")
    bt = 144 + count*22 + (u32(84)+u32(96))*4
    meta = bt + nb*12 + nm*ml + u32(48)
    require(meta+count*24==len(data), f"{path.name}: TOC layout/length mismatch")
    ids = [data[144+i*12:156+i*12] for i in range(count)]
    require(len(set(ids))==count, f"{path.name}: duplicate IDs inside container")
    cas = path.with_suffix(".ucas")
    require(cas.is_file(), f"Missing {cas.name}")
    size = cas.stat().st_size
    blocks, unpacked_sizes = [], []
    for i in range(nb):
        p = bt+i*12
        a = int.from_bytes(data[p:p+5],"little")
        compressed = int.from_bytes(data[p+5:p+8],"little")
        unpacked = int.from_bytes(data[p+8:p+11],"little")
        method = data[p+11]
        require(0<unpacked<=bs and compressed>0 and method<=nm, f"{path.name}: invalid block {i}")
        require(a+compressed<=size, f"{path.name}: block outside .ucas")
        require(method!=0 or compressed==unpacked, f"{path.name}: inconsistent uncompressed block")
        blocks.append([a,a+compressed])
        unpacked_sizes.append(unpacked)
    chunks = []
    for i,cid in enumerate(ids):
        p = 144+count*12+i*10
        a = int.from_bytes(data[p:p+5],"big")
        length = int.from_bytes(data[p+5:p+10],"big")
        first,end = a//bs,(a+length+bs-1)//bs
        if length:
            require(first<end<=nb, f"{path.name}: chunk outside block table")
            for b in range(first,end):
                require(min(a+length,(b+1)*bs)<=b*bs+unpacked_sizes[b],
                        f"{path.name}: chunk beyond decoded block")
        else:
            first=end=0
        chunks.append((cid,first,end))
    match = NAME.fullmatch(path.name)
    return dict(path=path,cas=cas,sha256=hashlib.sha256(data).hexdigest(),
                blocks=blocks,chunks=chunks,family=match[1].lower() if match else None,
                patch=int(match[2]) if match else -1)

def snapshot(path):
    s = path.stat()
    require(not(getattr(s,"st_file_attributes",0)&(0x400|0x4000)), f"Reparse/EFS file refused: {path}")
    return dict(size=s.st_size,mtime_ns=s.st_mtime_ns)

def paks_dir(value):
    p = Path(value).resolve(strict=True)
    nested = p/"OakGame"/"Content"/"Paks"
    if nested.is_dir():
        p=nested
    require(p.is_dir() and any(p.glob("*.utoc")), "No .utoc indexes in that folder")
    return p

def audit(root):
    root = paks_dir(root)
    files = sorted(p for p in root.iterdir() if p.suffix.lower() in (".utoc",".ucas",".pak",".sig"))
    require(all(p.is_file() for p in files), "Unexpected non-file container")
    snapshots = {p.name:snapshot(p) for p in files}
    tocs = [parse_toc(p) for p in files if p.suffix.lower()==".utoc"]
    require(all(t["family"] or t["path"].name.lower()=="global.utoc" for t in tocs),
            "Unknown/mod container present; cannot infer priority")
    require(not any(p.is_dir() for p in root.iterdir()), "Paks subdirectories/mods unsupported")
    require(not any(p.suffix.lower()==".sig" for p in files), "Signed pak layout refused")
    require({t["cas"].name for t in tocs}=={p.name for p in files if p.suffix.lower()==".ucas"},
            "Orphan/partitioned .ucas files refused")
    latest={}
    for t in tocs:
        if t["family"]:
            for cid,_,_ in t["chunks"]:
                key=(t["family"],cid)
                latest[key]=max(latest.get(key,-1),t["patch"])
    targets,by_family=[],{}
    for t in tocs:
        touched,live=bytearray(len(t["blocks"])),bytearray(len(t["blocks"]))
        dead_chunks=0
        for cid,first,end in t["chunks"]:
            # Asset/bulk types only; preserve headers, scripts, shaders,
            # memory-mapped bulk data, and all unknown types.
            dead=(t["family"] is not None and cid[11] in (1,2,3)
                  and latest[(t["family"],cid)]>t["patch"])
            dead_chunks+=int(dead)
            for i in range(first,end):
                touched[i]=1
                if not dead:
                    live[i]=1
        # Include only short alignment padding ending exactly at another known
        # physical block. No indexed bytes are added; protected aliases below win.
        starts={r[0] for r in t["blocks"]}
        candidates=[]
        for i,(a,b) in enumerate(t["blocks"]):
            if touched[i] and not live[i]:
                aligned=(b+15)//16*16
                candidates.append([a,aligned if aligned in starts else b])
        protected=[r for i,r in enumerate(t["blocks"]) if not touched[i] or live[i]]
        ranges=subtract(candidates,protected)
        if ranges:
            targets.append(dict(file=t["cas"].name,ranges=ranges,bytes=total(ranges),superseded_chunks=dead_chunks))
            fam=t["family"]
            by_family[fam]=by_family.get(fam,0)+total(ranges)
    require(snapshots=={p.name:snapshot(p) for p in files}, "Files changed during audit")
    lang=sum(v["size"] for n,v in snapshots.items() if re.match(r"pakchunk1[0-6]-",n,re.I))
    return dict(schema=1,root=str(root),files=snapshots,
        toc_hashes={t["path"].name:t["sha256"] for t in tocs},targets=targets,
        candidate_bytes=sum(x["bytes"] for x in targets),by_family=by_family,
        whole_64k_candidate_bytes=sum(max(0,(b//65536-(a+65535)//65536)*65536)
            for t in targets for a,b in t["ranges"]),
        logical_bytes=sum(s["size"] for s in snapshots.values()),language_10_to_16_logical_bytes=lang,
        assumption="Higher numeric _N_P overrides the same chunk ID within its pakchunk family. Runtime unverified.")

def hash_ranges(f,ranges,output=None):
    h=hashlib.sha256()
    for a,b in ranges:
        f.seek(a)
        h.update(struct.pack("<QQ",a,b))
        left=b-a
        while left:
            data=f.read(min(left,BUFFER))
            require(data,"Unexpected EOF")
            h.update(data)
            if output is not None:
                require(output.write(data)==len(data),"Short backup write")
            left-=len(data)
    return h.hexdigest()

def stream_hash(f):
    f.seek(0)
    h=hashlib.sha256()
    while data:=f.read(BUFFER):
        h.update(data)
    return h.hexdigest()

def backup_hash(f,ranges):
    f.seek(0)
    h=hashlib.sha256()
    for a,b in ranges:
        h.update(struct.pack("<QQ",a,b))
        left=b-a
        while left:
            data=f.read(min(left,BUFFER))
            require(data,"Truncated range backup")
            h.update(data)
            left-=len(data)
    require(not f.read(1),"Unexpected trailing backup bytes")
    return h.hexdigest()

def locked_files(api,plan,stack):
    targets={x["file"] for x in plan["targets"]}
    handles={}
    root=Path(plan["root"])
    current={p.name for p in root.iterdir() if p.suffix.lower() in (".utoc",".ucas",".pak",".sig")}
    require(current==set(plan["files"]),"Container inventory changed; run audit again")
    for name,info in plan["files"].items():
        f=stack.enter_context(api.open(root/name,name in targets))
        s=os.fstat(f.fileno())
        require(s.st_size==info["size"] and s.st_mtime_ns==info["mtime_ns"],f"{name} changed; run audit again")
        if name in plan["toc_hashes"]:
            require(stream_hash(f)==plan["toc_hashes"][name],f"{name} index changed")
        handles[name]=f
    return handles

def child(folder,name):
    require(Path(name).name==name and name not in ("",".","..") and ":" not in name,"Invalid backup filename")
    p=folder/name
    require(not p.is_symlink(),"Backup/target symlink refused")
    return p

def apply(plan_file,backup_dir,acknowledge):
    require(acknowledge,"Apply requires --accept-unverified-patch-order; read README first")
    old=json.loads(Path(plan_file).read_text(encoding="utf-8"))
    require(old.get("schema")==1,"Unsupported plan")
    print("Rebuilding plan from game indexes, ignoring supplied byte ranges...",flush=True)
    plan=audit(old["root"])
    require(plan==old,"Plan is stale or edited; run audit again")
    require(plan["targets"],"No candidate blocks")
    api=Windows()
    root=Path(plan["root"])
    api.ntfs(root)
    backup=Path(backup_dir).resolve()
    require(not backup.exists(),"Use a NEW backup directory; existing backups are never overwritten")
    require(backup!=root and root not in backup.parents,"Backup must be outside Paks")
    require(backup.parent.is_dir(),"Backup parent folder must already exist")
    require(shutil.disk_usage(backup.parent).free>plan["candidate_bytes"]+128*1024**2,"Insufficient backup space")
    if backup.anchor.lower()==root.anchor.lower():
        print("Backup is on the game drive: total drive use can INCREASE until you move the backup.",flush=True)
    backup.mkdir()
    journal=dict(schema=1,root=str(root),toc_hashes=plan["toc_hashes"],entries=[],state="preparing",
                 assumption=plan["assumption"])
    manifest=backup/"restore.json"
    save_json(manifest,journal)
    before=sum(api.allocated(root/name) for name in plan["files"])
    with contextlib.ExitStack() as stack:
        handles=locked_files(api,plan,stack)
        # All removed bytes are flushed, reread and journaled before ANY holes.
        for number,target in enumerate(plan["targets"]):
            name,ranges=target["file"],target["ranges"]
            f=handles[name]
            size=plan["files"][name]["size"]
            print(f"Backing up {number+1}/{len(plan['targets'])}: {name} ({gib(target['bytes'])})",flush=True)
            preserved=hash_ranges(f,kept(size,ranges))
            bin_name=f"{number:04d}.ranges.bin"
            with (backup/bin_name).open("xb") as out:
                removed=hash_ranges(f,ranges,out)
                out.flush()
                os.fsync(out.fileno())
            with (backup/bin_name).open("rb") as check:
                require(backup_hash(check,ranges)==removed,"Backup verification failed")
            journal["entries"].append(dict(file=name,size=size,ranges=ranges,backup=bin_name,
                removed_sha256=removed,kept_sha256=preserved,state="backed-up"))
            save_json(manifest,journal)
        journal["state"]="backups-complete"
        save_json(manifest,journal)
        for e in journal["entries"]:
            f=handles[e["file"]]
            e["state"]="punching"  # Persist intent before the first ioctl.
            save_json(manifest,journal)
            print(f"Making sparse holes: {e['file']}",flush=True)
            api.punch(f,e["ranges"])
            require(os.fstat(f.fileno()).st_size==e["size"],"File length changed")
            require(hash_ranges(f,kept(e["size"],e["ranges"]))==e["kept_sha256"],
                    "KEPT BYTES CHANGED: stop and recover from backup")
            e["state"]="verified"
            save_json(manifest,journal)
        journal["state"]="complete"
        save_json(manifest,journal)
    after=sum(api.allocated(root/name) for name in plan["files"])
    print(f"Container allocation reclaimed: {gib(before-after)}")
    print(f"Recovery manifest: {manifest}")
    print("Kept bytes verified. Runtime correctness still unverified. Keep your backup.")

def restore(manifest):
    manifest=Path(manifest).resolve(strict=True)
    journal=json.loads(manifest.read_text(encoding="utf-8"))
    require(journal.get("schema")==1,"Unsupported recovery manifest")
    root=paks_dir(journal["root"])
    api=Windows()
    with contextlib.ExitStack() as stack:
        # Preflight and lock all indexes, affected containers and backups before writes.
        for name,digest in journal["toc_hashes"].items():
            f=stack.enter_context(api.open(child(root,name)))
            require(stream_hash(f)==digest,"Game indexes changed; refusing restore")
        targets,backups={},{}
        for e in journal["entries"]:
            require(e["file"] not in targets and e["file"].lower().endswith(".ucas"),"Invalid recovery target")
            require(e["ranges"] and e["ranges"]==merge(e["ranges"]) and e["ranges"][-1][1]<=e["size"],
                    "Invalid recovery ranges")
            f=stack.enter_context(api.open(child(root,e["file"]),True))
            require(os.fstat(f.fileno()).st_size==e["size"],"Container size changed; refusing restore")
            require(hash_ranges(f,kept(e["size"],e["ranges"]))==e["kept_sha256"],
                    "Kept bytes changed; refusing restore")
            source=stack.enter_context(api.open(child(manifest.parent,e["backup"])))
            require(backup_hash(source,e["ranges"])==e["removed_sha256"],"Backup hash mismatch")
            source.seek(0)
            targets[e["file"]],backups[e["file"]]=f,source
        for e in journal["entries"]:
            print(f"Restoring {e['file']}",flush=True)
            f,source=targets[e["file"]],backups[e["file"]]
            for a,b in e["ranges"]:
                f.seek(a)
                left=b-a
                while left:
                    data=source.read(min(BUFFER,left))
                    require(data,"Truncated backup")
                    require(f.write(data)==len(data),"Short restore write")
                    left-=len(data)
            os.fsync(f.fileno())
            require(hash_ranges(f,e["ranges"])==e["removed_sha256"],"Restored bytes hash mismatch")
            require(hash_ranges(f,kept(e["size"],e["ranges"]))==e["kept_sha256"],
                    "Kept bytes hash mismatch after restore")
            e["state"]="restored"
            save_json(manifest,journal)
    journal["state"]="restored"
    save_json(manifest,journal)
    print("Original file bytes restored. Sparse attribute may remain; original contents are recovered.")

def clean_path(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    require(value, "A path is required")
    return Path(os.path.expandvars(value)).expanduser().resolve()


def prompt_path(label, kind, optional=False):
    while True:
        value = input(label + ": ").strip()
        if not value and optional:
            return None
        try:
            path = clean_path(value)
            if kind == "game":
                return paks_dir(path)
            if kind == "backup":
                require(not path.exists(), "Choose a NEW folder; existing backups are never overwritten")
                require(path.parent.is_dir(), "The backup folder's parent must already exist")
                return path
            if kind == "manifest":
                if path.is_dir():
                    path = path / "restore.json"
                require(path.is_file(), "Recovery manifest not found")
            elif kind == "plan":
                require(path.is_file(), "Plan file not found")
            return path
        except (OSError, ValueError) as error:
            print(f"Invalid path: {error}", flush=True)


def confirm_apply():
    print("\nExperimental: numeric patch priority has not been verified against every")
    print("Borderlands 4 runtime read. Kept-byte hashes do not prove removed data is unused.")
    print("Close the game and launcher/updater. Keep the complete backup for recovery.")
    return input("Type APPLY to back up and modify the game, or Enter to cancel: ").strip() == "APPLY"


def run_audit(game, out=None):
    from datetime import datetime
    from uuid import uuid4
    print("Scanning container indexes (read-only)...", flush=True)
    plan = audit(game)
    if out is None:
        reports = Path(__file__).resolve().parent / "reports"
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out = reports / f"bl4-plan-{stamp}-{uuid4().hex[:8]}.json"
    out = Path(out).resolve()
    root = Path(plan["root"])
    require(root not in out.parents and out != root, "Save report outside Paks")
    require(not out.exists(), "Report exists; choose a new --out filename")
    out.parent.mkdir(parents=True, exist_ok=True)
    save_json(out, plan)
    print(f"Container logical size: {gib(plan['logical_bytes'])}")
    print(f"Candidate superseded blocks/padding: {gib(plan['candidate_bytes'])}")
    print(f"Whole 64-KiB regions within candidates: {gib(plan['whole_64k_candidate_bytes'])}; estimate only")
    for family, amount in sorted(plan["by_family"].items()):
        print(f"  {family}: {gib(amount)}")
    if plan["language_10_to_16_logical_bytes"]:
        print(f"pakchunk10..16 files present: {gib(plan['language_10_to_16_logical_bytes'])} logical; untouched")
    if os.name == "nt":
        api = Windows()
        print(f"Current allocated container size: {gib(sum(api.allocated(root / n) for n in plan['files']))}")
    print(f"Plan: {out}\nRead-only audit complete. No game files changed.")
    print("Assumption: " + plan["assumption"])
    return plan, out


def interactive():
    require(os.name == "nt", "The interactive optimizer requires Windows and NTFS")
    print("BL4 Sparse - experimental IoStore patch optimizer")
    print("A read-only scan runs first. Press Ctrl+C at a prompt to exit.\n")
    game = prompt_path("Game directory (or OakGame\\Content\\Paks folder)", "game")
    plan, report = run_audit(game)
    if not plan["targets"]:
        print("No candidate data found. Nothing to apply.")
        return
    print(f"\nBackup data needs approximately {gib(plan['candidate_bytes'])}, plus a small reserve.")
    print("Choose another drive to free space on the game drive.")
    print("Using the same drive can consume MORE space until the backup is moved.")
    backup = prompt_path("NEW backup folder (Enter to finish after the read-only scan)", "backup", optional=True)
    if backup is None:
        print("Finished after audit. No game files changed.")
        return
    if not confirm_apply():
        print("Cancelled. No game files changed.")
        return
    apply(report, backup, True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    a = sub.add_parser("audit", help="Read-only index analysis; prompts for an omitted game path")
    a.add_argument("game", nargs="?", help="Game root or Paks folder")
    a.add_argument("--out", help="New JSON report path; defaults to a unique file in reports/")
    a = sub.add_parser("apply", help="Apply a saved plan with a mandatory recovery backup")
    a.add_argument("plan", nargs="?", help="JSON plan; prompts when omitted")
    a.add_argument("--backup", help="NEW directory; prompts when omitted")
    a.add_argument("--accept-unverified-patch-order", action="store_true",
                   help="Explicitly accept the runtime assumption without an interactive confirmation")
    a = sub.add_parser("restore", help="Restore original bytes from a backup; prompts when omitted")
    a.add_argument("manifest", nargs="?", help="Backup folder or restore.json")
    args = parser.parse_args(argv)
    if args.command is None:
        interactive()
    elif args.command == "audit":
        game = clean_path(args.game) if args.game else prompt_path("Game directory (or Paks folder)", "game")
        run_audit(game, clean_path(args.out) if args.out else None)
    elif args.command == "apply":
        plan = clean_path(args.plan) if args.plan else prompt_path("Saved JSON plan", "plan")
        backup = clean_path(args.backup) if args.backup else prompt_path("NEW backup folder", "backup")
        if args.accept_unverified_patch_order or confirm_apply():
            apply(plan, backup, True)
        else:
            print("Cancelled. No game files changed.")
    else:
        manifest = clean_path(args.manifest) if args.manifest else prompt_path("Backup folder or restore.json", "manifest")
        if manifest.is_dir():
            manifest = manifest / "restore.json"
        restore(manifest)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled. If sparse writes had started, keep the backup and use restore.json for recovery.",
              file=sys.stderr)
        sys.exit(130)
    except EOFError:
        print("STOPPED: input ended. Supply paths as arguments for noninteractive use.", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, struct.error) as error:
        print(f"STOPPED: {error}", file=sys.stderr)
        print("If apply started, preserve the backup folder and its restore.json.", file=sys.stderr)
        sys.exit(1)
