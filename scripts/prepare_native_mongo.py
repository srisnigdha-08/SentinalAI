"""Prepare only the owner's explicitly approved portable MongoDB location."""
from pathlib import Path
import hashlib
import json
import stat
import urllib.request
import zipfile

ROOT = Path(r"C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-acceptance-20261014")
URL = "https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-7.0.45.zip"
EXPECTED = "7e3a435fa86e36e8ca4f2618fb41de06d75c28009c63725a20f9badd36eec6f6"


def main():
    for path in (ROOT, *ROOT.parents):
        if path.exists() and path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise RuntimeError("Approved path has a reparse point; stop for review")
    if ROOT.exists():
        raise RuntimeError("Approved setup directory already exists; refusing to reuse it")
    with urllib.request.urlopen(URL + ".sha256", timeout=30) as response:
        published = response.read(1024).decode().split()[0].lower()
    if published != EXPECTED:
        raise RuntimeError("Published checksum differs from reviewed checksum")
    ROOT.mkdir(parents=True, exist_ok=False)
    archive = ROOT / "mongodb-windows-x86_64-7.0.45.zip"
    digest = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(URL, timeout=60) as response, archive.open("xb") as destination:
        while block := response.read(1024 * 1024):
            destination.write(block)
            digest.update(block)
            total += len(block)
    if digest.hexdigest() != published:
        raise RuntimeError("Downloaded checksum mismatch; no extraction or database start permitted")
    print("Official archive SHA-256 verified", flush=True)
    binaries = ROOT / "binaries"
    binaries.mkdir()
    # Extract only mongod plus DLL/license files. No server/data/service installer.
    with zipfile.ZipFile(archive) as source:
        selected = [item for item in source.infolist() if not item.is_dir() and (
            Path(item.filename).name.lower() == "mongod.exe"
            or item.filename.lower().endswith(".dll")
            or Path(item.filename).name.lower() in {"license-community.txt", "mpl-2", "third-party-notices"}
        )]
        if not any(Path(item.filename).name.lower() == "mongod.exe" for item in selected):
            raise RuntimeError("Official archive has no mongod.exe")
        for item in selected:
            destination = binaries / Path(item.filename).name
            with source.open(item) as incoming, destination.open("xb") as outgoing:
                while block := incoming.read(1024 * 1024):
                    outgoing.write(block)
    for name in ("data", "logs", "evidence"):
        (ROOT / name).mkdir()
    report = {"version": "7.0.45", "url": URL, "sha256": published, "download_bytes": total,
              "root": str(ROOT), "data_path": str(ROOT / "data"), "binary": str(binaries / "mongod.exe")}
    (ROOT / "evidence" / "download-verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
