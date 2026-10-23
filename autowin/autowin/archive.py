"""Export / import an engagement as a single .zip.

Export bundles the loot store (the SQLite DB plus the users/hashes/bloodhound
loot files) so a teammate can import it and land at the exact same progress --
same hosts, creds, hashes, vulns, policy, default target, and crucially the
`completed` resume markers, so they don't re-run steps you already did.

Local-only noise (logs, Kerberos ccaches) is left out of the bundle.
"""
import os
import pathlib
import shutil
import tempfile
import zipfile

from .console import info, good, warn, err

EXCLUDE_DIRS = {'logs', 'tickets'}


def export_loot(store, out_path: str, include_logs: bool = False) -> None:
    base = pathlib.Path(store.dir)
    exclude = {'tickets'} if include_logs else EXCLUDE_DIRS
    count = 0
    with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in exclude]
            for name in files:
                full = pathlib.Path(root) / name
                z.write(full, full.relative_to(base))
                count += 1
    good(f'export: wrote {count} file(s) to {out_path}')


def _safe_members(z: zipfile.ZipFile) -> bool:
    """Reject archives with absolute paths or traversal (zip-slip)."""
    for name in z.namelist():
        p = pathlib.PurePosixPath(name)
        if p.is_absolute() or '..' in p.parts:
            return False
    return True


def _copy_missing(src_dir: pathlib.Path, dst_dir: pathlib.Path) -> int:
    if not src_dir.is_dir():
        return 0
    dst_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for item in src_dir.iterdir():
        if item.is_file() and not (dst_dir / item.name).exists():
            shutil.copy2(item, dst_dir / item.name)
            n += 1
    return n


def import_loot(store, zip_path: str) -> None:
    if not os.path.isfile(zip_path):
        err(f'import: file not found: {zip_path}')
        return
    tmp = tempfile.mkdtemp(prefix='autowin-import-')
    try:
        with zipfile.ZipFile(zip_path) as z:
            if not _safe_members(z):
                err('import: refusing unsafe archive (absolute paths / traversal)')
                return
            z.extractall(tmp)

        src_db = os.path.join(tmp, 'autowin.sqlite')
        if not os.path.isfile(src_db):
            err('import: archive has no autowin.sqlite; not an autowin export')
            return

        added = store.merge_db(src_db)
        bh = _copy_missing(pathlib.Path(tmp) / 'bloodhound', store.bloodhound_dir)
        store.rebuild_loot_files()   # keep users.txt / hashes/ in step with the merged DB
        good(f'import: merged {added} new row(s); copied {bh} bloodhound file(s)')
        info('you are now caught up to the exported progress (completed steps will be skipped)')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
