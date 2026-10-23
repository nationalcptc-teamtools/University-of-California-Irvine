# Typst Local

A self-hosted, real-time collaborative [Typst](https://typst.app) editor. Run it on one machine and everyone on your network can open the link in a browser and edit together, with a live preview.

## Features

- **Real-time collaboration**: Yjs CRDT sync, with each person's cursor and selection shown under their name, and avatars showing who is in which file.
- **Live preview**: the server recompiles on every change and pushes only the changed pages to everyone. Browsers only draw the pages near what you're looking at, so long documents stay fast.
- **Diagnostics**: compiler errors and warnings appear inline in the editor, in a problems panel (click one to jump to it), and as red marks on files in the file tree.
- **Multi-file projects**: multiple `.typ` files, a selectable main file, and image, font, bib or data uploads.
- **Folders**: create folders (including empty ones), drag files and folders to move them, and upload whole folders from your computer by dragging them onto the file panel or with Upload → Upload folder.
- **Editor**: CodeMirror 6 with Typst syntax highlighting, autocompletion, folding, search, and collaborative undo/redo.
- **Version history**: automatic snapshots while you work, plus named versions. You can compare any version with the current project, preview or download its PDF, and restore it (see below).
- **Export**: PDF, Word (`.docx`), and the project source as a `.zip`. The Word file is a real Word document (headings, lists, tables, a live table of contents) styled after the PDF for any template: fonts, sizes, colours, cell shading, page size, margins and running header/footer are measured from the compiled document, and the fonts are embedded.
- **Typst Universe packages**: `#import "@preview/..."` works. Packages are downloaded on first use, so this needs internet access.
- **Optional shared password** for the whole server.
- Light and dark themes (follows your OS setting).

## Quick start

```sh
git clone <your repo url> typst-local
cd typst-local
./setup.sh        # add -y to skip the questions
./start.sh
```

`setup.sh` works on macOS and on Kali, Debian and Ubuntu, including fresh installs:

- If Node.js 22+ isn't installed, it downloads it into `.node/` inside the project.
- It installs the npm dependencies and builds the web client.
- It builds the fast compile engine. If Rust 1.89+ is missing, it installs a private copy into `.rust/`. On Linux it apt-installs `build-essential`, `pkg-config` and `libssl-dev` if they're missing; this needs sudo.
- It writes `.env` with the port and a random access password, and prints the addresses to share.

Nothing outside the project folder changes, apart from those apt packages. The script asks before each download or install unless you pass `-y`. It's safe to re-run, for example after `git pull`.

Other options:

```sh
./setup.sh --docker              # build and run it as a Docker container instead
./setup.sh --service             # Linux: install a systemd service that starts on boot
./setup.sh --port 8080 --password secret   # or --no-password
./setup.sh --no-engine           # skip the Rust build (slower previews)
```

## Configuration

Settings live in `.env`, which `setup.sh` writes. Environment variables override it.

| Variable           | Default   | Meaning                                                    |
| ------------------ | --------- | ---------------------------------------------------------- |
| `TYPST_LOCAL_PORT` | `3000`    | HTTP port (`PORT` also works)                              |
| `ACCESS_PASSWORD`  | _(none)_  | If set, everyone must enter this password once per browser |
| `LISTEN_HOST`      | `0.0.0.0` | Interface to bind (`127.0.0.1` keeps it local-only)        |
| `DATA_DIR`         | `./data`  | Where projects are stored                                  |

## Fonts

Like typst.app, any `.ttf`/`.otf` file anywhere in a project is available to that project. Fonts in `data/fonts/` are available to every project, like typst.app's built-in font list. Project fonts take precedence.

Fonts added to `data/fonts/` are picked up when the server restarts. Use the font's own family name, which isn't always the file name. For example, Inter's variable edition is called "Inter Variable". If a name isn't found, the warning lists the names that the available font files provide. Typst doesn't support variable fonts well, so prefer static font files.

## Version history

Open the **History** tab in the left panel. It works like a git log, and every version is a real git commit.

- **Automatic versions** are taken about 5 minutes after editing starts, and again when the last person leaves a project. Each one records who edited since the previous version.
- **Commit…** records the project right away, with your message. The top row shows uncommitted changes since the last commit.
- **Tag…** puts a git tag, like `v1.0`, on any commit.
- **Opening a commit** shows that commit's own changes against its parent, or its differences from the project now ("vs. now"), with `+/−` line counts.
- All versions are kept forever.
- **Clone:** each project's history is mirrored into a git repository (`data/projects/<id>/history.git`). Clone it read-only with `git clone http://<server>/git/<project-id>.git`. If a password is set, use any username and the access password. Commits keep their original times and authors.
- **Viewing a version:** click it to see which files changed since then. Each file shows its changes against the current text, and the preview pane shows that version rendered.
- **Restore** changes the project back for everyone, as a normal live edit. The state just before the restore is saved first as a version, so a restore can always be reversed.

## Data and backups

```
data/
  fonts/                  drop .ttf/.otf files here to make them available to every project
  projects/<id>/
    meta.json             name and timestamps
    doc.ystate            collaborative document state (source of truth)
    blobs/                uploaded binary files (content-addressed)
    files/                plain-file copy of the project, refreshed a few seconds after edits
    history/              version history (index.json + gzipped snapshots)
```

To back up, copy the `data/` directory. Fonts uploaded into a project (`.ttf`, `.otf`) are picked up by that project automatically.

## Development

```sh
npm run dev     # rebuilds the client on change and restarts the server on change
```

- `server/index.js`: HTTP API, auth, WebSocket upgrade
- `server/rooms.js`: per-project Yjs document, sync and awareness protocol, autosave, and compile scheduling
- `engine/`: native incremental compile engine (JSON lines over stdin/stdout), used when `bin/typst-engine` exists
- `server/compiler.js`: talks to the engine, or to `server/compile-worker.js` (typst-ts) as a fallback
- `client/editor.js`: editor UI; `client/lib/preview.js`: page rendering

## Security notes

There are no user accounts. Anyone who can reach the server (and knows the password, if one is set) can view, edit and delete every project. Run it on a trusted network. To expose it beyond your LAN, put it behind a reverse proxy with HTTPS. WebSockets work through any proxy that forwards `Upgrade` headers.
