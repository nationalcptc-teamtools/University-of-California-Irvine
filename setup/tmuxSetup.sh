#!/usr/bin/env bash
#
# TMUX SETUP - tpm, automatic pane logging, vi copy-mode and a working clipboard.
#
#   ./tmuxSetup.sh                    configure the user running it
#   sudo ./tmuxSetup.sh               configure the invoking user, not root
#   sudo ./tmuxSetup.sh --user alice  configure someone specific
#   ./tmuxSetup.sh --no-auto-log      do not log every pane automatically
#
# Running it twice is safe: the config is backed up before it is replaced, and tpm is
# updated in place rather than re-cloned.
set -euo pipefail

AUTO_LOG=1
TARGET_USER=""

die() {
  printf '\033[91m[!] %s\033[0m\n' "$*" >&2
  exit 1
}
warn() { printf '\033[93m[~] %s\033[0m\n' "$*"; }
step() { printf '\033[96m[*] %s\033[0m\n' "$*"; }
ok() { printf '\033[92m[+] %s\033[0m\n' "$*"; }

# wait_for <condition> [seconds] - poll until it holds, rather than sleeping blind and
# hoping. Returns the moment the condition is true, gives up after the timeout so a
# real failure is still a failure instead of a hang.
wait_for() {
  local tries=$((${2:-10} * 10))
  while ((tries-- > 0)); do
    eval "$1" && return 0
    sleep 0.1
  done
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
  --user)
    TARGET_USER="${2:-}"
    [[ -n $TARGET_USER ]] || die "--user needs a name"
    shift 2
    ;;
  --no-auto-log)
    AUTO_LOG=0
    shift
    ;;
  -h | --help)
    sed -n '3,11p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *) die "unknown option: $1 (try --help)" ;;
  esac
done

# ---------------------------------------------------------------- who gets configured
# Under sudo, SUDO_USER is the human who ran this, and they are almost always the one
# who wants their tmux configured. In a root shell reached any other way (su -, a root
# login, a container) SUDO_USER is unset, so there is nobody to infer - say so out loud
# instead of quietly configuring /root.
if [[ -z $TARGET_USER ]]; then
  if [[ $EUID -eq 0 && -n ${SUDO_USER:-} && ${SUDO_USER} != "root" ]]; then
    TARGET_USER="$SUDO_USER"
  else
    TARGET_USER="$(id -un)"
  fi
fi

id "$TARGET_USER" >/dev/null 2>&1 || die "no such user: $TARGET_USER"

if [[ $EUID -eq 0 && $TARGET_USER == "root" ]]; then
  warn "running as root with no SUDO_USER, so this configures root's tmux."
  warn "if you meant your own account, re-run with: --user <name>"
fi

# Act as the target user, without a pointless sudo round trip when we already are them.
if [[ "$(id -un)" == "$TARGET_USER" ]]; then
  run_as() { "$@"; }
else
  command -v sudo >/dev/null 2>&1 || die "sudo is needed to act as $TARGET_USER, and is not installed"
  run_as() { sudo -u "$TARGET_USER" -H "$@"; }
fi

# Ask the account for its home rather than guessing with eval/~, which yields a literal
# "~name" for a user that does not exist - no business being near an rm -rf.
USER_HOME="$(run_as bash -c 'printf %s "$HOME"')"
[[ -n $USER_HOME && -d $USER_HOME ]] || die "cannot resolve a home directory for $TARGET_USER"

for bin in tmux git; do
  command -v "$bin" >/dev/null 2>&1 || die "$bin is not installed (setup/install.sh does not install tmux)"
done

step "configuring tmux for $TARGET_USER ($USER_HOME)"

# ------------------------------------------------- which config, and which plugin dir
# tmux 3.2+ and tpm both prefer ~/.config/tmux/tmux.conf over ~/.tmux.conf, and tpm
# moves its plugin directory to match: with an XDG config it uses
# ~/.config/tmux/plugins, otherwise ~/.tmux/plugins (see set_default_tpm_path in tpm).
# Both have to follow the same rule here. Picking the config by XDG but installing to
# ~/.tmux/plugins anyway would put the plugins somewhere tpm never looks at startup,
# so the keybindings would be missing even though everything installed cleanly.
XDG_DIR="$(run_as bash -c 'printf %s "${XDG_CONFIG_HOME:-$HOME/.config}"')/tmux"
if [[ -f $XDG_DIR/tmux.conf ]]; then
  CONF="$XDG_DIR/tmux.conf"
  PLUGIN_DIR="$XDG_DIR/plugins"
  step "following the XDG layout, so plugins go in $PLUGIN_DIR"
else
  CONF="$USER_HOME/.tmux.conf"
  PLUGIN_DIR="$USER_HOME/.tmux/plugins"
fi

# ------------------------------------------------------------------------------- tpm
TPM_DIR="$PLUGIN_DIR/tpm"
if [[ -d $TPM_DIR/.git ]]; then
  step "updating tpm"
  run_as git -C "$TPM_DIR" pull --quiet --ff-only || warn "could not update tpm; keeping what is there"
else
  step "installing tpm"
  [[ -e $TPM_DIR ]] && run_as rm -rf "$TPM_DIR"
  run_as mkdir -p "$PLUGIN_DIR"
  run_as git clone --quiet https://github.com/tmux-plugins/tpm "$TPM_DIR"
fi
run_as mkdir -p "$USER_HOME/tmux-logs"

# ---------------------------------------------------------------------------- config
if [[ -f $CONF ]]; then
  BACKUP="$CONF.bak.$(date +%Y%m%d%H%M%S)"
  run_as cp "$CONF" "$BACKUP"
  warn "existing config backed up to $BACKUP"
fi

# A chain rather than one tool: pbcopy on macOS, wl-copy on Wayland, xclip on X11.
# set-clipboard on also gets OSC 52 working through most modern terminals, which covers
# a box where none of the three is installed.
CLIP='pbcopy 2>/dev/null || wl-copy 2>/dev/null || xclip -selection clipboard -in 2>/dev/null'

TOGGLE="$PLUGIN_DIR/tmux-logging/scripts/toggle_logging.sh"

run_as tee "$CONF" >/dev/null <<EOF
# Written by setup/tmuxSetup.sh. Re-running it replaces this file (after backing it up).

set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'

# Evidence: a long scrollback, and logs somewhere predictable.
set -g history-limit 100000
set -g @logging-path "$USER_HOME/tmux-logs"
# @logging-filename, not @logging-filename-format: the latter is not an option the
# plugin reads, so it was ignored and logs kept the plugin's default names. Leading
# timestamp so the directory sorts chronologically.
set -g @logging-filename "%Y%m%dT%H%M%S-#{session_name}-#{window_index}.#{pane_index}.log"
set -g @save-complete-history-path "$USER_HOME/tmux-logs"
set -g @screen-capture-path "$USER_HOME/tmux-logs"

set-option -g set-clipboard on
setw -g mode-keys vi
set -g mouse on

bind -T copy-mode-vi y send-keys -X copy-pipe-and-cancel "$CLIP"
bind -T copy-mode-vi MouseDragEnd1Pane send-keys -X copy-pipe-and-cancel "$CLIP"
EOF

# Two details in the hook command below, both learned the hard way. The -x test is
# there because these hooks are written before tpm has fetched the plugin, so the
# setup session fired a script that did not exist yet and tmux reported "returned
# 127" - it also keeps things quiet if the plugin is ever removed from under the
# config. The trailing || true is there because tmux reports a hook's exit status as
# the status of the command that fired it: without it, a false -x test makes the
# new-session call further down look like it failed.
if [[ $AUTO_LOG -eq 1 ]]; then
  run_as tee -a "$CONF" >/dev/null <<EOF

# Log every pane from the moment it exists, so the evidence behind a finding does not
# depend on someone remembering prefix+shift+P. Re-run with --no-auto-log to drop this.
set-hook -g after-new-session  'run-shell "[ -x $TOGGLE ] && $TOGGLE || true"'
set-hook -g after-new-window   'run-shell "[ -x $TOGGLE ] && $TOGGLE || true"'
set-hook -g after-split-window 'run-shell "[ -x $TOGGLE ] && $TOGGLE || true"'
EOF
fi

run_as tee -a "$CONF" >/dev/null <<EOF

run -b '$TPM_DIR/tpm'
EOF

ok "wrote $CONF"

# -------------------------------------------------------------------- install plugins
# tpm's installer runs headlessly as long as a server is up, so drive it directly.
# Typing it into a detached session and sleeping raced the clone, and the prefix key it
# sent afterwards went to a shell with no client attached to interpret it.
#
# It has to be the default socket: tpm shells out to a plain "tmux" itself, so a
# private -L socket would be invisible to it.
tmux_as() { run_as env -u TMUX -u TMUX_TMPDIR tmux "$@"; }

step "installing plugins"

# The session name is per-process, and any older one is cleared out first. A fixed
# name was a trap: a run that died left the session behind, every later run then
# failed here with "duplicate session", and set -e meant the script exited before
# tpm was ever called - so tmux-logging silently never arrived.
tmux_as kill-session -t _tmux_setup >/dev/null 2>&1 || true
SETUP_SESSION="_tmux_setup_$$"
tmux_as kill-session -t "$SETUP_SESSION" >/dev/null 2>&1 || true
cleanup() {
  tmux_as kill-session -t "$SETUP_SESSION" >/dev/null 2>&1 || true
  # Once tmux-logging is installed the auto-log hook fires for our own throwaway
  # session as well; drop its empty log so the evidence directory stays clean.
  rm -f "$USER_HOME/tmux-logs"/*_tmux_setup*.log 2>/dev/null || true
}
trap cleanup EXIT
tmux_as new-session -d -s "$SETUP_SESSION" ||
  die "cannot start a tmux server to install plugins into"
tmux_as source-file "$CONF"

# Keep tpm's chatter out of the way, but hold on to it: if a plugin is missing it is
# the only thing that says why. The old version sent it to /dev/null, which is how
# the failure above stayed invisible.
# A full template, because -t means something different to BSD and GNU mktemp and
# "mktemp -t name" is an error on Kali.
# tpm's installer finds the plugin directory by reading TMUX_PLUGIN_MANAGER_PATH out
# of the tmux server environment. The only thing that sets it is the tpm script itself,
# fired by the "run -b" line at the end of the config - and -b means backgrounded, so
# the installer can look the variable up before tpm has got around to setting it and
# abort with "FATAL: Tmux Plugin Manager not configured in tmux.conf". That is a race,
# which is why it failed on one box and not another. Setting it here, exactly as tpm
# would, takes the timing out of it.
tmux_as set-environment -g TMUX_PLUGIN_MANAGER_PATH "$PLUGIN_DIR"
wait_for 'tmux_as show-environment -g TMUX_PLUGIN_MANAGER_PATH >/dev/null 2>&1' 5 ||
  die "the tmux server did not accept TMUX_PLUGIN_MANAGER_PATH"

TPM_LOG="$(mktemp "${TMPDIR:-/tmp}/tmuxSetup.XXXXXX")"
if ! run_as env -u TMUX -u TMUX_TMPDIR "$TPM_DIR/bin/install_plugins" >"$TPM_LOG" 2>&1; then
  warn "tpm's installer exited non-zero:"
  sed 's/^/    /' "$TPM_LOG" >&2
fi

# Check by name rather than counting directories: the count looked healthy with tpm
# alone, which is exactly the case that was broken.
# A directory can exist while the clone is still arriving, so wait for the plugin's
# own *.tmux entry point - the file tpm sources - rather than just the directory.
MISSING=""
for plugin in tmux-sensible tmux-logging; do
  wait_for "compgen -G '$PLUGIN_DIR/$plugin/*.tmux' >/dev/null" 10 ||
    MISSING="$MISSING $plugin"
done
if [[ -n $MISSING ]]; then
  warn "tpm output was:"
  sed 's/^/    /' "$TPM_LOG" >&2
  rm -f "$TPM_LOG"
  die "these plugins did not install:$MISSING"
fi
rm -f "$TPM_LOG"
ok "plugins: tpm, tmux-sensible, tmux-logging"

# Source once more now that the plugins are on disk. A server that was already running
# read the config before they existed, so its keybindings would otherwise stay missing
# until tmux was restarted.
#
# Sourcing only queues the work: the config ends with "run -b", so tpm sources the
# plugins in the background and the bindings appear some time after this returns. Wait
# for the binding itself rather than guessing at a sleep - it is the thing we actually
# care about, and tying the wait to it means a slow box just waits a little longer.
tmux_as source-file "$CONF"
if ! wait_for 'tmux_as list-keys 2>/dev/null | grep -q toggle_logging' 15; then
  warn "plugins are installed but tmux has not bound their keys yet"
  warn "run 'tmux source-file $CONF' in a live session, or restart tmux"
fi

for tool in pbcopy wl-copy xclip; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "clipboard: $tool"
    CLIP_OK=1
    break
  fi
done
[[ -n ${CLIP_OK:-} ]] || warn "no pbcopy, wl-copy or xclip - copy falls back to the terminal's OSC 52"

if [[ $AUTO_LOG -eq 1 ]]; then
  ok "new panes log to $USER_HOME/tmux-logs automatically"
  ok "prefix + P stops the log on the current pane; prefix + M-P dumps full scrollback"
else
  ok "prefix + P starts and stops logging, into $USER_HOME/tmux-logs"
fi
ok "done - start tmux, or run 'tmux source-file ~/.tmux.conf' in a live session"

ok "Fixing termincal config!"
