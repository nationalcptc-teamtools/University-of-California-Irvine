#TMUX SETUP
TARGET_USER="${SUDO_USER:-$USER}"
USER_HOME=$(eval echo ~${SUDO_USER:-$USER})
sudo -u "$TARGET_USER" -H rm -rf "$USER_HOME/.tmux/plugins/tpm"
sudo -u "$TARGET_USER" -H git clone https://github.com/tmux-plugins/tpm "$USER_HOME/.tmux/plugins/tpm"
sudo -u "$TARGET_USER" -H mkdir -p $USER_HOME/tmux-logs

sudo -u "$TARGET_USER" -H bash <<EOF
cat > "\$HOME/.tmux.conf" <<EOC
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'
set -g @logging-path "\$HOME/tmux-logs"

set-option -g set-clipboard on

setw -g mode-keys vi
bind -T copy-mode-vi MouseDragEnd1Pane send-keys -X copy-pipe-and-cancel "xclip -sel c"
bind -T copy-mode-vi y send-keys -X copy-pipe-and-cancel "xclip -selection clipboard -in || wl-copy"
set -g mouse on

run -b '~/.tmux/plugins/tpm/tpm'
EOC
EOF

sudo -u "$TARGET_USER" -H tmux new-session -d -s _tpm_bootstrap

sudo -u "$TARGET_USER" -H tmux send-keys -t _tpm_bootstrap "tmux source-file $USER_HOME/.tmux.conf" C-m
sleep 0.5
sudo -u "$TARGET_USER" -H tmux send-keys -t _tpm_bootstrap "$USER_HOME/.tmux/plugins/tpm/bin/install_plugins" C-m
sleep 1
sudo -u "$TARGET_USER" -H tmux send-keys -t _tpm_bootstrap C-b I
sleep 1

sudo -u "$TARGET_USER" -H tmux kill-session -t _tpm_bootstrap
