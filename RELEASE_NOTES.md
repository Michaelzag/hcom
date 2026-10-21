## Unreleased

Terminal cleanup now requires a receipt from the instance's own launch.
Manually started agents can't close another seat by inheriting its pane or
systemd unit id.

**Upgrade behavior:** instances launched by v0.7.58 or earlier have no receipt.
Kill or resume leaves their terminal panes open until they're relaunched.
This includes the gnomeseat and zagtmux seats already running on mbai. The
upgrade doesn't retroactively certify their captured terminal ids.

Run-here tool launches still close their own identified pane in tmux,
wezterm, kitty, zellij, herdr and waveterm. The launcher records ownership
before exec using that pane's environment id. Window, workspace and unit
ids don't grant run-here ownership: an inherited `GNOME_SEAT_UNIT` or
`gnome-terminal-seat-*` value never permits closing the whole seat.

Session adoption transfers receipt ownership to the canonical instance
alongside its pid and launch context. After ownership is proven, the close
id order stays `pane_id` (from `pane_id_env`), then `terminal_id`, then the
opener's captured id. The per-seat unit-name guard applies to the chosen id.
