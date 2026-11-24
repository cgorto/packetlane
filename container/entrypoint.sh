#!/bin/sh
# Gives a home folder the bundled Helix settings if it has none of its own,
# then runs the command. An existing ~/.config/helix is never touched.
if [ -n "$HOME" ] && [ -d "$HOME" ] && [ ! -e "$HOME/.config/helix" ]; then
    mkdir -p "$HOME/.config" \
        && cp -r /usr/local/share/helix/config "$HOME/.config/helix"
fi
exec "$@"
