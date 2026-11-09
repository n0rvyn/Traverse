# Deferred: hosts without a graphical session

Docs only, outside the active goal. A browser terminal can use an authenticated UNIX98 PTY and a terminal renderer without X11/Wayland. This creates a terminal session; it does not make a graphical desktop or automatically take over the host physical TTY. Physical-console access, existing-session attachment, login authority, reconnect persistence, process lifetime, clipboard and audit policy need a separate design after the present goal.

Reference: https://man7.org/linux/man-pages/man7/pty.7.html . No terminal server or shell endpoint is added now.
