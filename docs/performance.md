# Performance evidence

The current runtime uses software VP8 encoding. Hardware encoding, native
Wayland and physical input-to-photon measurements remain separate work.

Development tests used the same 1280×720 X11 desktop, encoder settings and
ordinary Chrome 156 over the Internet. They preserve input authorization,
encryption and the existing text/readability fixture. These are observations
from one CPU-only Linux host, not a guarantee for other machines or networks.

| Test | Observed result |
|---|---|
| Direct UDP, full browser control path | 59.6 decoded fps; 120 ms median visible response across 10 input samples |
| TURN/TLS, full browser control path | 58.8 decoded fps; 162 ms median visible response across 10 input samples |
| One deliberately dropped video packet, two direct recovery runs | Received retransmissions; no receiver freezes during either measured trace; largest displayed-frame gaps about 83 ms |
| Same loss probe over TURN/TLS | Recovery succeeded; displayed-frame gaps still reached 417 ms |

The control path includes actual X11 typing, modifiers, scrolling, pointer
mapping, reconnect and disconnect. Visible response measures browser key dispatch
to the first decoded-video callback showing a changed desktop marker. It includes
capture, encoding, transport, decoding and callback scheduling; it excludes
physical keyboard and monitor timing. Frame gaps describe spacing between video
callbacks, rather than input response time.

The exact `1af36a9` CI portable artifact subsequently passed the same full Chrome
control checks over both paths: 60.0/58.3 decoded fps and 125/156 ms median visible
response for direct/relay, respectively. Each median uses 10 samples. Its local
Stop sharing released a held Shift key before Chrome closed and stopped all
owned sharing processes.

The earlier `5de5721` runtime did not negotiate generic NACK/RTX recovery. Known
single-packet drops produced frame gaps between 233 and 767 ms across four traces.
The recovery change negotiates retransmission and fixes each peer's video source
identity before creating its answer. Its first version exposed a reconnect
failure by announcing a different source from the one carrying video; the final
version was checked on repeated connections to the same server.

These tests establish working recovery and retained controls. Relay variation
still needs investigation. They do not establish a physical latency limit,
GPU performance, broad distribution support or a statistically reliable tail
latency estimate. Development probes are excluded from shipped payloads.
