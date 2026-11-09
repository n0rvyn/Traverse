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

A later `5b8b697` package passed the same controls in headless Chrome156. Two unchanged direct
runs measured 59.8/59.1 fps and 107/122 ms median visible response. Each median
uses ten samples. A relay run measured 57.3 fps and 94 ms median, but also had
four freezes during its five-second stats interval and input acknowledgement
spikes up to 908 ms across the control trace. Its lower median does not establish
better relay performance.

Private metadata tracing then measured the native path without changing the
media settings or installed payload. A known 10 ms delay calibrated at 10.15 ms;
shifted segment, future timestamp and invalid timestamp controls also passed.
The analysis uses actual GStreamer clock/segment conversion and the sender's
observed sink latency. It retains startup observations separately from samples
after each pipeline's first two seconds.

| Native stage | Matched frames | Median | p95 |
|---|---:|---:|---:|
| Capture output to converted frame | 1,795 | 3.90 ms | 5.86 ms |
| Sender output to received frame | 1,496 | 0.17 ms | 0.43 ms |
| Received frame to pre-encoder queue output | 1,491 | 0.07 ms | 0.83 ms |
| Pre-encoder queue output to encoded frame | 1,491 | 7.24 ms | 12.53 ms |

These are matched-frame stage differences, not physical input latency. Encoding
is the largest measured native stage; frame transfer and the pre-encoder queue
are small. The traced runs passed the full control and local Stop checks, at
60.1 fps and 120/128 ms median visible response. Two controls and two probes do
not precisely isolate tracing overhead from network variation.

Chrome stats observed average jitter buffering of 22–30 ms and decoding of
2.3–2.8 ms during these direct runs. The next experiment targets receiver
buffering while checking drops, freezes and packet recovery. The standard
receiver target influences a delay-versus-recovery tradeoff; no buffering default
has been changed. See the [WebRTC receiver specification](https://www.w3.org/TR/webrtc/#dom-rtcrtpreceiver-jitterbuffertarget).

Visible desktop Chrome156 independently passed the same eight control checks
on the exact `5b8b697` package: 59.7 fps / 109 ms median over direct UDP and
59.9 fps / 121 ms median over TURN/TLS, with ten visible-response samples each.
Browser diagnostics identified Intel Iris graphics through ANGLE Metal and
enabled GPU compositing. This confirms the desktop rendering path; it does not
establish hardware VP8 decoding or physical input-to-photon latency.
