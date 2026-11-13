"""Installed-entry boundary shared by actual-main fixtures; never packaged."""
import os
from pathlib import Path


def host_command(executable, prefix, environment):
    if os.environ.get('TRAVERSE_TEST_HOST_PACKAGED_ENTRY')!='1':
        return [str(executable),'--prefix',str(prefix)],environment
    env=dict(environment)
    utilities=os.environ['TRAVERSE_TEST_HOST_TOOL_PATH']
    env.update(PATH=str(prefix/'libexec/traverse')+':'+utilities,
               LD_LIBRARY_PATH=str(prefix/'lib'),TRAVERSE_RUNTIME_PREFIX=str(prefix),
               GST_PLUGIN_SYSTEM_PATH_1_0=str(prefix/'lib/gstreamer-1.0'),
               GST_PLUGIN_PATH_1_0=str(prefix/'lib/gstreamer-1.0'),
               PIPEWIRE_MODULE_DIR=str(prefix/'lib/pipewire-0.3'),SPA_PLUGIN_DIR=str(prefix/'lib/spa-0.2'))
    return [str(executable)],env


def check_ui_process(process, prefix):
    if os.environ.get('TRAVERSE_TEST_HOST_PACKAGED_ENTRY')!='1':return
    expected=prefix.resolve()/'libexec/traverse/traverse-host'
    assert Path('/proc/'+str(process.pid)+'/exe').resolve()==expected,'App did not execute the packaged UI'
    maps=Path('/proc/'+str(process.pid)+'/maps').read_text()
    paths=[row.split(maxsplit=5)[5] for row in maps.splitlines() if len(row.split(maxsplit=5))==6 and row.split(maxsplit=5)[5].startswith('/')]
    for name in ('libQt6Core.so.6','libQt6Gui.so.6','libQt6Widgets.so.6','libQt6DBus.so.6'):
        matched=[Path(p) for p in paths if Path(p).name.startswith(name)]
        assert matched and all(str(p).startswith(('/usr/lib/','/lib/','/usr/lib64/','/lib64/')) for p in matched),'Qt did not resolve through system libraries'
    assert not any(Path(p).is_relative_to(prefix.resolve()/'lib') for p in paths),'UI loaded private media libraries'
    assert not any(Path(p).name.startswith(('libgstreamer','libgst','libnice','libpipewire','libei.')) for p in paths),'Media runtime entered UI process'
    environment=Path('/proc/'+str(process.pid)+'/environ').read_bytes().split(b'\0')
    assert not any(row.startswith((b'LD_LIBRARY_PATH=',b'TRAVERSE_RUNTIME_PREFIX=',b'GST_PLUGIN_SYSTEM_PATH_1_0=',b'PIPEWIRE_MODULE_DIR=')) for row in environment),'Host wrapper retained private media environment'
    status=Path('/proc/'+str(process.pid)+'/status').read_text().splitlines()
    capabilities=next(row.split(':',1)[1].strip() for row in status if row.startswith('CapEff:'))
    assert int(capabilities,16)==0,'Qt UI acquired capabilities'
