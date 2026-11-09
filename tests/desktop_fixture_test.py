"""Real X11 regression for complete fixture history, including buffer growth."""
import ctypes
import ctypes.util
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix='traverse-fixture-') as directory:
    directory=Path(directory);binary=directory/'fixture';state=directory/'state.json'
    subprocess.run(['gcc','-O2','-Wall','-Wextra','-Werror',str(ROOT/'desktop_fixture.c'),'-o',str(binary),'-lX11'],check=True)
    x=ctypes.CDLL(ctypes.util.find_library('X11'));xt=ctypes.CDLL(ctypes.util.find_library('Xtst'))
    x.XOpenDisplay.argtypes=[ctypes.c_char_p];x.XOpenDisplay.restype=ctypes.c_void_p
    x.XSetInputFocus.argtypes=[ctypes.c_void_p,ctypes.c_ulong,ctypes.c_int,ctypes.c_ulong]
    x.XStringToKeysym.argtypes=[ctypes.c_char_p];x.XStringToKeysym.restype=ctypes.c_ulong
    x.XKeysymToKeycode.argtypes=[ctypes.c_void_p,ctypes.c_ulong];x.XKeysymToKeycode.restype=ctypes.c_ubyte
    x.XSync.argtypes=[ctypes.c_void_p,ctypes.c_int];x.XCloseDisplay.argtypes=[ctypes.c_void_p]
    xt.XTestFakeKeyEvent.argtypes=[ctypes.c_void_p,ctypes.c_uint,ctypes.c_int,ctypes.c_ulong]
    display=x.XOpenDisplay(os.environ['DISPLAY'].encode());assert display,'X11 display unavailable'
    process=None
    try:
        process=subprocess.Popen([str(binary),str(state)],stdout=subprocess.PIPE)
        assert select.select([process.stdout],[],[],10)[0],'Fixture did not map its window'
        line=process.stdout.readline().decode();assert line.startswith('window=') and ' pid=' in line
        window=int(line.split()[0].split('=')[1]);x.XSetInputFocus(display,window,1,0)
        def press(name):
            code=x.XKeysymToKeycode(display,x.XStringToKeysym(name.encode()));assert code
            assert xt.XTestFakeKeyEvent(display,code,1,0)
            assert xt.XTestFakeKeyEvent(display,code,0,0)
        def observed(count):
            x.XSync(display,0);end=time.monotonic()+30
            while True:
                assert process.poll() is None,'Fixture exited during input'
                try:value=json.loads(state.read_text())
                except (FileNotFoundError,json.JSONDecodeError):value={}
                if value.get('presses')==count and value.get('releases')==count:return value
                assert time.monotonic()<end,'Fixture did not record all input events'
                time.sleep(.02)
        for _ in range(1100):press('a')
        first=observed(1100)
        assert first['text']=='a'*1100,'Fixture truncated received text'
        press('BackSpace');press('b')
        second=observed(1102)
        assert second['text']=='a'*1099+'b','Append/backspace after growth failed'
        print(json.dumps({'desktopFixture':'passed','initialCharacters':1100,'appendAfterBackspace':True}))
    finally:
        if process is not None:
            if process.poll() is None:process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
            if process.stdout:process.stdout.close()
        x.XCloseDisplay(display)
