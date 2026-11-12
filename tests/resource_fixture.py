"""Optional system pressure telemetry for disposable Linux integration tests."""
import json
import threading
import time
from pathlib import Path


class ResourceTrace:
    def __init__(self, destination):
        self.destination=Path(destination)
        self.stopping=threading.Event()
        self.thread=threading.Thread(target=self.run,daemon=True)
        self.thread.start()

    def run(self):
        with self.destination.open('w') as output:
            while not self.stopping.is_set():
                row={'monotonic':time.monotonic()}
                try:
                    memory={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in Path('/proc/meminfo').read_text().splitlines() if ':' in line}
                    row['memory']={key:memory[key] for key in ('MemTotal','MemAvailable','SwapTotal','SwapFree','Shmem') if key in memory}
                    row['pressure']={key:(Path('/proc/pressure')/key).read_text().strip() for key in ('cpu','memory','io') if (Path('/proc/pressure')/key).is_file()}
                    row['oomKill']=next(line.split()[1] for line in Path('/proc/vmstat').read_text().splitlines() if line.startswith('oom_kill '))
                except (OSError,StopIteration) as failure:row['error']=type(failure).__name__
                output.write(json.dumps(row)+'\n');output.flush()
                self.stopping.wait(1)

    def close(self):
        self.stopping.set()
        self.thread.join()
