"""The shell preparation path must never receive the private owner descriptor."""
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent


class HostEntryTests(unittest.TestCase):
    def test_private_owner_flag_is_rejected_before_shell_utilities(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);marker=root/'called'
            for name in ('readlink','dirname','basename','uname','mkdir'):
                helper=root/name
                helper.write_text('#!/bin/sh\nprintf called >> '+shlex.quote(str(marker))+"\nprintf /nonexistent\n")
                helper.chmod(0o755)
            environment={'PATH':str(root),'HOME':str(root)}
            entry=ROOT/'packaging/runtime-entry.sh'
            # Positive control proves this PATH observer sees the ordinary path.
            subprocess.run(['/bin/sh',str(entry),'--help'],env=environment,
                capture_output=True,timeout=3)
            self.assertTrue(marker.exists());marker.unlink()
            result=subprocess.run(['/bin/sh',str(entry),'--config','unused','--owner-fd','9'],
                env=environment,capture_output=True,text=True,timeout=3)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('native launcher',result.stderr)
            self.assertFalse(marker.exists(),'A shell utility inherited the private owner descriptor')
