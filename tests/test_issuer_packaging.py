"""Real ELF closure controls; actual Go payload assembly also runs in package CI."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('issuer_package',ROOT/'packaging/package.py')
package=importlib.util.module_from_spec(spec);spec.loader.exec_module(package)


@unittest.skipUnless(sys.platform=='linux' and shutil.which('cc') and shutil.which('readelf') and shutil.which('ldd'),
                     'Requires native Linux ELF build tools; full actual Go assembly runs in package CI')
class IssuerELFPackagingTests(unittest.TestCase):
    def test_actual_static_executable_needs_no_dynamic_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'static.c';source.write_text('void _start(void) { for (;;) {} }\n')
            binary=root/'static'
            subprocess.run(['cc','-nostdlib','-static','-fno-stack-protector',str(source),'-o',str(binary)],check=True,capture_output=True)
            self.assertTrue(package.static_executable(binary))
            package.validate_elf_architecture(binary,os.uname().machine)
            wrong=root/'wrong-architecture';data=bytearray(binary.read_bytes())
            data[18:20]=(183 if os.uname().machine=='x86_64' else 62).to_bytes(2,'little');wrong.write_bytes(data)
            with self.assertRaises(ValueError):package.validate_elf_architecture(wrong,os.uname().machine)
            destination=root/'lib';destination.mkdir()
            self.assertEqual(package.collect_dependencies(binary,destination,os.environ),[])
            self.assertEqual(list(destination.iterdir()),[])

    def test_missing_dynamic_dependency_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);library=root/'required.c';library.write_text('int required(void) { return 0; }\n')
            dependency=root/'libtraverse_required.so'
            subprocess.run(['cc','-shared','-fPIC',str(library),'-o',str(dependency)],check=True,capture_output=True)
            main=root/'main.c';main.write_text('extern int required(void); int main(void) { return required(); }\n')
            binary=root/'dynamic'
            subprocess.run(['cc',str(main),'-L'+str(root),'-ltraverse_required','-Wl,-rpath,'+str(root),'-o',str(binary)],check=True,capture_output=True)
            self.assertFalse(package.static_executable(binary))
            dependency.unlink()
            destination=root/'lib';destination.mkdir()
            with self.assertRaises((ValueError,subprocess.CalledProcessError)):
                package.collect_dependencies(binary,destination,os.environ)


if __name__=='__main__':unittest.main()
