"""Stable tags must match CMake and point to a commit contained in main."""
from pathlib import Path
import re
import subprocess
import sys


def validate(tag, version):
    if not re.fullmatch(r'v\d+\.\d+\.\d+',tag):raise ValueError('Stable release needs vX.Y.Z')
    if tag[1:]!=version:raise ValueError('Tag does not match CMake project version')


def require_main_commit(sha, repository="."):
    subprocess.run(["git","-C",str(repository),"merge-base","--is-ancestor",sha,"origin/main"],check=True)


def main():
    tag=sys.argv[1]
    root=Path(__file__).resolve().parent.parent
    version=re.search(r'project\(traverse VERSION (\d+\.\d+\.\d+)\b',(root/'native/CMakeLists.txt').read_text()).group(1)
    validate(tag,version)
    sha=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    tag_sha=subprocess.check_output(['git','rev-parse',tag+'^{commit}'],text=True).strip()
    if sha!=tag_sha:raise ValueError('Checkout is not the exact release tag commit')
    require_main_commit(tag_sha)
    print(sha)


if __name__=='__main__':main()
