import contextlib
import hashlib
import http.server
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('fetch_download',ROOT/'packaging/fetch-sources.py')
fetch=importlib.util.module_from_spec(spec);spec.loader.exec_module(fetch)


class SourceDownloadTests(unittest.TestCase):
    @contextlib.contextmanager
    def source_server(self, truncate_first):
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w') as archive:
            content=b'verified source\n'
            item=tarfile.TarInfo('fixture/README');item.size=len(content)
            archive.addfile(item,io.BytesIO(content))
        body=data.getvalue();requests=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
                partial=truncate_first and len(requests)==1
                self.wfile.write(body[:64] if partial else body);self.wfile.flush()
                self.close_connection=True
            def log_message(self,*_):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:yield f'http://127.0.0.1:{server.server_port}/fixture.tar',body,requests
        finally:server.shutdown();server.server_close();thread.join()

    def run_fetch(self, root, url, digest):
        root=Path(root);(root/'packaging').mkdir()
        (root/'packaging/runtime-manifest.json').write_text(json.dumps({'sources':[{'name':'fixture','url':url,'sha256':digest}]}))
        with patch.object(fetch,'ROOT',root),patch.object(fetch.sys,'argv',['fetch-sources.py',str(root/'sources')]):
            fetch.main()
        return root/'sources'

    def test_real_curl_recovers_a_truncated_download(self):
        with tempfile.TemporaryDirectory() as root,self.source_server(True) as (url,body,requests):
            output=self.run_fetch(root,url,hashlib.sha256(body).hexdigest())
            self.assertEqual(len(requests),2)
            self.assertEqual((output/'fixture.tar').read_bytes(),body)
            self.assertEqual((output/'fixture/README').read_bytes(),b'verified source\n')

    def test_retried_download_still_requires_the_pinned_digest(self):
        with tempfile.TemporaryDirectory() as root,self.source_server(True) as (url,body,requests):
            with self.assertRaisesRegex(ValueError,'Source digest mismatch'):
                self.run_fetch(root,url,'0'*64)
            self.assertEqual(len(requests),2)
            self.assertFalse((Path(root)/'sources/fixture').exists())
            self.assertFalse((Path(root)/'sources/fixture-extract').exists())


if __name__=='__main__':unittest.main()
