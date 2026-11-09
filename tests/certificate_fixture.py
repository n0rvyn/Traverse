"""Ephemeral certificate-manager fixtures; no system trust-store writes."""
import datetime
import ipaddress
from pathlib import Path
import subprocess


def issue_leaf(root, issuer_cert, issuer_key, name, hostname='localhost',
               start=None, end=None, san=True, lifetime_seconds=None):
    root = Path(root)
    key, request, cert = root/(name+'.key'), root/(name+'.csr'), root/(name+'.pem')
    arguments = ['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
                 '-keyout', str(key), '-out', str(request), '-subj', '/CN='+hostname,
                 '-addext', 'basicConstraints=critical,CA:FALSE',
                 '-addext', 'extendedKeyUsage=serverAuth']
    if san:
        try:
            ipaddress.ip_address(hostname);kind = 'IP'
        except ValueError:
            kind = 'DNS'
        arguments += ['-addext', 'subjectAltName='+kind+':'+hostname]
    subprocess.run(arguments, check=True, capture_output=True)
    database = root/(name+'-index');database.write_text('')
    serial = root/(name+'-serial');serial.write_text('01\n')
    directory = root/(name+'-signed');directory.mkdir()
    config = root/(name+'.cnf')
    config.write_text('[ca]\ndefault_ca=local\n[local]\ndatabase='+str(database)+
                      '\nserial='+str(serial)+'\nnew_certs_dir='+str(directory)+
                      '\ncertificate='+str(issuer_cert)+'\nprivate_key='+str(issuer_key)+
                      '\ndefault_md=sha256\ndefault_days=1\npolicy=policy\n'
                      'copy_extensions=copy\nunique_subject=no\nx509_extensions=leaf\n'
                      '[policy]\ncommonName=supplied\n[leaf]\nbasicConstraints=critical,CA:FALSE\n'
                      'keyUsage=critical,digitalSignature,keyEncipherment\n'
                      'extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\n'
                      'authorityKeyIdentifier=keyid:always\n')
    if lifetime_seconds is not None:
        if end is not None:raise ValueError('Choose explicit expiry or relative test lifetime')
        # Compute after key generation so slow test machines retain the full
        # intended observation window. This is a fixture, not a server limit.
        end = datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=lifetime_seconds)
    dates = []
    if start:dates += ['-startdate', start.strftime('%Y%m%d%H%M%SZ')]
    if end:dates += ['-enddate', end.strftime('%Y%m%d%H%M%SZ')]
    subprocess.run(['openssl', 'ca', '-batch', '-notext', '-config', str(config),
                    '-in', str(request), '-out', str(cert), *dates], check=True, capture_output=True)
    return cert.read_bytes(), key.read_bytes()
