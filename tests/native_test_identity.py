"""Run media-only native test actors without the root CI observer's privilege."""
import os
import pwd
import tempfile


def unprivileged_media_test():
    if os.geteuid()!=0:return None
    account=pwd.getpwnam('nobody')
    os.setgroups([]);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
    cache=tempfile.TemporaryDirectory(prefix='traverse-native-test-')
    os.environ.update(HOME=cache.name,XDG_CACHE_HOME=cache.name,
                      GST_REGISTRY=cache.name+'/registry.bin',GST_REGISTRY_1_0=cache.name+'/registry.bin')
    return cache # Keep alive until the test interpreter exits; no cache remnants.
