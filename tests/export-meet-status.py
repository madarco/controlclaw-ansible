"""Build the actual pinned, patched status-script function for DOM regressions."""
import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile
root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('patcher', root / 'roles/controlclaw/files/meeting-runtime-patch.py')
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)
upstream = Path(sys.argv[1])
with tempfile.TemporaryDirectory() as d:
    dest = Path(d)
    for p in patcher.PATCHES:
        source = upstream / ('host/package' if p['kind'] == 'host' else 'package') / p['path']
        target = dest / p['kind'] / p['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()):
        patcher.patch(dest / 'host', dest / 'plugin')
    source = (dest / 'plugin/dist/.setup/google-meet-platform-adapter-gosgbMIM.mjs').read_text()
    print(source[source.index('const GOOGLE_MEET_TRANSCRIPT_MAX_LINES'):source.index('function meetAudioCaptureScript(')])
    print(source[source.index('function meetStatusScript(params) {'):source.index('\nfunction meetLeaveScript(')])
