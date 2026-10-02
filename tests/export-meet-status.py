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
    if len(sys.argv) > 2 and sys.argv[2] == 'recovery':
        source = (dest / 'plugin/dist/.setup/runtime-BdiF53A2.mjs').read_text()
        start = source.index('async function recoverCurrentMeetTab(params) {')
        end = source.index('\n}', start) + 2
        print(source[start:end])
        start = source.index('\tasync #refreshBrowserHealth(session, options = {}) {')
        end = source.index('\n\tasync #refreshStatus(', start)
        print('class Probe { params = {config: {}, fullConfig: {}, runtime: {}, logger: {debug() {}}}; async run(session) { return this.#refreshBrowserHealth(session); }')
        print(source[start:end])
        print('}; new Probe()')
        sys.exit(0)
    source = (dest / 'plugin/dist/.setup/google-meet-platform-adapter-gosgbMIM.mjs').read_text()
    print(source[source.index('const GOOGLE_MEET_TRANSCRIPT_MAX_LINES'):source.index('function meetAudioCaptureScript(')])
    print(source[source.index('function meetStatusScript(params) {'):source.index('\nfunction meetLeaveScript(')])
