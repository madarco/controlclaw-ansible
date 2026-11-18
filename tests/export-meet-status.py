"""Build the actual pinned, patched status-script function for DOM regressions."""
import importlib.util
from pathlib import Path
import re
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
    if len(sys.argv) > 2 and sys.argv[2] == 'backend':
        # 2026.11.5 moved it to its own module (meeting-config), with minified parameter names.
        [config] = (dest / 'host/dist').glob('meeting-config-????????.mjs')
        source = config.read_text()
        start = re.search(r'async function ensureMeetingAudioBackend\(\w+\) \{', source).start()
        print(source[start:source.index('\n}', start)+2])
        print('; ensureMeetingAudioBackend')
        sys.exit(0)
    if len(sys.argv) > 2 and sys.argv[2] == 'consult':
        source = (dest / 'host/dist/plugin-sdk/meeting-runtime.js').read_text()
        start = re.search(r'async function consultMeetingAgent\(\w+\) \{', source).start()
        # The model of the meeting's lookups (Model for meetings) comes from a helper next to it.
        if 'function ccMeetingConsultModel(' in source:
            helper = source.index('function ccMeetingConsultModel(')
            print(source[helper:source.index('\n}', helper)+2])
        print(source[start:source.index('\n}', start)+2])
        print('; consultMeetingAgent')
        sys.exit(0)
    if len(sys.argv) > 2 and sys.argv[2] == 'output-queue':
        source = (dest / 'host/dist/plugin-sdk/meeting-runtime.js').read_text()
        start = source.index('const OUTPUT_MAX_PENDING_MS')
        end = source.index('\n}', source.index('function createMeetingRealtimeOutputQueue', start)) + 2
        print(source[start:end])
        print('; createMeetingRealtimeOutputQueue')
        sys.exit(0)
    if len(sys.argv) > 2 and sys.argv[2] == 'recovery':
        source = next((dest / 'plugin/dist/.setup').glob('runtime-????????.mjs')).read_text()
        start = source.index('async function recoverCurrentMeetTab(params) {')
        end = source.index('\n}', start) + 2
        print(source[start:end])
        start = source.index('\tasync #refreshBrowserHealth(session, options = {}) {')
        end = source.index('\n\tasync #refreshStatus(', start)
        print('class Probe { params = {config: {}, fullConfig: {}, runtime: {}, logger: {debug() {}}}; async run(session) { return this.#refreshBrowserHealth(session); }')
        print(source[start:end])
        print('}; new Probe()')
        sys.exit(0)
    source = next((dest / 'plugin/dist/.setup').glob('google-meet-platform-adapter-*.mjs')).read_text()
    print(source[source.index('const GOOGLE_MEET_TRANSCRIPT_MAX_LINES'):source.index('function meetAudioCaptureScript(')])
    print(source[source.index('function meetStatusScript(params) {'):source.index('\nfunction meetLeaveScript(')])
