"""A new guest profile per call. Camera always denied; microphone only for approved Bidi."""
import json
from pathlib import Path
import sys
voice = Path('/opt/controlclaw/state/meeting-browser-voice').exists()
Path(sys.argv[1]).write_text(json.dumps({'profile': {'default_content_setting_values': {
    'media_stream_camera': 2, 'media_stream_mic': 1 if voice else 2,
}}}))
