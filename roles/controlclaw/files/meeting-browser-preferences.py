"""Settings for the meeting browser's profile, written before each start.

Camera always denied; microphone only for approved Bidi. The guest profile is new per call. The
signed-in profile is kept between calls, so its other settings are left as they are; it never
offers to save a password.
"""
import json
from pathlib import Path
import sys
voice = Path('/opt/controlclaw/state/meeting-browser-voice').exists()
path = Path(sys.argv[1])
try:
    prefs = json.loads(path.read_text())
except (OSError, ValueError):
    prefs = {}
if not isinstance(prefs, dict):
    prefs = {}
profile = prefs.setdefault('profile', {})
profile.setdefault('default_content_setting_values', {}).update({
    'media_stream_camera': 2, 'media_stream_mic': 1 if voice else 2,
})
profile['password_manager_enabled'] = False
# The unit stops Chrome with a signal; without this the next start offers to restore its pages.
profile['exit_type'] = 'Normal'
profile['exited_cleanly'] = True
prefs['credentials_enable_service'] = False
path.write_text(json.dumps(prefs))
