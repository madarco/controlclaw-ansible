"""Only the pinned source filename and line number leave the box, never task arguments/results."""
from pathlib import Path
from ansible.plugins.callback import CallbackBase

class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'notification'
    CALLBACK_NAME = 'cc_pool_progress'
    CALLBACK_NEEDS_ENABLED = True

    def v2_playbook_on_task_start(self, task, is_conditional):
        source = task.get_path().rsplit('/', 1)[-1]
        Path('/root/cc-pool-task').write_text(source[:150])
