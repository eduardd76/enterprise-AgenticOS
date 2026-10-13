"""Agent process entrypoint: `python -m agenticos.runner module:Class`.

Rebinds stdout to stderr so stray prints can't corrupt the syscall channel, reads the
kernel's boot frame, restores the last checkpoint and runs the agent.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import traceback

from .sdk import Sys, SyscallFailed


def main() -> None:
    # Move the kernel channel off fd 1 at the OS level, so subprocesses and C extensions
    # writing to "stdout" can't inject frames into the syscall pipe.
    channel_out = os.fdopen(os.dup(1), "w")
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    module_name, cls_name = sys.argv[1].split(":")
    agent_cls = getattr(importlib.import_module(module_name), cls_name)
    boot = json.loads(sys.stdin.readline())["boot"]
    api = Sys(sys.stdin, channel_out)
    try:
        checkpoint = api.call("checkpoint.load")["result"]["state"]
        result = agent_cls(api, boot).run(checkpoint)
        api.call("agent.exit", status="completed", result=result)
    except SyscallFailed as e:
        api.call("agent.exit", status="failed", reason=str(e),
                 result={"error": e.error, "op": e.op})
    except Exception as e:  # agent logic bug: report failure (crashes are signals, not exceptions)
        traceback.print_exc()
        api.call("agent.exit", status="failed", reason=repr(e))


if __name__ == "__main__":
    main()
