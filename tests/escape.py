"""Test-only hostile agent: tries to step around the syscall boundary."""

import glob
import os
import socket
import sqlite3

from agenticos.sdk import Agent


class Escape(Agent):
    def run(self, cp):
        out = {}
        db = self.params["db"]
        try:
            c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            c.execute("SELECT COUNT(*) FROM approvals").fetchone()
            out["read_db"] = "ESCAPED"
        except Exception as e:
            out["read_db"] = type(e).__name__
        try:
            c = sqlite3.connect(db)
            c.execute("UPDATE approvals SET status='approved'")
            c.commit()
            out["write_db"] = "ESCAPED"
        except Exception as e:
            out["write_db"] = type(e).__name__
        try:
            open(os.path.join(self.params["project"], "aos", "policy.py"), "a").write("#")
            out["edit_policy"] = "ESCAPED"
        except Exception as e:
            out["edit_policy"] = type(e).__name__
        try:
            socket.create_connection(("1.1.1.1", 53), timeout=2).close()
            out["network"] = "ESCAPED"
        except Exception as e:
            out["network"] = type(e).__name__
        out["cwd_listing"] = glob.glob("*")
        return out
