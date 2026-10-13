"""Test-only agent that reports what an agent process can see of its environment."""

import os

from agenticos.sdk import Agent


class EnvProbe(Agent):
    def run(self, cp):
        return {"env": sorted(os.environ), "fds": sorted(os.listdir("/dev/fd"))}
