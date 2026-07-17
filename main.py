"""Repo-root shim — kept so `python main.py` still works from a clone.

The real entrypoint is the installed console script (`agentpay`), defined in
src/agentpay/main.py. Transport (stdio vs streamable-http) comes from .env.
"""

from agentpay.main import main

if __name__ == "__main__":
    main()
