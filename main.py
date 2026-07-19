"""Repo-root shim — kept so `python main.py` still works from a clone.

The real entrypoint is the installed console script (`imprest`), defined in
src/imprest/main.py. Transport (stdio vs streamable-http) comes from .env.
"""

from imprest.main import main

if __name__ == "__main__":
    main()
