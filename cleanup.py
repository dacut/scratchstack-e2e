#!/usr/bin/env python3
"""
Run the sweeper from a checkout, as `./cleanup.py`.

The implementation lives in scratchstack_e2e.sweep, because a console script
can only name a module inside the package -- a file at the repo root is not
shipped by the src layout and so could never back the `scratchstack-e2e-sweep`
entry point. This keeps the invocation that predates that entry point working,
and takes no arguments of its own: everything is forwarded by virtue of sharing
the same main().

Equivalent to `scratchstack-e2e-sweep` and to
`python -m scratchstack_e2e.sweep`. Requires the virtualenv to be active, as it
always did, since the shebang resolves python3 from PATH.
"""

from scratchstack_e2e.sweep import main

if __name__ == "__main__":
    main()
