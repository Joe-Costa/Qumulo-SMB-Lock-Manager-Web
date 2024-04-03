# Qumulo SMB Lock Manager Web UI

** Beta **

Two options are available:

`main.py` which can be run via `gunicorn` with `gunicorn --config gunicorn_config.py main:app`

and `async_main.py`, which uses asyncio and aiohttp for some functions and "may" provide some performance benefits with user name resolution.

Run it with: `hypercorn async_main:app --workers 4 --bind 127.0.0.1:4000`

Note that the async version is considerably different and uses Quart instead of Flask, so check your dependencies.

Both require a running Redis Server instance.

Note that `async_main.py` has been receiving the most attention and is likely to be the final method used.