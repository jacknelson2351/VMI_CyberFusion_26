# VMI CyberFusion 26

Small Flask + Socket.IO app for running CTF challenge workflows with Docker.

## What this is

- Web UI + API for challenge tracking
- Docker-backed challenge runtime
- Optional OpenAI-powered solving agent

## Quick start

1. Install Python deps:

```bash
pip install -r requirements.txt
```

2. Make sure Docker is running.

3. Put your OpenAI key in `config.json`:

```json
{
  "openai_api_key": "your-key-here"
}
```

4. Start the server:

```bash
python3 server.py
```

5. Open:

`http://localhost:7331`

## Notes

- Max upload size is `256MB`.
- The app uses `Dockerfile` to build the challenge image (`ctf-kali:latest`).
- Main app entrypoint is `server.py`.

## Debugging Agent Loop (Detailed)

The agent now emits structured `loop_trace` events for each run/step/tool phase.

To summarize a challenge timeline from a running server:

```bash
python scripts/explain_loop_trace.py --cid <challenge_id> --base-url http://127.0.0.1:7331
```

Or from a saved logs JSON file:

```bash
python scripts/explain_loop_trace.py --file logs.json
```

## Manual Docker CLI Control

If the agent is underperforming, you can attach to the same challenge container and intervene manually.

Open shell + live watcher together:

```bash
python scripts/container_cli.py <challenge_id> --both
```

If the container is not running yet, start it without launching the agent:

```bash
python scripts/container_cli.py <challenge_id> --both --start
```

In the web UI, use **Run Manually** to start the challenge container without launching the agent and open a native OS terminal attached to it.
This supports Windows, macOS, and Linux (with terminal-emulator fallbacks).

```bash
docker exec -it ctf-agent-<challenge_id> bash
```

Only shell:

```bash
python scripts/container_cli.py <challenge_id> --shell
```

Only live watch:

```bash
python scripts/container_cli.py <challenge_id> --watch
```

The agent now writes a live stream to `/ctf/.agent_live.log`, so while attached you can watch:

```bash
tail -n 120 -f /ctf/.agent_live.log
```
