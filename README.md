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
