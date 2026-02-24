# CTF Copilot (VMI CyberFusion 26)

CTF Copilot is a local web app for running CTF workflows with Docker-backed challenge containers and an optional AI agent.

## What You Get

- Challenge dashboard (create, edit, track solve state)
- Per-challenge Docker runtime
- File uploads into `/ctf/`
- Optional AI solve assistant (OpenAI or Anthropic key)
- Writeup generation after flag approval

## Prerequisites

- Python 3.10+
- Docker Desktop (or Docker Engine) running
- Internet access for first Docker image build

## Quick Start (Recommended)

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Start the app:

```bash
python server.py
```

3. Open:

`http://localhost:7331`

4. In the UI, open **Settings** and add your API key.

5. Click **Build Image** once.

Important: the agent cannot launch until image build finishes successfully.

## How to Get an API Key

### OpenAI Key

1. Go to: `https://platform.openai.com/`
2. Sign in and open API keys.
3. Create a new secret key.
4. Copy it and paste into CTF Copilot Settings under **OPENAI API KEY**.

### Anthropic Key

1. Go to: `https://console.anthropic.com/`
2. Sign in and open API keys.
3. Create a new key.
4. Copy it and paste into CTF Copilot Settings under **ANTHROPIC API KEY**.

## API Key Setup Options

### Option A: In App (best)

- Open **Settings** in the top bar.
- Paste key(s).
- Save.

### Option B: `config.json`

You can also set keys directly:

```json
{
  "openai_api_key": "sk-...",
  "anthropic_api_key": "sk-ant-..."
}
```

Then restart the server.

## First Challenge Flow

1. Click **+ New Challenge**
2. Fill in name, category, optional flag format, and description
3. Open the challenge card
4. Upload files
5. Launch agent or run manually
6. When a flag is found, review and approve/reject
7. On approval, container is cleaned up and writeup is generated

## Manual Mode

Use **Run Manually** in challenge view to start container without launching the agent.

Useful direct attach command:

```bash
docker exec -it ctf-agent-<challenge_id> bash
```

Live log inside container:

```bash
tail -n 120 -f /ctf/.agent_live.log
```

## Useful Scripts

Loop trace summary:

```bash
python scripts/explain_loop_trace.py --cid <challenge_id> --base-url http://127.0.0.1:7331
```

Or from file:

```bash
python scripts/explain_loop_trace.py --file logs.json
```

Container helper:

```bash
python scripts/container_cli.py <challenge_id> --both
```

## Troubleshooting

- `Docker not running`: start Docker Desktop/Engine.
- `Build required before launch`: run **Build Image** in UI.
- Agent errors about missing key: set API key in Settings and save.
- Upload worked but not in container yet: launch/run manual first; files sync to active container.

## Notes

- Max upload size: `256MB`
- Docker image tag: `ctf-kali:latest`
- Main app entrypoint: `server.py`
