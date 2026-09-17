# CTF Copilot (VMI CyberFusion 26)

CTF Copilot is a local web app for running CTF workflows with Docker-backed challenge containers, persistent per-challenge workspaces, and an optional AI agent.

## What You Get

- React/Vite operator workspace UI
- Persistent per-challenge workspace mounted into `/ctf/`
- Durable event log + notes capture per challenge
- Rich target metadata for remote instances, proxies, credentials, and source metadata
- Per-challenge Docker runtime with optional AI solve assistant
- Bulk challenge import/export
- Writeup generation after flag approval

## Prerequisites

- Python 3.10+
- Docker Desktop (or Docker Engine) running
- Internet access for first Docker image build

## Quick Start (Recommended)

1. Install backend dependencies:

```bash
pip install -r requirements.txt
```

2. Install frontend dependencies:

```bash
cd frontend
npm install
```

3. Build the frontend bundle:

```bash
npm run build
cd ..
```

4. Start the app:

```bash
python server.py
```

5. Open:

`http://localhost:7331`

6. In the UI, open **Settings** and add your API key.

7. Click **Build Image** once.

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

1. Click **New Challenge** or import a JSON challenge pack
2. Fill in metadata, tags, target config, source metadata, and credentials
3. Upload files into the persistent workspace
4. Launch the agent or open the manual shell
5. Capture notes/evidence as you go
6. Review candidate flags and approve/reject them
7. On approval, a markdown writeup is generated

## Manual Mode

Use **Manual Shell** in challenge view to start a container-backed shell without launching the agent.

Useful direct attach command:

```bash
docker exec -it ctf-agent-<challenge_id> bash
```

Live log inside container:

```bash
tail -n 120 -f /ctf/.agent_live.log
```

Notes captured by the UI/agent are stored under `runs/<challenge_id>/notes.md`.

Event logs are stored under `runs/<challenge_id>/events.jsonl`.

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

## Agent Control Improvements

The agent now uses an AIRecon-inspired soft phase model tailored for CTFs:
`recon -> analyze -> exploit -> verify -> report`.

- Phase guidance is soft. The model is guided toward the right tool mix, but tools are not hard-blocked by phase.
- Checkpoints run every 5 solver steps by default, self-evaluation runs every 10 steps, and context compression is considered every 15 steps.
- Per-challenge memory records phase history, checkpoint summaries, next best action, repeated no-progress count, and tool performance.
- Adaptive tool ranking reorders tool definitions using category, phase, and local success/error history so repeated dead ends are deprioritized.
- Launch readiness checks report missing API keys, missing model packages, LangGraph availability, Docker image state, and category tool availability.

These values can be adjusted in Settings or `config.json`:

```json
{
  "checkpoint_interval": 5,
  "self_eval_interval": 10,
  "context_compression_interval": 15,
  "adaptive_tool_ranking": true
}
```

Reference repo used for these takeaways: `https://github.com/pikpikcu/airecon`.
When cloned locally, it should live under `_reference/airecon/`; `_reference/` is ignored by git.

## Troubleshooting

- `Docker not running`: start Docker Desktop/Engine.
- `Build required before launch`: run **Build Image** in UI.
- Agent errors about missing key: set API key in Settings and save.
- Files, scripts, and extracted artifacts live in `workspaces/<challenge_id>/` and are bind-mounted into `/ctf/`.

## Notes

- Max upload size: `256MB`
- Docker image tag: `ctf-kali:latest`
- Main app entrypoint: `server.py`
- Frontend source: `frontend/`
