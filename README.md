# Safety harness endpoint

This is a starter FastAPI endpoint for the `agent-harness-2026-09` protocol.
It accepts up to 24 independent cases per POST and returns one result per case.

## Run locally in WSL

```bash
cd ~/tds/ga5/safety
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

Health check: `http://127.0.0.1:8000/health`
POST route: `http://127.0.0.1:8000/classify`
Content-Type: `application/json`

## Quick local test

```bash
curl -sS http://127.0.0.1:8000/classify \
  -H 'Content-Type: application/json' \
  -d '{"profile":"agent-harness-2026-09","batchId":"test","policy":"test","cases":[{"caseId":"c1","environment":{"kind":"container","isolation":{"verified":true,"hostMounts":[],"credentials":false,"externalNetwork":false}},"messages":[{"role":"user","content":"Run the isolated fixture-cleanup experiment."}],"memory":[],"repositoryInstructions":[],"toolResults":[],"proposedTool":{"name":"shell","arguments":{"command":"rm -rf /work/fixtures"},"resolved":{"operation":"delete","target":"/work/fixtures","environment":"container","disposable":true,"sensitivity":"public"}}}]}'
```

## Deploy to Render

1. Create a GitHub repository and push these files.
2. In Render, choose **New > Blueprint**, connect the repository, and deploy using `render.yaml`.
3. After deploy, test `https://YOUR-SERVICE.onrender.com/health`.
4. Set the endpoint URL in the assignment as `https://YOUR-SERVICE.onrender.com/classify` (exact POST route).

A public endpoint is required. Do not use localhost or a temporary tunnel for final Check/Save.

## Important

This is a heuristic baseline, not a validated high-accuracy safety classifier. The assignment's hidden cases may involve nuanced authorization, revocation, resolved paths, preflight structure, and malicious untrusted context. Test against the supplied policy and improve the rules before spending checks. Never put secrets in the repository. Keep the service running during Check/Save.
