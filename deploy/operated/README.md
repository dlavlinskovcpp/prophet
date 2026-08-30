Non-local operated deployment templates live here.

Each environment directory contains:

- `docker-compose.yml`: a production-shaped stack for resolver registry, verifier A/B, coordinator, and matching keeper
- `stack.env.example`: the single input file for public URLs, secrets, RPC/signer-backend settings, and runtime roots
- `*.env.example`: service runtime templates that the renderer turns into concrete `*.env` files

The compose manifests assume:

- runtime state is stored under `PROPHET_RUNTIME_ROOT`
- secret files are stored under `PROPHET_SECRET_ROOT`
- public TLS or private ingress is handled outside the compose stack

Defaults:

- `PROPHET_RUNTIME_ROOT=/var/lib/prophet/<environment>`
- `PROPHET_SECRET_ROOT=/etc/prophet/<environment>`

Typical bring-up:

```bash
cd deploy/operated/devnet
cp stack.env.example stack.env
python3 ../../../scripts/render_operated_stack.py --environment devnet
docker compose up -d --build
```

The renderer writes only the active operated environment artifacts:

- `.env` for Compose path substitution
- `resolver-registry.env`
- `matching-keeper.env`

It also syncs `deploy/environments/<environment>.json` service endpoints so release manifests and bundles carry the real operated metadata for that environment.

The generic remote signer and direct attester settlement paths are retired. Production settlement uses the separate fixed-role A/B signer boundary behind the secure coordinator; no operator environment file or compose service accepts the retired generic signer settings.
