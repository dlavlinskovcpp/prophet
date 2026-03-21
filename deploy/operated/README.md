Non-local operated deployment templates live here.

Each environment directory contains:

- `docker-compose.yml`: a production-shaped stack for resolver registry, remote signer, oracle attester, and matching keeper
- `stack.env.example`: the single input file for public URLs, secrets, RPC/KMS settings, and runtime roots
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

The renderer writes:

- `.env` for Compose path substitution
- `oracle-attester.env`
- `remote-signer.env`
- `resolver-registry.env`
- `matching-keeper.env`

It also syncs `deploy/environments/<environment>.json` service endpoints so release manifests and bundles carry the real operated metadata for that environment.
