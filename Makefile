# Prophet v0.2 Operational Makefile

.PHONY: validator build deploy test reliability attester verifier-a-run verifier-b-run verifier-services-test coordinator-run coordinator-service-test remote-signer resolver-registry seed-resolver publish-resolver factory maker keeper keeper-example grafana ops-backup ops-restore ops-verify-restore ops-validate-alerts ops-drills localnet-up localnet-down clean zktls-audit release-plan release-bundle release-deploy render-operated operated-smoke operated-devnet signer-vault-bootstrap signer-kms-bootstrap signer-dry-run signer-allowlist security-review-bundle demo devnet-runtime-up devnet-runtime-status devnet-runtime-preflight devnet-runtime-logs devnet-runtime-down rc44-security-acceptance rc46-security-acceptance rc47-security-acceptance

validator:
	SOLANA_VERSION=3.1.10 bash scripts/localnet_start.sh

build:
	anchor build

deploy:
	anchor deploy --provider.cluster localnet

release-plan:
	# Usage: make release-plan ENV=devnet TAG=v0.2.3
	python3 scripts/release.py plan --environment $(ENV) --release-tag $(TAG)

release-bundle:
	# Usage: make release-bundle ENV=devnet TAG=v0.2.3
	python3 scripts/release.py bundle --environment $(ENV) --release-tag $(TAG)

release-deploy:
	# Usage: make release-deploy ENV=devnet TAG=v0.2.3
	python3 scripts/release.py deploy --environment $(ENV) --release-tag $(TAG)

security-review-bundle:
	# Usage: make security-review-bundle ENV=devnet TAG=v0.2.3 [OUT=/tmp/prophet-security-review]
	python3 scripts/security_review_bundle.py --environment $(ENV) $(if $(TAG),--release-tag $(TAG),) $(if $(OUT),--review-root $(OUT),)

render-operated:
	# Usage: cp deploy/operated/$(ENV)/stack.env.example deploy/operated/$(ENV)/stack.env && make render-operated ENV=$(ENV)
	python3 scripts/render_operated_stack.py --environment $(ENV) $(if $(VALUES),--values-file $(VALUES),) $(if $(OUT),--output-dir $(OUT),) $(if $(NO_SYNC_ENV_JSON),--skip-sync-env-json,) $(if $(GENERATE_SECRETS),--generate-secrets,)

operated-smoke:
	# Localtest-only fixed-role signer A/B proof; no generic signer or Vault credential inputs.
	cd apps/oracle-attester && poetry run python ../../scripts/operated_localnet_smoke.py $(if $(KEEP_ARTIFACTS),--keep-artifacts,)

operated-devnet:
	# Prerequisites: external fixed-role signer A/B services and externally issued role-local grants. This target never starts signers or reads signer/Vault/issuer credentials.
	# Usage: make operated-devnet ARGS="--authorization-request-file <request.json> --canonical-message-file <message.bin> --signer-a-endpoint <url> --signer-b-endpoint <url> --signer-a-id <id> --signer-b-id <id> --signer-a-public-key <pubkey> --signer-b-public-key <pubkey> --signer-a-grant-file <grant.json> --signer-b-grant-file <grant.json> --acceptance-run-id <32-lowercase-hex>"
	cd apps/oracle-attester && poetry run python ../../scripts/operated_devnet_smoke.py $(ARGS)

signer-vault-bootstrap:
	# Usage: make signer-vault-bootstrap ARGS="--vault-addr https://vault.example --key-name prophet-devnet-notary-01 --output-allowlist /tmp/signer_allowlist.txt --output-key-map /tmp/vault-transit-key-map.json"
	cd apps/oracle-attester && poetry install && poetry run python scripts/vault_transit_bootstrap.py $(ARGS)

signer-kms-bootstrap:
	# Usage: make signer-kms-bootstrap ARGS="--region us-east-1 --key-id alias/prophet-devnet-notary --output-allowlist /tmp/signer_allowlist.txt"
	cd apps/oracle-attester && poetry install && poetry run python scripts/kms_bootstrap.py $(ARGS)

signer-dry-run:
	# Usage: make signer-dry-run ARGS="--public-key <pubkey> backend" or make signer-dry-run ARGS="--public-key <pubkey> service --url https://signer.example/sign --api-key token"
	cd apps/oracle-attester && poetry install && poetry run python scripts/signer_dry_run.py $(ARGS)

signer-allowlist:
	# Usage: make signer-allowlist ARGS="--path /etc/prophet/devnet/signer_allowlist.txt show"
	cd apps/oracle-attester && poetry install && poetry run python scripts/manage_signer_allowlist.py $(ARGS)

test:
	anchor test

reliability:
	cargo test -p prophet --lib
	bash scripts/check_zktls.sh

rc44-security-acceptance:
	python3 scripts/validate_rc44_security_acceptance.py --run

rc46-security-acceptance:
	python3 scripts/validate_rc46_security_acceptance.py --run

rc47-security-acceptance:
	python3 scripts/validate_rc47_security_acceptance.py --run

demo:
	cd apps/oracle-attester && poetry run python ../../scripts/demo_agent_market.py
	cd apps/oracle-attester && poetry run python ../../scripts/demo_agent_market.py --conflict

clean:
	rm -rf target .anchor/test-ledger node_modules sdk/python/__pycache__

# --- Oracle Attester ---
attester:
	cd apps/oracle-attester && poetry install && poetry run uvicorn src.main:app --host 0.0.0.0 --port 8000

verifier-a-run:
	cd apps/oracle-attester && poetry install && poetry run uvicorn src.verifier_a_main:app --host $${VERIFIER_HOST:-127.0.0.1} --port $${VERIFIER_A_PORT:-8301}

verifier-b-run:
	cd apps/oracle-attester && poetry install && poetry run uvicorn src.verifier_b_main:app --host $${VERIFIER_HOST:-127.0.0.1} --port $${VERIFIER_B_PORT:-8302}

verifier-services-test:
	cd apps/oracle-attester && poetry run pytest -q tests/test_verifier_services.py

coordinator-run:
	cd apps/oracle-attester && poetry install && poetry run uvicorn src.coordinator_main:app --host $${COORDINATOR_HOST:-127.0.0.1} --port $${COORDINATOR_PORT:-8400}

coordinator-service-test:
	cd apps/oracle-attester && poetry run pytest -q tests/test_coordinator_service.py

remote-signer:
	@echo "remote-signer is retired for production; use independent fixed-role signer services."
	@false

resolver-registry:
	cd apps/oracle-attester && poetry install && poetry run uvicorn src.resolver_registry_main:app --host 0.0.0.0 --port 8200

seed-resolver:
	# Usage: make seed-resolver RESOLVER=path/to.json
	python3 scripts/seed_resolver.py $(RESOLVER) --store-dir apps/oracle-attester/resolver_store

publish-resolver:
	# Usage: make publish-resolver RESOLVER=path/to.json RESOLVER_REGISTRY_URL=http://127.0.0.1:8200/resolvers RESOLVER_REGISTRY_API_KEY=token
	python3 scripts/seed_resolver.py $(RESOLVER) --registry-url $(RESOLVER_REGISTRY_URL) --api-key $(RESOLVER_REGISTRY_API_KEY)

# --- Python SDK Agents ---
factory:
	# Usage: make factory RESOLVER=... QUOTE_MINT=... ORACLE=... COUNT=... OUT=...
	cd sdk/python && poetry run python examples/market_factory.py \
		--resolver-file $(RESOLVER) --quote-mint $(QUOTE_MINT) --oracle $(ORACLE) --count $(COUNT) --out $(OUT)

maker:
	# Usage: make maker MARKETS=markets.jsonl QUOTE_MINT=...
	cd sdk/python && poetry run python examples/market_maker_basic.py \
		--markets $(MARKETS) --quote-mint $(QUOTE_MINT)

keeper:
	# Usage: cp apps/matching-keeper/.env.example apps/matching-keeper/.env && make keeper
	cd apps/matching-keeper && poetry install && poetry run prophet-matching-keeper

grafana:
	docker compose -f docker-compose.localnet.yml up -d grafana

ops-backup:
	# Usage: make ops-backup [OUT=ops/backups/prophet-ops.tgz]
	bash scripts/ops_backup.sh $(OUT)

ops-restore:
	# Usage: make ops-restore ARCHIVE=ops/backups/prophet-ops.tgz [FORCE=--force]
	bash scripts/ops_restore.sh $(FORCE) $(ARCHIVE)

ops-verify-restore:
	python3 scripts/verify_ops_backup_restore.py

ops-validate-alerts:
	python3 scripts/validate_alert_rules.py

ops-drills:
	python3 scripts/verify_ops_backup_restore.py
	python3 scripts/validate_alert_rules.py

keeper-example:
	# Usage: make keeper-example MARKETS="m1 m2" WS_URL=ws://127.0.0.1:8900
	cd sdk/python && poetry run python examples/keeper_multi_market_logs.py \
		$(MARKETS) --ws-url $(WS_URL)

localnet-up:
	SOLANA_VERSION=3.1.10 BIND_ADDRESS=$${BIND_ADDRESS:-0.0.0.0} bash scripts/localnet_start.sh
	docker compose -f docker-compose.localnet.yml up -d resolver-registry matching-keeper prometheus grafana

localnet-down:
	docker compose -f docker-compose.localnet.yml down
	-bash scripts/localnet_stop.sh

zktls-audit:
	./scripts/check_zktls.sh

devnet-runtime-up:
	RUNTIME_ENV=$${RUNTIME_ENV:-/etc/prophet/public-devnet/runtime.env} python3 scripts/public_devnet_runtime_preflight.py
	docker compose --env-file $${RUNTIME_ENV:-/etc/prophet/public-devnet/runtime.env} -f deploy/operated/public-devnet/docker-compose.yml up -d

devnet-runtime-status:
	docker compose --env-file $${RUNTIME_ENV:-/etc/prophet/public-devnet/runtime.env} -f deploy/operated/public-devnet/docker-compose.yml ps

devnet-runtime-preflight:
	RUNTIME_ENV=$${RUNTIME_ENV:-/etc/prophet/public-devnet/runtime.env} python3 scripts/public_devnet_runtime_preflight.py

devnet-runtime-logs:
	docker compose --env-file $${RUNTIME_ENV:-/etc/prophet/public-devnet/runtime.env} -f deploy/operated/public-devnet/docker-compose.yml logs --tail=200

devnet-runtime-down:
	docker compose --env-file $${RUNTIME_ENV:-/etc/prophet/public-devnet/runtime.env} -f deploy/operated/public-devnet/docker-compose.yml down
