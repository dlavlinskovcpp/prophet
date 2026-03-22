# Prophet v0.2 Operational Makefile

.PHONY: validator build deploy test reliability attester remote-signer resolver-registry seed-resolver publish-resolver factory maker keeper keeper-example grafana ops-backup ops-restore ops-verify-restore ops-validate-alerts ops-drills localnet-up localnet-down clean zktls-audit release-plan release-bundle release-deploy render-operated operated-smoke signer-kms-bootstrap signer-dry-run signer-allowlist security-review-bundle

validator:
	@mkdir -p .anchor/test-ledger
	solana-test-validator --reset --rpc-port 8899  --ledger .anchor/test-ledger

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
	# Usage: make operated-smoke [RPC_URL=http://127.0.0.1:8899] [PROPHET_PROGRAM_ID=<program id>]
	python3 scripts/operated_localnet_smoke.py $(if $(RPC_URL),--rpc-url $(RPC_URL),) $(if $(PROPHET_PROGRAM_ID),--program-id $(PROPHET_PROGRAM_ID),) $(if $(QUOTE_MINT),--quote-mint $(QUOTE_MINT),) $(if $(KEEP_ARTIFACTS),--keep-artifacts,)

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

clean:
	rm -rf target .anchor/test-ledger node_modules sdk/python/__pycache__

# --- Oracle Attester ---
attester:
	cd apps/oracle-attester && poetry install && poetry run uvicorn src.main:app --host 0.0.0.0 --port 8000

remote-signer:
	cd apps/oracle-attester && poetry install && poetry run uvicorn src.remote_signer_main:app --host 0.0.0.0 --port 8100

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
	docker-compose -f docker-compose.localnet.yml up -d grafana

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
	docker-compose -f docker-compose.localnet.yml up -d validator resolver-registry remote-signer oracle-attester matching-keeper prometheus grafana

localnet-down:
	docker-compose -f docker-compose.localnet.yml down

zktls-audit:
	./scripts/check_zktls.sh
