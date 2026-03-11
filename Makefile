# Prophet v0.2 Operational Makefile

.PHONY: validator build deploy test reliability attester remote-signer resolver-registry seed-resolver publish-resolver factory maker keeper keeper-example grafana ops-backup ops-restore localnet-up localnet-down clean zktls-audit release-plan release-bundle release-deploy

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
