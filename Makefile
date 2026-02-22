# Prophet v0.2 Operational Makefile

.PHONY: validator build deploy test attester seed-resolver factory maker keeper clean zktls-audit

validator:
	@mkdir -p .anchor/test-ledger
	COPYFILE_DISABLE=1 solana-test-validator --reset \
		--ledger .anchor/test-ledger \
		--bind-address 127.0.0.1 \
		--rpc-port 8899 \
		--faucet-port 9901 \
		--gossip-port 10256 \
		--dynamic-port-range 10240-10300

build:
	anchor build

deploy:
	anchor deploy --provider.cluster localnet

test:
	anchor test

clean:
	rm -rf target .anchor/test-ledger node_modules sdk/python/__pycache__

# --- Oracle Attester ---
attester:
	cd apps/oracle-attester && poetry install && poetry run uvicorn src.main:app --host 0.0.0.0 --port 8000

seed-resolver:
	# Usage: make seed-resolver RESOLVER=path/to.json
	python3 scripts/seed_resolver.py $(RESOLVER) --store-dir apps/oracle-attester/resolver_store

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
	# Usage: make keeper MARKETS="m1 m2" WS_URL=ws://127.0.0.1:8900
	cd sdk/python && poetry run python examples/keeper_multi_market_logs.py \
		$(MARKETS) --ws-url $(WS_URL)

zktls-audit:
	./scripts/check_zktls.sh
