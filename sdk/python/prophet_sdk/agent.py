"""Small agent-facing orchestration facade.

It intentionally delegates transaction submission to an injected backend so
security-relevant resolver and signer policy configuration stays explicit.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol


@dataclass(frozen=True)
class ResolverConfig:
    resolver_id: str
    definition: Mapping[str, Any]
    required_verifiers: tuple[str, ...]
    threshold: int


@dataclass(frozen=True)
class MarketHandle:
    market_id: str
    market_pda: str
    question: str
    resolver: ResolverConfig


class AgentBackend(Protocol):
    def create_market(self, question: str, resolver: ResolverConfig) -> MarketHandle: ...
    def place_order(self, market: MarketHandle, owner: str, side: str, quantity: int, price_e8: int) -> Mapping[str, Any]: ...
    def match(self, market: MarketHandle) -> Mapping[str, Any]: ...
    def resolve(self, market: MarketHandle) -> Mapping[str, Any]: ...
    def redeem(self, market: MarketHandle, owner: str) -> Mapping[str, Any]: ...


class ProphetAgent:
    """Ergonomic surface for autonomous agents; no PDA or transaction fields leak."""
    def __init__(self, backend: AgentBackend):
        self._backend = backend

    def create_market(self, *, question: str, resolver: ResolverConfig) -> MarketHandle:
        return self._backend.create_market(question, resolver)

    def buy_yes(self, market: MarketHandle, *, agent_id: str, quantity: int, price_e8: int) -> Mapping[str, Any]:
        return self._backend.place_order(market, agent_id, "YES", quantity, price_e8)

    def buy_no(self, market: MarketHandle, *, agent_id: str, quantity: int, price_e8: int) -> Mapping[str, Any]:
        return self._backend.place_order(market, agent_id, "NO", quantity, price_e8)

    def match_orders(self, market: MarketHandle) -> Mapping[str, Any]:
        return self._backend.match(market)

    def resolve(self, market: MarketHandle) -> Mapping[str, Any]:
        return self._backend.resolve(market)

    def redeem(self, market: MarketHandle, *, agent_id: str) -> Mapping[str, Any]:
        return self._backend.redeem(market, agent_id)
