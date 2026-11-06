"""Bounded CDP request lifecycle reconstruction without retaining URLs or browser IDs.

CDP requestId is an ephemeral in-memory correlation key only. Redirect chains reuse
it; every redirected hop receives a new random public reference. No request body,
headers, raw URL, or Chrome requestId ever leaves this module.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from uuid import uuid4
from .policy import Scope, VALID_METHODS


@dataclass(frozen=True)
class RequestHop:
    authorized: bool
    route: str
    method: str
    reference: str
    chain: str
    hop: int


class RequestLedger:
    def __init__(self, scope: Scope, capacity: int = 4096):
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ValueError('capacity must be positive')
        self.scope = scope
        self.capacity = capacity
        self._active: OrderedDict[str, RequestHop] = OrderedDict()
        self.evictions = 0
        self.redirects = 0
        self.rejected = 0

    def begin(self, event: dict) -> tuple[RequestHop | None, RequestHop | None]:
        """Returns (old redirect hop, new hop); only approved metadata persists."""
        if not isinstance(event, dict):
            self.rejected += 1
            return None, None
        request = event.get('request') or {}
        request_id = event.get('requestId')
        if (not isinstance(request_id, str) or not request_id or len(request_id) > 256
                or not isinstance(request, dict)):
            self.rejected += 1
            return None, None
        # Validate the replacement before changing active state. Malformed events
        # must never erase a valid in-flight request.
        if not isinstance(request.get('url'), str) or not isinstance(request.get('method'), str):
            self.rejected += 1
            # Preserve the legacy caller contract (an unauthorized hop is
            # returned for diagnostic classification), without mutating an
            # existing valid in-flight request with the same identifier.
            invalid_hop = RequestHop(False, 'unclassified', 'GET',
                                     uuid4().hex, uuid4().hex, 0)
            if request_id not in self._active:
                self._active[request_id] = invalid_hop
                if len(self._active) > self.capacity:
                    self._active.popitem(last=False)
                    self.evictions += 1
            return None, invalid_hop
        previous = self._active.pop(request_id, None)
        redirected = previous if isinstance(event.get('redirectResponse'), dict) else None
        # Reuse can occur without redirect. Never merge unrelated operations.
        chain = previous.chain if redirected else uuid4().hex
        hop_number = previous.hop + 1 if redirected else 0
        url = request.get('url')
        method = request.get('method')
        authorized = self.scope.allowed(url) and isinstance(method, str) and method in VALID_METHODS
        hop = RequestHop(authorized, self.scope.category(url) or 'unclassified',
                         method if isinstance(method, str) and method in VALID_METHODS else 'GET',
                         uuid4().hex, chain, hop_number)
        self._active[request_id] = hop
        if redirected:
            self.redirects += 1
        if len(self._active) > self.capacity:
            self._active.popitem(last=False)
            self.evictions += 1
        return redirected, hop

    def get(self, request_id: object) -> RequestHop | None:
        if not isinstance(request_id, str) or len(request_id) > 256:
            return None
        return self._active.get(request_id)

    def finish(self, request_id: object) -> RequestHop | None:
        if not isinstance(request_id, str) or len(request_id) > 256:
            return None
        return self._active.pop(request_id, None)

    def reset(self) -> None:
        self._active.clear()

    def __len__(self) -> int:
        return len(self._active)
