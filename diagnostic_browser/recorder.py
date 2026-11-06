"""Bounded, durable, fail-closed diagnostic flight recorder.

No raw CDP objects enter memory queues or persistence. Lost observations are
accounted for without storing unsafe exception messages or event payloads.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime, timezone
from .policy import normalize, UnsafeEvent
from .store import EvidenceStore


class Recorder:
    def __init__(self, store: EvidenceStore, max_queue: int = 2048,
                 auto_incident: bool = True):
        self.store = store
        self.queue: asyncio.Queue[tuple] = asyncio.Queue(maxsize=max_queue)
        self.stats: Counter = Counter()
        self.task: asyncio.Task | None = None
        self.maintenance_task: asyncio.Task | None = None
        self.auto_incident = auto_incident
        self.last_auto: datetime | None = None
        self.last_commit_utc: str | None = None
        self.status = 'INITIALIZING'

    async def start(self) -> None:
        if self.task is not None:
            raise RuntimeError('recorder already started')
        self.task = asyncio.create_task(self._writer(), name='encrypted-evidence-writer')
        self.maintenance_task = asyncio.create_task(self._maintenance(), name='evidence-retention-maintenance')
        self.status = 'ARMED'

    async def _maintenance(self) -> None:
        # Retention must continue even when an IT diagnostic session is idle;
        # otherwise old unpreserved events remain on disk indefinitely.
        while True:
            await asyncio.sleep(60)
            try:
                self.store.prune()
                self.stats['maintenance_checks'] += 1
            except Exception:
                self.stats['maintenance_failures'] += 1
                self.status = 'DEGRADED'

    def _loss(self, reason: str) -> None:
        try:
            self.store.record_loss(reason)
        except Exception:
            # A failed ledger is reported as an unverifiable loss count;
            # never log raw database exceptions (which may include evidence).
            self.stats['unpersisted_loss_notices'] += 1

    def accept(self, kind: str, severity: str, fields: dict, observed_at: datetime | None = None) -> bool:
        try:
            validated = normalize(kind, severity, fields)
        except (UnsafeEvent, TypeError, ValueError):
            self.stats['privacy_rejected'] += 1
            return False
        if self.task is None or self.task.done() or self.status in ('STOPPED', 'FAILED'):
            self.stats['inactive_rejected'] += 1
            self.status = 'DEGRADED' if self.task and not self.task.done() else 'FAILED'
            self._loss('WRITE_FAILED')
            return False
        try:
            # Timestamp at observation, not eventual SQLite commit. Backpressure
            # and transient disk failures must not falsify incident chronology.
            self.queue.put_nowait((*validated, observed_at or datetime.now(timezone.utc), None, None))
            self.stats['accepted'] += 1
            return True
        except asyncio.QueueFull:
            self.stats['queue_full'] += 1
            self.status = 'DEGRADED'
            self._loss('QUEUE_FULL')
            return False

    async def ingest_confirmed(self, kind: str, severity: str, fields: dict,
                               observed_at: datetime, event_id: str) -> bool:
        """Return only after SQLCipher has committed a host event.

        Event ID is stable across IPC retries, preventing duplicate evidence.
        A broken or saturated collector never sends a false-success receipt.
        """
        validated = normalize(kind, severity, fields)
        if not self.task or self.task.done() or self.status in ('STOPPED', 'FAILED'):
            raise OSError('recorder writer unavailable')
        if not isinstance(observed_at, datetime) or observed_at.tzinfo is None:
            raise ValueError('observation time must be timezone aware')
        future = asyncio.get_running_loop().create_future()
        try:
            self.queue.put_nowait((*validated, observed_at, future, event_id))
        except asyncio.QueueFull as exc:
            self.stats['queue_full'] += 1
            self._loss('QUEUE_FULL')
            self.status = 'DEGRADED'
            raise OSError('collector queue full') from exc
        await future
        return True

    async def _writer(self) -> None:
        self.status = 'RECORDING'
        while True:
            item = await self.queue.get()
            try:
                kind, severity, fields, observed_at, receipt, event_id = item
                persisted = False
                for attempt in range(3):
                    try:
                        self.store.add(kind, severity, fields, observed_at=observed_at, event_id=event_id)
                        persisted = True
                        if attempt:
                            self.stats['recovered_writes'] += 1
                        break
                    except Exception:
                        self.stats['write_attempt_failures'] += 1
                        if attempt != 2:
                            await asyncio.sleep(0.05 * (2 ** attempt))
                if persisted:
                    self.stats['committed'] += 1
                    self.last_commit_utc = datetime.now(timezone.utc).isoformat()
                    if self.auto_incident and severity in ('error', 'critical'):
                        now = datetime.now(timezone.utc)
                        if self.last_auto is None or (now - self.last_auto).total_seconds() > 60:
                            try:
                                self.store.mark('automatic', observed_at=observed_at)
                                self.last_auto = now
                            except Exception:
                                self.stats['incident_mark_failure'] += 1
                                self.status = 'DEGRADED'
                    if self.stats['committed'] % 200 == 0:
                        try:
                            self.store.prune()
                        except Exception:
                            self.stats['prune_failure'] += 1
                            self.status = 'DEGRADED'
                else:
                    self.stats['lost_events'] += 1
                    self.status = 'DEGRADED'
                    self._loss('WRITE_FAILED')
                if receipt is not None and not receipt.done():
                    if persisted:
                        receipt.set_result(True)
                    else:
                        receipt.set_exception(OSError('host evidence could not be committed'))
            finally:
                self.queue.task_done()

    async def flush(self, timeout: float = 15.0, strict: bool = False) -> None:
        if not self.task or self.task.done():
            raise RuntimeError('recorder writer unavailable')
        await asyncio.wait_for(self.queue.join(), timeout=timeout)
        if strict and self.stats['lost_events']:
            raise OSError('recorder lost evidence due to unrecoverable storage errors')

    async def stop(self) -> None:
        try:
            if self.task:
                try:
                    await self.flush()
                finally:
                    self.task.cancel()
                    try:
                        await self.task
                    except asyncio.CancelledError:
                        pass
        finally:
            if self.maintenance_task is not None:
                self.maintenance_task.cancel()
                try:
                    await self.maintenance_task
                except asyncio.CancelledError:
                    pass
                self.maintenance_task = None
            self.status = 'STOPPED'

    def health(self) -> dict:
        alive = bool(self.task and not self.task.done())
        state = self.status if alive or self.status == 'STOPPED' else 'FAILED'
        if self.stats['lost_events'] or self.stats['queue_full']:
            if state == 'RECORDING':
                state = 'DEGRADED'
        return dict(state=state, queued=self.queue.qsize(), counts=dict(self.stats),
                    writer_running=alive, last_commit_utc=self.last_commit_utc,
                    evidence_gaps=self.stats['lost_events'] + self.stats['queue_full'],
                    active_capture_verified=False)
