"""Small in-memory job queue. Users submit and get a live position instead of blocking."""
import asyncio
import logging
import math
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, List

logger = logging.getLogger(__name__)


@dataclass(eq=False)
class Job:
    run: Callable[["Job"], Awaitable[None]]       # the work, receives the job itself
    set_status: Callable[[str], Awaitable[None]]  # edits the user's status message
    shown_pos: int = 0
    started: float = 0.0


class JobQueue:
    def __init__(self, workers: int = 3):
        self.workers = max(1, workers)
        self.waiting: List[Job] = []
        self.running: set = set()
        self._avg = 25.0                           # moving average of job duration (seconds)
        self._queue = None
        self._tasks: list = []
        self._refresh_lock = None

    # -- lifecycle (lazy, so it binds to the running event loop)
    def _ensure_started(self):
        if self._queue is not None:
            return
        self._queue = asyncio.Queue()
        self._refresh_lock = asyncio.Lock()
        self._tasks = [asyncio.create_task(self._worker()) for _ in range(self.workers)]

    # -- public api
    def submit(self, job: Job) -> int:
        """Add a job. Returns its queue position (0 = starts right away)."""
        self._ensure_started()
        self.waiting.append(job)
        self._queue.put_nowait(job)
        return self._position(job)

    def queued_text(self, pos: int) -> str:
        eta = int(math.ceil(pos / self.workers) * self._avg)
        return (f"📥 <b>Queued</b> · #{pos}\n"
                f"<i>~{eta}s wait · {len(self.running)}/{self.workers} workers busy</i>")

    def snapshot(self) -> str:
        return f"{len(self.running)}/{self.workers} running · {len(self.waiting)} waiting"

    # -- internals
    def _free(self) -> int:
        return self.workers - len(self.running)

    def _position(self, job: Job) -> int:
        try:
            idx = self.waiting.index(job)
        except ValueError:
            return 0
        return max(0, idx + 1 - self._free())

    async def _refresh(self):
        """Push updated positions to everyone still waiting (throttled to avoid flood limits)."""
        async with self._refresh_lock:
            for job in list(self.waiting):
                pos = self._position(job)
                if pos > 0 and pos != job.shown_pos:
                    job.shown_pos = pos
                    try:
                        await job.set_status(self.queued_text(pos))
                    except Exception as exc:
                        logger.debug("queue status update failed: %s", exc)
                    await asyncio.sleep(0.4)

    async def _worker(self):
        while True:
            job = await self._queue.get()
            if job in self.waiting:
                self.waiting.remove(job)
            self.running.add(job)
            job.started = time.monotonic()
            asyncio.create_task(self._refresh())
            try:
                await job.run(job)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Job crashed")
            finally:
                duration = time.monotonic() - job.started
                self._avg = 0.7 * self._avg + 0.3 * duration
                self.running.discard(job)
                self._queue.task_done()
