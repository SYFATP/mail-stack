"""Single-process bounded I/O workers; interrupted operations are never replayed."""
import logging
import threading
import time
from api.services.readiness_refresh import ReadinessRefresh

logger = logging.getLogger("domain-jobs")


class DomainWorker:
    def __init__(self, manager):
        self.manager = manager
        self.stop_event = threading.Event()
        self.thread = None
        self.threads = []
        self._lifecycle_lock = threading.Lock()
        self.readiness = ReadinessRefresh(manager)

    def start(self):
        with self._lifecycle_lock:
            if any(thread.is_alive() for thread in self.threads):
                return
            self.manager.jobs.recover_interrupted()
            self.stop_event.clear()
            self.threads = [
                threading.Thread(target=self._run, daemon=True, name=f"domain-jobs-{number + 1}")
                for number in range(self.manager.job_concurrency)
            ]
            self.thread = self.threads[0]
            for thread in self.threads:
                thread.start()

    def stop(self):
        with self._lifecycle_lock:
            self.stop_event.set()
            deadline = time.monotonic() + 25
            for thread in self.threads:
                thread.join(timeout=max(0, deadline - time.monotonic()))

    def status(self):
        return {"concurrency": self.manager.job_concurrency,
                "threads_alive": sum(thread.is_alive() for thread in self.threads),
                "stopping": self.stop_event.is_set()}

    def _run(self):
        while not self.stop_event.is_set():
            try:
                self.readiness.tick()
            except Exception:
                # Readiness failures do not kill the worker or replay writes.
                logger.error("readiness scheduler unavailable")
            try:
                worked = self.manager.run_once()
            except Exception:
                logger.error("domain worker ledger unavailable")  # No upstream/secret exception text.
                worked = False
            if not worked:
                self.stop_event.wait(1)
