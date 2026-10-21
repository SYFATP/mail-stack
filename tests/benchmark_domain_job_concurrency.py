"""Offline apply throughput benchmark; all provider responses are simulated."""
from concurrent.futures import ThreadPoolExecutor
import json
import time

from test_domain_job_concurrency import DomainConcurrencyTests


def measure(concurrency):
    case = DomainConcurrencyTests(methodName="runTest")
    case.fixture_domains = [f"bench-{number:02}.test" for number in range(16)]
    case.setUp()
    try:
        case.m.job_concurrency = concurrency
        jobs = [case.enqueue(name) for name in case.names]
        case.read_hook = lambda name: time.sleep(0.03)
        case.write_hook = lambda name: time.sleep(0.03)
        start = time.perf_counter()
        def drain():
            while case.m.run_once():
                pass
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [pool.submit(drain) for _ in range(concurrency)]
            for future in futures:
                future.result()
        elapsed = time.perf_counter() - start
        assert all(case.m.jobs.get(job["id"])["status"] == "succeeded" for job in jobs)
        assert case.sequence == 64
        return {"concurrency": concurrency, "domains": len(jobs), "confirmed_fixture_writes": case.sequence,
                "seconds": round(elapsed, 4), "provider_network_calls": 0}
    finally:
        case.doCleanups()


if __name__ == "__main__":
    serial = measure(1)
    parallel = measure(2)
    report = {"serial": serial, "parallel": parallel,
              "speedup": round(serial["seconds"] / parallel["seconds"], 3)}
    try:
        import resource
        report["process_peak_rss_MiB"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 2)
    except ImportError:
        pass
    print(json.dumps(report))
