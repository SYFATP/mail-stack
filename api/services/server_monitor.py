"""Cached system-visible CPU, memory and data-partition usage, without agents."""
from __future__ import annotations

import copy
import ctypes
import os
from pathlib import Path
import shutil
import sys
import threading
import time

from pydantic import BaseModel, ConfigDict, Field, model_validator

SAMPLE_INTERVAL = 5.0
DEFAULT_THRESHOLDS = {
    "cpu": {"warning": 80, "critical": 95},
    "memory": {"warning": 80, "critical": 95},
    "disk": {"warning": 90, "critical": 95},
}


class Threshold(BaseModel):
    model_config = ConfigDict(extra="forbid")
    warning: float = Field(ge=0, le=100, allow_inf_nan=False, strict=True)
    critical: float = Field(gt=0, le=100, allow_inf_nan=False, strict=True)

    @model_validator(mode="after")
    def ordered(self):
        if self.warning >= self.critical:
            raise ValueError("黄色阈值必须小于红色阈值")
        return self


class MonitorThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cpu: Threshold
    memory: Threshold
    disk: Threshold


class ServerMonitor:
    def __init__(self, data_path: Path = Path("/app-data"), proc_root: Path = Path("/proc")):
        self.data_path = data_path
        self.proc_root = proc_root
        self._lock = threading.Lock()
        self._cached = None
        self._cached_at = float("-inf")
        self._previous_cpu = None
        self._previous_cpu_at = float("-inf")

    def _cpu_times(self):
        if sys.platform == "win32":
            from ctypes import wintypes
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            read = kernel32.GetSystemTimes
            read.argtypes = [ctypes.POINTER(wintypes.FILETIME)] * 3
            read.restype = wintypes.BOOL
            idle, kernel, user = (wintypes.FILETIME() for _ in range(3))
            if not read(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
                raise ctypes.WinError(ctypes.get_last_error())
            def ticks(value):
                return (value.dwHighDateTime << 32) | value.dwLowDateTime
            return ticks(kernel) + ticks(user), ticks(idle), os.cpu_count() or 1
        if not sys.platform.startswith("linux"):
            raise OSError("unsupported_cpu_platform")
        lines = (self.proc_root / "stat").read_text(encoding="ascii").splitlines()
        fields = lines[0].split()
        if fields[0] != "cpu" or len(fields) < 5:
            raise ValueError("invalid_cpu_counters")
        # guest/guest_nice are included in user/nice; don't count them twice.
        counters = [int(value) for value in fields[1:9]]
        cores = sum(line.split()[0][3:].isdigit() for line in lines if line.startswith("cpu"))
        return sum(counters), counters[3] + (counters[4] if len(counters) > 4 else 0), cores or 1

    def _cpu(self):
        total, idle, cores = self._cpu_times()
        if self._previous_cpu is None or time.monotonic() - self._previous_cpu_at > SAMPLE_INTERVAL * 3:
            self._previous_cpu = (total, idle)
            # Sync endpoints run in FastAPI's threadpool, never on the ASGI loop.
            time.sleep(0.1)
            total, idle, cores = self._cpu_times()
        previous_total, previous_idle = self._previous_cpu
        self._previous_cpu = (total, idle)
        self._previous_cpu_at = time.monotonic()
        elapsed, idle_elapsed = total - previous_total, idle - previous_idle
        if elapsed <= 0 or idle_elapsed < 0 or idle_elapsed > elapsed:
            return {"percent": None, "cores": cores, "error": "等待下一次 CPU 采样"}
        return {"percent": round(100 * (elapsed - idle_elapsed) / elapsed, 1), "cores": cores}

    def _memory(self):
        if sys.platform == "win32":
            from ctypes import wintypes
            class MemoryStatus(ctypes.Structure):
                _fields_ = [("length", wintypes.DWORD), ("load", wintypes.DWORD)] + [
                    (name, ctypes.c_ulonglong) for name in (
                        "total_phys", "avail_phys", "total_page", "avail_page",
                        "total_virtual", "avail_virtual", "avail_extended",
                    )
                ]
            status = MemoryStatus()
            status.length = ctypes.sizeof(status)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            read = kernel32.GlobalMemoryStatusEx
            read.argtypes = [ctypes.POINTER(MemoryStatus)]
            read.restype = wintypes.BOOL
            if not read(ctypes.byref(status)):
                raise ctypes.WinError(ctypes.get_last_error())
            total, available = status.total_phys, status.avail_phys
        elif sys.platform.startswith("linux"):
            values = {}
            for line in (self.proc_root / "meminfo").read_text(encoding="ascii").splitlines():
                name, value = line.split(":", 1)
                values[name] = int(value.split()[0]) * 1024
            total = values["MemTotal"]
            available = values.get("MemAvailable")
            if available is None:
                available = sum(values.get(key, 0) for key in ("MemFree", "Buffers", "Cached", "SReclaimable"))
                available -= values.get("Shmem", 0)
        else:
            raise OSError("unsupported_memory_platform")
        if total <= 0:
            raise ValueError("invalid_memory_total")
        available = max(0, min(total, available))
        return {"percent": round((total - available) * 100 / total, 1),
                "total": total, "used": total - available, "available": available}

    def _disk(self):
        path = self.data_path.resolve()
        usage = shutil.disk_usage(path)
        usable = usage.used + usage.free
        if usable <= 0:
            raise ValueError("invalid_disk_total")
        # Like df, reserved filesystem blocks are excluded from usable capacity.
        return {"percent": round(usage.used * 100 / usable, 1), "total": usage.total,
                "used": usage.used, "available": usage.free, "path": str(path)}

    def snapshot(self):
        # One shared sample per process even when many dashboards poll together.
        with self._lock:
            if self._cached is None or time.monotonic() - self._cached_at >= SAMPLE_INTERVAL:
                result = {}
                for key, read in (("cpu", self._cpu), ("memory", self._memory), ("disk", self._disk)):
                    try:
                        result[key] = read()
                    except (OSError, ValueError, KeyError, IndexError):
                        result[key] = {"percent": None, "error": "暂未取得系统指标"}
                result.update(sampled_at=time.time(), sample_interval_seconds=SAMPLE_INTERVAL,
                              platform=sys.platform, scope="system-visible",
                              scope_label="CPU、内存：API 运行环境可见的系统总量；磁盘：数据目录所在分区。")
                self._cached = result
                self._cached_at = time.monotonic()
            result = copy.deepcopy(self._cached)
            result["sample_age_seconds"] = max(0, time.monotonic() - self._cached_at)
            return result
