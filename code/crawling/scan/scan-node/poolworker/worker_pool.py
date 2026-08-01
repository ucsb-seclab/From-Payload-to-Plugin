import asyncio
import logging
import os
import re
import signal
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from .chrome_controller import ChromeController
from .job_logger import JobLogger
from .redis_task_source import RedisTaskSource

SCRIPT_DIR = Path(__file__).resolve().parent.parent
CHECK_SCRIPT = SCRIPT_DIR / "check.py"
CDPSCAN_SCRIPT = SCRIPT_DIR / "cdpscan.py"

__all__ = ["WorkerPool"]

def env_int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default

def env_bool(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}

class WorkerPool:
    def __init__(self):
        self.redis_host = os.getenv("REDIS_HOST", "redis")
        self.redis_port = env_int("REDIS_PORT", 6379)
        self.mount_point = Path(os.getenv("MOUNT_POINT", "/app/data"))
        self.event_root = self.mount_point / "event_data"
        self.event_root.mkdir(parents=True, exist_ok=True)

        self.chrome_port = env_int("CHROME_REMOTE_DEBUG_PORT", 9222)
        self.max_tabs = env_int("CONCURRENT_TABS", 5)
        self.check_timeout = env_int("CHECK_TIMEOUT_SECONDS", 150)
        self.scan_timeout = env_int("SCAN_TIMEOUT_SECONDS", 300)
        self.queue_sleep = env_int("QUEUE_IDLE_SLEEP_SECONDS", 5)
        self.chrome_headless = env_bool("CHROME_HEADLESS", False)

        self.chrome_log_path = self.mount_point / "logs" / "chrome.log"
        chrome_executable = os.getenv("CHROME_BINARY", "google-chrome-stable")
        self.chrome = ChromeController(
            chrome_executable,
            self.chrome_port,
            self.chrome_log_path,
            headless=self.chrome_headless,
        )

        self.redis_source = RedisTaskSource(self.redis_host, self.redis_port)
        self.job_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=self.max_tabs * 2)
        self.stop_event = asyncio.Event()
        self.worker_tasks: list[asyncio.Task] = []
        self.watchdog_task: Optional[asyncio.Task] = None
        self.queue_task: Optional[asyncio.Task] = None

    async def run(self):
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, self.request_stop)
        loop.add_signal_handler(signal.SIGTERM, self.request_stop)

        await self.chrome.ensure_browser()
        self.watchdog_task = asyncio.create_task(self.chrome.watchdog(self.stop_event))
        self.queue_task = asyncio.create_task(self._queue_poller())
        self.worker_tasks = [
            asyncio.create_task(self._worker_loop(slot))
            for slot in range(self.max_tabs)
        ]

        await self.stop_event.wait()
        logging.info("Stop requested, waiting for outstanding jobs to finish...")
        await self.job_queue.join()
        if self.queue_task:
            self.queue_task.cancel()
        for task in self.worker_tasks:
            task.cancel()
        if self.watchdog_task:
            self.watchdog_task.cancel()

        await self.redis_source.close()
        await self.chrome.shutdown()

    def request_stop(self):
        if not self.stop_event.is_set():
            logging.info("Received termination signal, shutting down...")
            self.stop_event.set()

    async def _queue_poller(self):
        try:
            while not self.stop_event.is_set():
                queue_name = await self.redis_source.next_queue()
                if not queue_name:
                    await asyncio.sleep(self.queue_sleep)
                    continue

                logging.info("Processing task queue %s", queue_name)
                idle_polls = 0
                while not self.stop_event.is_set():
                    job = await self.redis_source.pop_job(queue_name, timeout=5)
                    if job is None:
                        idle_polls += 1
                        if idle_polls >= 2:
                            logging.info("Queue %s drained, deleting.", queue_name)
                            await self.redis_source.delete_queue(queue_name)
                            break
                        continue
                    idle_polls = 0
                    await self.job_queue.put(job)
        except asyncio.CancelledError:
            logging.info("Queue poller cancelled.")
        except Exception as exc:
            logging.exception("Queue poller crashed: %s", exc)
            self.request_stop()

    async def _worker_loop(self, slot_index):
        try:
            while not self.stop_event.is_set():
                try:
                    job = await asyncio.wait_for(self.job_queue.get(), timeout=1)
                except asyncio.TimeoutError:
                    continue
                try:
                    await self._process_job(slot_index, job)
                except Exception as exc:
                    logging.exception("Worker %s failed: %s", slot_index, exc)
                finally:
                    self.job_queue.task_done()
        except asyncio.CancelledError:
            logging.info("Worker %s cancelled.", slot_index)

    async def _process_job(self, slot_index, job):
        job_id = job.get("id")
        url = job.get("url")
        complete_queue = job.get("complete_queue")
        job_type = job.get("job_type", "standard")
        if not job_id or not url or not complete_queue:
            logging.warning("Skipping malformed job: %s", job)
            return

        domain_dir, job_dir = self._build_output_dir(job)
        domain_dir.mkdir(parents=True, exist_ok=True)
        (domain_dir / "logs").mkdir(parents=True, exist_ok=True)
        job_dir.mkdir(parents=True, exist_ok=True)
        (job_dir / "logs").mkdir(parents=True, exist_ok=True)
        execution_log_path = job_dir / "logs" / "execution.log"
        chrome_log_path = job_dir / "logs" / "chrome.log"

        logger = JobLogger(execution_log_path)
        chrome_offset = self.chrome.snapshot_log()
        logger.log(f"[Slot {slot_index}] Processing {url} (job_type={job_type}) JobID={job_id}")

        status = "completed"
        context_id = None

        for attempt in range(2):
            try:
                context_id = await self.chrome.create_context()
                check_success = await self._run_stage(
                    context_id=context_id,
                    script_path=CHECK_SCRIPT,
                    url=url,
                    output_dir=domain_dir,
                    timeout=self.check_timeout,
                    stage_name="check.py",
                    logger=logger,
                    extra_args=[],
                )
                if not check_success:
                    status = "error"

                cdpscan_args = []
                if job_type == "changed_js":
                    if job.get("source_url"):
                        cdpscan_args += ["--target-source-url", job["source_url"]]
                    if job.get("script_sha256"):
                        cdpscan_args += ["--target-script-sha256", job["script_sha256"]]
                    if job.get("diff_signature"):
                        cdpscan_args += ["--target-diff-signature", job["diff_signature"]]
                    if job.get("domain"):
                        cdpscan_args += ["--submission-domain", job["domain"]]

                scan_success = await self._run_stage(
                    context_id=context_id,
                    script_path=CDPSCAN_SCRIPT,
                    url=url,
                    output_dir=job_dir,
                    timeout=self.scan_timeout,
                    stage_name="cdpscan.py",
                    logger=logger,
                    extra_args=cdpscan_args,
                )
                if not scan_success:
                    status = "error"
                break
            except RuntimeError as exc:
                logger.log(f"Browser error while processing job (attempt {attempt + 1}): {exc}")
                logging.warning("Browser error on job %s: %s", job_id, exc)
                await self.chrome.restart()
                status = "error"
                if attempt == 1:
                    break
                continue
            except Exception as exc:
                logger.log(f"Unexpected failure while processing job: {exc}")
                logging.exception("Job %s failed: %s", job_id, exc)
                status = "error"
                break
            finally:
                if context_id:
                    await self.chrome.dispose_context(context_id)
                    context_id = None
        await self.chrome.export_log_slice(chrome_offset, chrome_log_path)
        logger.log(f"Finished job {job_id} with status={status}")
        logger.close()

        payload = {"id": job_id, "url": url, "status": status}
        try:
            await self.redis_source.push_complete(complete_queue, payload)
        except Exception as exc:
            logging.error("Failed to push completion status for %s: %s", job_id, exc)

    async def _run_stage(
        self,
        context_id,
        script_path,
        url,
        output_dir,
        timeout,
        stage_name,
        logger: JobLogger,
        extra_args,
    ):
        target_id = await self.chrome.create_target(context_id)
        ws_url = self.chrome.build_page_ws_url(target_id)
        cmd = [
            sys.executable,
            str(script_path),
            url,
            "--port",
            str(self.chrome_port),
            "--output-dir",
            str(output_dir),
            "--websocket-url",
            ws_url,
        ] + extra_args

        logger.log(f"Starting {stage_name} on {url}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=logger.stream,
            stderr=logger.stream,
            cwd=str(SCRIPT_DIR),
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.log(f"{stage_name} timed out after {timeout} seconds; killing process.")
            proc.kill()
            await proc.wait()
            await self.chrome.close_target(target_id)
            return False

        await self.chrome.close_target(target_id)
        if proc.returncode != 0:
            logger.log(f"{stage_name} exited with code {proc.returncode}")
            return False
        logger.log(f"{stage_name} completed successfully.")
        return True

    def _build_output_dir(self, job):
        def slugify(text):
            text = text.strip().lower().replace(" ", "-")
            return re.sub(r"[^a-z0-9._-]", "-", text) or "job"

        domain_slug = None
        domain = job.get("domain")
        if domain:
            domain_slug = slugify(domain)

        if not domain_slug:
            domain_slug = slugify(job.get("id", "job"))

        domain_dir = self.event_root / domain_slug

        diff_slug = None
        if job.get("job_type") == "changed_js":
            diff = job.get("diff_signature") or job.get("script_sha256")
            if diff:
                diff_slug = slugify(diff)

        if not diff_slug:
            diff_slug = slugify(job.get("id", "job"))

        job_dir = domain_dir / diff_slug
        idx = 1
        while job_dir.exists():
            job_dir = domain_dir / f"{diff_slug}-{idx}"
            idx += 1

        return domain_dir, job_dir
