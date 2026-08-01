import asyncio
import json
import logging
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
import websockets
from websockets.exceptions import WebSocketException

class ChromeController:

    def __init__(
        self,
        chrome_binary: str,
        port: int,
        log_path: Path,
        extra_flags: Optional[list[str]] = None,
        headless: bool = True,
    ):
        self.chrome_binary = chrome_binary
        self.port = port
        self.log_path = log_path
        self.extra_flags = extra_flags or []
        self.headless = headless
        self.process: Optional[asyncio.subprocess.Process] = None
        self.browser_ws_url: Optional[str] = None
        self._log_handle = None
        self._user_data_dir: Optional[str] = None
        self._health_client = httpx.AsyncClient(timeout=2.0)
        self._command_lock = asyncio.Lock()

    async def ensure_browser(self):
        if self.process and self.process.returncode is None:
            return
        await self._start_browser()

    async def _start_browser(self):
        await self._cleanup()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._user_data_dir = tempfile.mkdtemp(prefix="chrome_pool_")
        self._log_handle = open(self.log_path, "ab", buffering=0)
        cmd = [
            self.chrome_binary,
            f"--remote-debugging-port={self.port}",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-extensions",
            f"--user-data-dir={self._user_data_dir}",
            "--disable-blink-features=AutomationControlled",
            "--disable-infobars",
            "--window-size=1366,768",
            "--disable-popup-blocking",
            "--disable-notifications",
            "--disable-dev-shm-usage",
            "--remote-allow-origins=*",
        ] + self.extra_flags
        if self.headless:
            cmd.insert(1, "--headless=new")

        logging.info("Launching pooled Chrome: %s", " ".join(cmd))
        self.process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=self._log_handle,
            stderr=asyncio.subprocess.STDOUT,
        )
        await self._wait_for_ready()

    async def _wait_for_ready(self, timeout = 30):
        deadline = time.monotonic() + timeout
        url = f"http://127.0.0.1:{self.port}/json/version"
        while time.monotonic() < deadline:
            if self.process and self.process.returncode is not None:
                raise RuntimeError("Chrome exited during startup.")
            try:
                resp = await self._health_client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    ws = data.get("webSocketDebuggerUrl")
                    if ws:
                        self.browser_ws_url = ws
                        logging.info("Chrome DevTools ready at %s", ws)
                        return
            except httpx.RequestError:
                pass
            await asyncio.sleep(1)
        raise TimeoutError(f"Timed out waiting for Chrome DevTools on port {self.port}")

    async def check_health(self):
        await self.ensure_browser()
        if not self.browser_ws_url:
            await self._wait_for_ready()
            return
        try:
            resp = await self._health_client.get(f"http://127.0.0.1:{self.port}/json/version")
            resp.raise_for_status()
        except Exception as exc:
            logging.warning("Chrome health check failed: %s", exc)
            await self.restart()

    async def restart(self):
        logging.warning("Restarting Chrome process...")
        await self._cleanup()
        await self._start_browser()

    async def _browser_command(self, method, params = None, timeout = 10):
        attempts = 0
        while attempts < 2:
            await self.ensure_browser()
            if not self.browser_ws_url:
                raise RuntimeError("Browser WebSocket URL unavailable.")
            try:
                async with self._command_lock:
                    payload = {"id": 1, "method": method}
                    if params:
                        payload["params"] = params
                    async with websockets.connect(self.browser_ws_url, max_size=None) as websocket:
                        await websocket.send(json.dumps(payload))
                        while True:
                            response_raw = await asyncio.wait_for(websocket.recv(), timeout=timeout)
                            response = json.loads(response_raw)
                            if response.get("id") == payload["id"]:
                                if "error" in response:
                                    raise RuntimeError(f"Chrome command {method} failed: {response['error']}")
                                return response
            except (ConnectionRefusedError, OSError, WebSocketException, asyncio.TimeoutError) as exc:
                attempts += 1
                logging.warning("Browser command %s failed (%s); restarting Chrome (attempt %s).", method, exc, attempts)
                await self.restart()
                continue
            break
        raise RuntimeError("Failed to execute browser command after restarting Chrome.")

    async def create_context(self):
        attempts = 0
        while attempts < 2:
            try:
                response = await self._browser_command("Target.createBrowserContext")
                context_id = response["result"]["browserContextId"]
                logging.debug("Created browser context %s", context_id)
                return context_id
            except RuntimeError as exc:
                attempts += 1
                logging.warning("create_context failed (%s); restarting Chrome (attempt %s).", exc, attempts)
                await self.restart()
        raise RuntimeError("Failed to create browser context after restart.")

    async def dispose_context(self, context_id):
        try:
            await self._browser_command("Target.disposeBrowserContext", {"browserContextId": context_id})
            logging.debug("Disposed browser context %s", context_id)
        except Exception as exc:
            logging.warning("Failed to dispose context %s: %s", context_id, exc)

    async def create_target(self, context_id):
        attempts = 0
        while attempts < 2:
            try:
                response = await self._browser_command(
                    "Target.createTarget",
                    {"browserContextId": context_id, "url": "about:blank"},
                )
                target_id = response["result"]["targetId"]
                logging.debug("Created target %s in context %s", target_id, context_id)
                return target_id
            except RuntimeError as exc:
                attempts += 1
                logging.warning("create_target failed (%s); restarting Chrome (attempt %s).", exc, attempts)
                await self.restart()
        raise RuntimeError("Failed to create target after restart.")

    async def close_target(self, target_id):
        try:
            await self._browser_command("Target.closeTarget", {"targetId": target_id})
        except Exception as exc:
            logging.debug("Target %s close failed (likely already closed): %s", target_id, exc)

    def build_page_ws_url(self, target_id):
        return f"ws://127.0.0.1:{self.port}/devtools/page/{target_id}"

    def snapshot_log(self):
        if not self.log_path.exists():
            return 0
        return self.log_path.stat().st_size

    async def export_log_slice(self, start_offset, destination):
        if not self.log_path.exists():
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._copy_log_slice, start_offset, destination)

    def _copy_log_slice(self, start_offset, destination):
        with open(self.log_path, "rb") as src, open(destination, "ab") as dst:
            src.seek(start_offset)
            shutil.copyfileobj(src, dst)

    async def watchdog(self, stop_event, interval = 30):
        while not stop_event.is_set():
            await asyncio.sleep(interval)
            await self.check_health()

    async def _cleanup(self):
        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=10)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
        if self._log_handle:
            self._log_handle.close()
            self._log_handle = None
        if self._user_data_dir and os.path.isdir(self._user_data_dir):
            shutil.rmtree(self._user_data_dir, ignore_errors=True)
        self.browser_ws_url = None

    async def shutdown(self):
        await self._cleanup()
        await self._health_client.aclose()
