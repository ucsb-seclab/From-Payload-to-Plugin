import argparse
import asyncio
import hashlib
import http.client
import json
import logging
import os
import signal
import socket
import sys
import time
import traceback
from datetime import datetime
from urllib.parse import urlparse

import requests
import websockets
try:
    import zstandard as zstd
except Exception:
    zstd = None

POST_LOAD_IDLE_SECONDS = int(os.getenv("CDP_POST_LOAD_IDLE_SECONDS", "5"))
INTERACTION_CAPTURE_SECONDS = int(os.getenv("CDP_INTERACTION_CAPTURE_SECONDS", "10"))
ADDITIONAL_WHITESPACE_CLICKS = int(os.getenv("CDP_WHITESPACE_CLICK_ATTEMPTS", "3"))

_events_log_data = None
_output_file_path = None

def get_trace_output_path(output_dir):
    if zstd is None:
        logging.warning("zstandard not available; falling back to trace_v2.json.")
        return os.path.join(output_dir, "trace_v2.json")
    return os.path.join(output_dir, "trace_v2.json.zst")

def write_events_log(output_file, events_log):
    if output_file.endswith(".zst"):
        if zstd is None:
            raise RuntimeError("zstandard is required to write compressed traces.")
        data = json.dumps(events_log, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        with open(output_file, "wb") as f:
            with zstd.ZstdCompressor().stream_writer(f) as compressor:
                compressor.write(data)
        return
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(events_log, f)

def signal_handler(signum, frame):
    logging.warning(f"Received signal {signum}, saving partial events...")
    if _events_log_data and _output_file_path:
        try:
            write_events_log(_output_file_path, _events_log_data)
            logging.info(f"Emergency save: Saved {len(_events_log_data)} events to {_output_file_path}")
        except Exception as e:
            logging.error(f"Failed to emergency save: {e}")
    sys.exit(1)

def load_js_script(file_path):
    logging.info(f"Attempting to load JavaScript file: {file_path}")
    try:
        with open(file_path, "r") as js_file:
            script_content = js_file.read()
            logging.info(f"Successfully loaded JavaScript file: {file_path}")
            return script_content
    except FileNotFoundError:
        logging.error(f"JavaScript file not found: {file_path}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error reading {file_path}: {e}")
        logging.debug(traceback.format_exc())
        raise

def get_websocket_url(port, timeout=30):
    logging.info(f"Attempting to retrieve WebSocket URL from port {port}")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            conn = http.client.HTTPConnection(f"localhost:{port}")
            conn.request("GET", "/json")
            response = conn.getresponse()
            if response.status == 200:
                try:
                    json_data = json.loads(response.read().decode())
                except json.JSONDecodeError as je:
                    logging.error(f"Error decoding JSON from /json endpoint: {je}")
                    json_data = []
                for entry in json_data:
                    if entry.get("type") == "page":
                        websocket_url = entry['webSocketDebuggerUrl']
                        logging.info(f"Found WebSocket URL: {websocket_url}")
                        conn.close()
                        return websocket_url
            conn.close()
        except (ConnectionRefusedError, IndexError, KeyError, socket.gaierror, http.client.HTTPException) as e:
            logging.warning(f"Error retrieving WebSocket URL: {e}")
        except Exception as e:
            logging.error(f"Unexpected error while getting WebSocket URL: {e}")
            logging.debug(traceback.format_exc())
        time.sleep(1)
    raise Exception("Failed to find a valid WebSocket URL for a page.")

def normalize_script_url(url):
    if not url:
        return ""
    url = url.strip()
    if url.startswith("//"):
        url = f"https:{url}"
    parsed = urlparse(url)
    if not parsed.netloc:
        return url
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    return f"{netloc}{path}{query}{fragment}"

def value_mentions_target(value, target_script_ids, target_source_url, current_key=None):
    if value is None:
        return False

    if isinstance(value, dict):
        for key, val in value.items():
            if target_script_ids and key == "scriptId" and val in target_script_ids:
                return True
            if target_source_url and key in ("url", "documentURL", "requestURL"):
                if normalize_script_url(val) == target_source_url:
                    return True
            if value_mentions_target(val, target_script_ids, target_source_url, key):
                return True
        return False

    if isinstance(value, list):
        for item in value:
            if value_mentions_target(item, target_script_ids, target_source_url, current_key):
                return True
        return False

    if target_source_url and current_key in ("url", "documentURL", "requestURL"):
        if normalize_script_url(value) == target_source_url:
            return True

    return False

def filter_events_for_target(events_log, target_script_ids, target_source_url):
    if not target_script_ids and not target_source_url:
        return events_log

    filtered_events = []
    for event_entry in events_log:
        event_body = event_entry.get("event", {})
        if value_mentions_target(event_body, target_script_ids, target_source_url):
            filtered_events.append(event_entry)
    return filtered_events

async def capture_events_for_duration(websocket, events_log, script_infos, event_counter, seconds, context):
    if seconds <= 0:
        return
    logging.info(f"Capturing events during {context} for {seconds} seconds...")
    end_time = time.time() + seconds
    while time.time() < end_time:
        remaining = max(0.1, end_time - time.time())
        try:
            response = await asyncio.wait_for(websocket.recv(), timeout=min(0.5, remaining))
            message = json.loads(response)
            await process_event(message, events_log, script_infos, event_counter)
        except asyncio.TimeoutError:
            continue
        except websockets.ConnectionClosed:
            logging.error(f"WebSocket connection closed while capturing events ({context}).")
            break
        except json.JSONDecodeError as je:
            logging.error(f"JSON decoding error while capturing events ({context}): {je}")
            logging.debug(traceback.format_exc())
        except Exception as exc:
            logging.error(f"Unexpected error while capturing events ({context}): {exc}")
            logging.debug(traceback.format_exc())
    logging.info(f"Finished capturing events during {context}.")

async def process_event(message, events_log, script_infos, event_counter=None):
    if event_counter:
        event_counter['count'] += 1
        if event_counter['count'] > event_counter['limit']:
            logging.error(f"CIRCUIT BREAKER: Event limit ({event_counter['limit']}) exceeded! Stopping event processing.")
            raise Exception("Event limit exceeded - possible infinite loop detected")

    logging.debug("Processing received event")
    timestamp = datetime.now().isoformat()
    event_data = {
        "timestamp": timestamp,
        "event": message
    }
    events_log.append(event_data)
    event_method = message.get('method', 'Unknown')
    logging.debug(f"Processed event: {event_method}")

    if event_method == "Debugger.scriptParsed":
        params = message.get("params", {})
        url = params.get("url", "")
        script_id = params.get("scriptId", "")
        if url:
            script_info = {
                "url": url,
                "scriptId": script_id,
                "hash": params.get("hash", ""),
                "startLine": params.get("startLine", 0),
                "endLine": params.get("endLine", 0),
                "startColumn": params.get("startColumn", 0),
                "endColumn": params.get("endColumn", 0),
                "length": params.get("length", 0),
                "isModule": params.get("isModule", False),
            }
            script_infos.append(script_info)
            logging.info(f"Captured script: {url} with script ID: {script_id}, hash: {params.get('hash', 'N/A')}")

async def get_script_source(websocket, script_id, command_id, events_log, script_infos, event_counter):
    try:
        get_source_command = {
            "id": command_id,
            "method": "Debugger.getScriptSource",
            "params": {"scriptId": script_id}
        }
        await websocket.send(json.dumps(get_source_command))
        logging.debug(f"Requested source for script ID: {script_id}")

        start_time = time.time()
        timeout_seconds = 10

        while True:
            if time.time() - start_time > timeout_seconds:
                logging.warning(f"Timeout retrieving script source for {script_id} after {timeout_seconds}s")
                return None

            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                message = json.loads(response)

                if message.get("id") == command_id:
                    if "result" in message and "scriptSource" in message["result"]:
                        return message["result"]["scriptSource"]
                    else:
                        logging.warning(f"Failed to get script source for {script_id}: {message.get('error', 'Unknown error')}")
                        return None

                if "method" in message:
                    await process_event(message, events_log, script_infos, event_counter)
            except asyncio.TimeoutError:
                continue

    except Exception as e:
        logging.error(f"Error retrieving script source for {script_id}: {e}")
        logging.debug(traceback.format_exc())
        return None

async def main(url_to_load, port, output_dir, target_config=None, websocket_url=None):
    global _events_log_data, _output_file_path

    logging.info("Starting main event capture process")
    events_log = []
    script_infos = []

    target_config = target_config or {}
    target_source_url = (target_config.get("source_url") or "").strip()
    target_source_url_normalized = normalize_script_url(target_source_url)
    expected_script_sha = (target_config.get("script_sha256") or "").strip().lower()
    target_diff_signature = (target_config.get("diff_signature") or "").strip()
    submission_domain = (target_config.get("submission_domain") or "").strip()
    target_mode = bool(target_source_url or expected_script_sha)
    target_report = None
    target_script_ids = set()

    if target_mode:
        target_report = {
            "mode": "changed_js",
            "page_url": url_to_load,
            "domain": submission_domain,
            "source_url": target_source_url,
            "normalized_source_url": target_source_url_normalized,
            "expected_script_sha256": expected_script_sha,
            "diff_signature": target_diff_signature,
            "target_found": False,
            "hash_verified": False,
            "matches": [],
            "notes": [],
        }
        logging.info(
            f"Changed JS targeting enabled for source_url='{target_source_url}' expected_sha='{expected_script_sha}'"
        )

    _events_log_data = events_log
    _output_file_path = get_trace_output_path(output_dir)

    event_counter = {'count': 0, 'limit': 50000}

    try:
        os.makedirs(output_dir, exist_ok=True)
        logging.info(f"Output directory is ready: {output_dir}")
    except Exception as e:
        logging.error(f"Failed to create output directory {output_dir}: {e}")
        logging.debug(traceback.format_exc())
        return

    output_file = get_trace_output_path(output_dir)
    target_report_path = os.path.join(output_dir, "changed_js_report.json") if target_mode else None

    try:
        ws_url = websocket_url or get_websocket_url(port)
    except Exception as e:
        logging.error(f"Could not obtain WebSocket URL: {e}")
        return

    try:
        async with websockets.connect(ws_url) as websocket:
            logging.info(f"Connected to WebSocket: {ws_url}")

            enable_commands = [
                {"id": 1, "method": "Page.enable"},
                {"id": 2, "method": "DOM.enable"},
                {"id": 3, "method": "DOM.setNodeStackTracesEnabled"},
                {"id": 4, "method": "DOMStorage.enable"},
                {"id": 5, "method": "DOM.getDocument"},
                {"id": 6, "method": "Network.enable"},
                {"id": 7, "method": "Network.setAttachDebugStack", "params": {"enabled": True}},
                {"id": 8, "method": "Runtime.enable"},
                {"id": 9, "method": "Console.enable"},
                {"id": 10, "method": "Debugger.enable"},
                {"id": 11, "method": "Log.enable"},
                {"id": 12, "method": "Inspector.enable"},
                {"id": 13, "method": "Overlay.enable"},
                {"id": 14, "method": "Performance.enable"},
                {"id": 15, "method": "Security.enable"},
                {"id": 16, "method": "Storage.enable"},
                {"id": 17, "method": "serviceWorker.enable"},
                {"id": 18, "method": "LayerTree.enable"},
                {"id": 19, "method": "Audits.enable"},
            ]
            for command in enable_commands:
                try:
                    await websocket.send(json.dumps(command))
                    logging.debug(f"Sent command: {command['method']}")
                except Exception as e:
                    logging.error(f"Failed to send command {command['method']}: {e}")
                    logging.debug(traceback.format_exc())

            try:
                dom_mutation_observer_script = load_js_script('mutation_observers/dom_mutation_observer.js')
                inject_command = {"id": 20, "method": "Page.addScriptToEvaluateOnNewDocument",
                                  "params": {"source": dom_mutation_observer_script}}
                await websocket.send(json.dumps(inject_command))
                logging.info("Injected DOM MutationObserver script using Page.addScriptToEvaluateOnNewDocument.")
            except Exception as e:
                logging.error(f"Error injecting DOM MutationObserver script: {e}")
                logging.debug(traceback.format_exc())

            try:
                navigation_command = {"id": 21, "method": "Page.navigate", "params": {"url": url_to_load}}
                await websocket.send(json.dumps(navigation_command))
                logging.info(f"Navigating to URL: {url_to_load}")
            except Exception as e:
                logging.error(f"Error during navigation command: {e}")
                logging.debug(traceback.format_exc())

            page_loaded = False
            start_time = time.time()
            while not page_loaded:
                if time.time() - start_time > 30:
                    logging.warning("Timeout reached while waiting for page to load. Continuing with partial results...")
                    break
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                    message = json.loads(response)
                    await process_event(message, events_log, script_infos, event_counter)
                    if message.get("method") == "Page.loadEventFired":
                        page_loaded = True
                        logging.info(f"Page load event detected for {url_to_load}")
                except asyncio.TimeoutError:
                    continue
                except websockets.ConnectionClosed:
                    logging.error("WebSocket connection closed unexpectedly while waiting for page load.")
                    break
                except json.JSONDecodeError as je:
                    logging.error(f"JSON decoding error: {je}")
                    logging.debug(traceback.format_exc())
                except Exception as e:
                    logging.error(f"Unexpected error while processing events: {e}")
                    logging.debug(traceback.format_exc())

            command_id = 23

            if page_loaded:
                logging.info("Page loaded. Performing synthetic user interactions after idle wait...")
            else:
                logging.info("Page did not fully load, but continuing with synthetic user interactions...")

            await capture_events_for_duration(
                websocket,
                events_log,
                script_infos,
                event_counter,
                POST_LOAD_IDLE_SECONDS,
                "post-load idle wait",
            )

            try:
                scroll_down_js = """
                    console.log(JSON.stringify({
                        type: 'Synthetic Interaction',
                        action: 'Scroll Down',
                        stack: new Error().stack
                    }));
                    window.scrollTo(0, document.documentElement.scrollHeight / 2);
                """
                scroll_down_command = {"id": command_id, "method": "Runtime.evaluate",
                                      "params": {"expression": scroll_down_js}}
                await websocket.send(json.dumps(scroll_down_command))
                logging.info("Sent synthetic scroll down command.")
                await asyncio.sleep(0.5)
                command_id += 1
            except Exception as e:
                logging.error(f"Error sending scroll down command: {e}")
                logging.debug(traceback.format_exc())

            try:
                scroll_up_js = """
                    console.log(JSON.stringify({
                        type: 'Synthetic Interaction',
                        action: 'Scroll Up',
                        stack: new Error().stack
                    }));
                    window.scrollTo(0, 0);
                """
                scroll_up_command = {"id": command_id, "method": "Runtime.evaluate",
                                    "params": {"expression": scroll_up_js}}
                await websocket.send(json.dumps(scroll_up_command))
                logging.info("Sent synthetic scroll up command.")
                await asyncio.sleep(0.5)
                command_id += 1
            except Exception as e:
                logging.error(f"Error sending scroll up command: {e}")
                logging.debug(traceback.format_exc())

            click_attempts = max(1, ADDITIONAL_WHITESPACE_CLICKS)
            click_positions = [
                ("center", 0.5, 0.5),
                ("upper_left", 0.25, 0.3),
                ("upper_right", 0.75, 0.3),
                ("lower_center", 0.5, 0.75),
                ("lower_left", 0.25, 0.9),
                ("lower_right", 0.75, 0.9),
            ]
            for attempt in range(click_attempts):
                label, frac_x, frac_y = click_positions[attempt % len(click_positions)]
                click_js = f"""(function() {{
                   const clickX = Math.max(2, Math.min(window.innerWidth - 2, window.innerWidth * {frac_x}));
                   const clickY = Math.max(2, Math.min(window.innerHeight - 2, window.innerHeight * {frac_y}));
                   const elementAtPoint = document.elementFromPoint(clickX, clickY);
                   const isInteractive = !!(elementAtPoint && (
                       elementAtPoint.tagName === 'A' ||
                       elementAtPoint.tagName === 'BUTTON' ||
                       elementAtPoint.tagName === 'INPUT' ||
                       elementAtPoint.hasAttribute('onclick') ||
                       elementAtPoint.getAttribute('role') === 'button' ||
                       elementAtPoint.getAttribute('role') === 'link'
                   ));
                   const clickEvent = new MouseEvent('click', {{
                       bubbles: true,
                       cancelable: true,
                       view: window,
                       clientX: clickX,
                       clientY: clickY
                   }});
                   if (elementAtPoint) {{
                       elementAtPoint.dispatchEvent(clickEvent);
                   }} else {{
                       document.body.dispatchEvent(clickEvent);
                   }}
                   console.log(JSON.stringify({{
                       type: 'Synthetic Interaction',
                       action: 'Whitespace Click',
                       label: '{label}',
                       isInteractiveTarget: isInteractive,
                       stack: new Error().stack,
                       position: {{ x: clickX, y: clickY }},
                       targetTag: elementAtPoint ? elementAtPoint.tagName : 'none'
                   }}));
                   return {{
                       clicked: true,
                       label: '{label}',
                       isInteractiveTarget: isInteractive,
                       targetTag: elementAtPoint ? elementAtPoint.tagName : 'none'
                   }};
                }})()"""
                try:
                    whitespace_click_command = {"id": command_id, "method": "Runtime.evaluate",
                                               "params": {"expression": click_js}}
                    await websocket.send(json.dumps(whitespace_click_command))
                    logging.info(
                        "Sent synthetic whitespace click command %s/%s targeting %s.",
                        attempt + 1,
                        click_attempts,
                        label,
                    )
                    await asyncio.sleep(1.5)
                    command_id += 1
                except Exception as e:
                    logging.error(f"Error sending whitespace click command ({label}): {e}")
                    logging.debug(traceback.format_exc())
                    break

            await capture_events_for_duration(
                websocket,
                events_log,
                script_infos,
                event_counter,
                INTERACTION_CAPTURE_SECONDS,
                "post-interaction observation",
            )

            try:
                write_events_log(output_file, events_log)
                logging.info(f"Saved {len(events_log)} events to {output_file} (early save after interactions)")
            except Exception as e:
                logging.error(f"Failed to write events log (early save): {e}")
                logging.debug(traceback.format_exc())

            if target_mode:
                logging.info("Retrieving script sources via CDP for target matching")
                try:
                    for script_info in script_infos:
                        script_url = script_info.get("url") or ""
                        script_id = script_info.get("scriptId")
                        normalized_url = script_url
                        if normalized_url.startswith("//"):
                            normalized_url = f"https:{normalized_url}"
                        is_http_script = normalized_url.startswith(("http://", "https://"))

                        if not is_http_script and not expected_script_sha:
                            continue

                        script_content = None
                        log_url = script_url or "[inline script]"

                        logging.info(f"Retrieving script source for script ID {script_id} from URL: {log_url}")
                        normalized_script_url = normalize_script_url(script_url)
                        script_content = await get_script_source(
                            websocket,
                            script_id,
                            command_id,
                            events_log,
                            script_infos,
                            event_counter
                        )
                        command_id += 1

                        if script_content is None and is_http_script and not normalized_url.endswith(".html"):
                            try:
                                logging.info(f"CDP retrieval failed, trying HTTP download for: {normalized_url}")
                                resp = requests.get(normalized_url, timeout=10)
                                resp.raise_for_status()
                                script_content = resp.text
                            except requests.exceptions.RequestException as re:
                                logging.warning(f"Request error downloading script {normalized_url}: {re}")
                            except Exception as e:
                                logging.error(f"Error downloading script {normalized_url}: {e}")
                                logging.debug(traceback.format_exc())

                        if not script_content:
                            logging.warning(f"Could not retrieve content for script {script_id} from {log_url}")
                            continue

                        script_hash = hashlib.sha256(script_content.encode("utf-8")).hexdigest()
                        hash_matched = bool(expected_script_sha and script_hash.lower() == expected_script_sha)
                        url_matched = bool(
                            target_source_url_normalized
                            and normalized_script_url == target_source_url_normalized
                        )
                        is_target_script = False
                        match_reason_parts = []

                        if url_matched:
                            is_target_script = True
                            match_reason_parts.append("url")
                        if hash_matched:
                            is_target_script = True
                            match_reason_parts.append("sha256")
                        if not is_target_script:
                            continue

                        target_script_ids.add(script_id)
                        match_reason = "+".join(match_reason_parts) if match_reason_parts else ""
                        target_report["matches"].append({
                            "script_id": script_id,
                            "script_url": script_url or "[inline]",
                            "script_sha256": script_hash,
                            "hash_matched": hash_matched,
                            "url_matched": url_matched,
                            "match_reason": match_reason,
                        })
                        target_report["target_found"] = True
                        if hash_matched:
                            target_report["hash_verified"] = True
                        if url_matched and not hash_matched:
                            note = f"Script {script_id} matched source_url but SHA256 mismatched (observed {script_hash})."
                            if note not in target_report["notes"]:
                                target_report["notes"].append(note)
                except Exception as e:
                    logging.error(f"Error during script source retrieval: {e}")
                    logging.debug(traceback.format_exc())
            else:
                logging.info("Skipping script source retrieval because target matching is disabled")

            if target_mode:
                if target_script_ids:
                    filtered_events = filter_events_for_target(
                        events_log,
                        target_script_ids,
                        target_source_url_normalized,
                    )
                    logging.info(f"Filtered events from {len(events_log)} to {len(filtered_events)} for target script context.")
                    events_log = filtered_events
                else:
                    logging.warning("Target script did not load; keeping full trace for investigation.")

            _events_log_data = events_log
            try:
                write_events_log(output_file, events_log)
                logging.info(f"Saved events log to {output_file}")
            except Exception as e:
                logging.error(f"Failed to write events log to file: {e}")
                logging.debug(traceback.format_exc())

            if target_mode and target_report and target_report_path:
                target_report["script_ids"] = list(target_script_ids)
                target_report["events_recorded"] = len(events_log)
                if not target_report["target_found"]:
                    target_report["notes"].append("Target script not observed on this run.")
                try:
                    with open(target_report_path, "w", encoding="utf-8") as report_file:
                        json.dump(target_report, report_file, indent=2)
                    logging.info(f"Saved changed JS report to {target_report_path}")
                except Exception as report_error:
                    logging.error(f"Failed to write changed JS report: {report_error}")
                    logging.debug(traceback.format_exc())

            try:
                clear_cache_command = {"id": command_id, "method": "Network.clearBrowserCache"}
                await websocket.send(json.dumps(clear_cache_command))
                logging.info("Browser cache cleared.")
                command_id += 1
            except websockets.ConnectionClosed as e:
                logging.error(f"WebSocket connection closed when clearing browser cache: {e}")
            except Exception as e:
                logging.error(f"Failed to clear browser cache: {e}")
                logging.debug(traceback.format_exc())

            try:
                close_tab_command = {"id": command_id, "method": "Page.close"}
                await websocket.send(json.dumps(close_tab_command))
                logging.info("Closed the tab.")
            except websockets.ConnectionClosed as e:
                logging.error(f"WebSocket connection closed when closing the tab: {e}")
            except Exception as e:
                logging.error(f"Failed to close the tab: {e}")
                logging.debug(traceback.format_exc())

    except Exception as e:
        logging.error(f"An error occurred during WebSocket communication: {e}")
        logging.debug(traceback.format_exc())
    finally:
        if events_log:
            try:
                write_events_log(output_file, events_log)
                logging.info(f"Saved {len(events_log)} events to {output_file} (via finally block)")
            except Exception as e:
                logging.error(f"Failed to write events log in finally block: {e}")
                logging.debug(traceback.format_exc())
        else:
            logging.warning("No events captured to save")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Log network/DOM events for a given URL using CDP and save trace."
                    "json along with loaded JS and script IDs."
    )
    parser.add_argument("url", help="URL to process")
    parser.add_argument("--port", type=int, required=True, help="Chrome remote debugging port")
    parser.add_argument(
        "--output-dir",
        default=os.getenv("CDP_DATA_PATH", "output"),
        help="Directory where results will be saved (default: $CDP_DATA_PATH or 'output')"
    )
    parser.add_argument("--target-source-url", help="When set, only retain traces for this script URL.", default="")
    parser.add_argument("--target-script-sha256", help="Expected SHA256 for the target script.", default="")
    parser.add_argument("--target-diff-signature", help="Diff signature identifier for reporting.", default="")
    parser.add_argument("--submission-domain", help="Original domain from the submission payload.", default="")
    parser.add_argument(
        "--websocket-url",
        help="Connect to a specific DevTools target endpoint instead of discovering via /json.",
        default=""
    )
    args = parser.parse_args()
    log_dir = os.path.join(args.output_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(log_dir, "trace.log")),
            logging.StreamHandler()
        ]
    )

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    logging.info(f"Starting event capture for URL: {args.url}")

    target_config = {
        "source_url": args.target_source_url,
        "script_sha256": args.target_script_sha256,
        "diff_signature": args.target_diff_signature,
        "submission_domain": args.submission_domain,
    }
    if not any(target_config.values()):
        target_config = None

    provided_ws = args.websocket_url or None
    try:
        asyncio.run(main(args.url, args.port, args.output_dir, target_config, provided_ws))
    except Exception as e:
        logging.error(f"Fatal error in main execution: {e}")
        logging.debug(traceback.format_exc())
