import argparse
import asyncio
import http.client
import json
import logging
import os
import re
import signal
import socket
import sys
import time
import traceback
from datetime import datetime

import websockets

_result_data = None
_output_file_path = None

def signal_handler(signum, frame):
    logging.warning(f"Received signal {signum}, saving partial results...")
    if _result_data and _output_file_path:
        try:
            with open(_output_file_path, "w") as file:
                json.dump(_result_data, file, indent=2)
            logging.info(f"Emergency save: Results written to {_output_file_path}")
        except Exception as e:
            logging.error(f"Failed to emergency save: {e}")
    sys.exit(1)

def get_websocket_url(port, timeout=30):
    logging.info(f"Attempting to retrieve WebSocket URL on port {port}")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            conn = http.client.HTTPConnection("localhost", port)
            conn.request("GET", "/json")
            response = conn.getresponse()
            if response.status == 200:
                targets = json.loads(response.read().decode())
                for target in targets:
                    if target.get("type") == "page" and "webSocketDebuggerUrl" in target:
                        ws_url = target["webSocketDebuggerUrl"]
                        logging.info(f"Found WebSocket URL: {ws_url}")
                        conn.close()
                        return ws_url
            conn.close()
        except (http.client.HTTPException, socket.gaierror, OSError) as e:
            logging.warning(f"HTTP/HTTPS/DNS error retrieving WebSocket URL: {e}")
        except Exception as e:
            logging.warning(f"Unexpected error retrieving WebSocket URL: {e}")
            logging.debug(traceback.format_exc())
        time.sleep(1)
    raise Exception("Failed to find a valid WebSocket URL for a page.")

def extract_resources(frame_tree):
    all_resources = []
    logging.debug("Extracting resources from frame tree")
    resources = frame_tree.get("resources", [])
    for res in resources:
        url = res.get("url", "")
        if url:
            logging.debug(f"Found resource URL: {url}")
            all_resources.append(url)
    child_frames = frame_tree.get("childFrames", [])
    for child in child_frames:
        child_resources = extract_resources(child)
        all_resources.extend(child_resources)
    return all_resources

def extract_wordpress_version(generator_value, resource_urls):
    meta_generator_regex = re.compile(r"WordPress\s+(\d+\.\d+(\.\d+)?)", re.IGNORECASE)
    match = meta_generator_regex.search(generator_value)
    if match:
        wp_version = match.group(1)
        logging.info(f"Detected WordPress version {wp_version} from meta generator.")
        return wp_version
    versioned_files_regex = re.compile(r"[?&]ver=(\d+\.\d+(\.\d+)?)", re.IGNORECASE)
    for url in resource_urls:
        match = versioned_files_regex.search(url)
        if match:
            wp_version = match.group(1)
            logging.info(f"Detected WordPress version {wp_version} from resource URL: {url}")
            return wp_version
    return None

async def main(url_to_load, port, output_dir, websocket_url=None):
    global _result_data, _output_file_path

    logging.info(f"Starting fingerprint process for URL: {url_to_load}")
    wp_patterns = [
        'wp-content', 'wp-content/uploads', 'wp-content/themes', 'wp-content/plugins',
        'wp-includes', 'wp-admin', 'wp-login', 'wp-json', 'wp-config', 'wp-cron',
        'wp-links-opml', 'wp-trackback', 'wp-mail', 'wp-activate', 'wp-signup', 'wp-comments-post'
    ]

    result = {
        "url": url_to_load,
        "timestamp": datetime.now().isoformat(),
        "generator_meta": "",
        "wordpress_version": None,
        "resource_urls_with_wp_paths": [],
        "is_wordpress": False
    }

    _result_data = result
    _output_file_path = os.path.join(output_dir, "fingerprint.json")

    try:
        os.makedirs(output_dir, exist_ok=True)
        logging.info(f"Output directory ensured: {output_dir}")
    except Exception as e:
        logging.error(f"Error creating output directory {output_dir}: {e}")
        logging.debug(traceback.format_exc())
        return

    output_file = os.path.join(output_dir, "fingerprint.json")

    try:
        ws_url = websocket_url or get_websocket_url(port)
        async with websockets.connect(ws_url) as websocket:
            logging.info(f"Connected to WebSocket: {ws_url}")

            enable_commands = [
                {"id": 1, "method": "Page.enable"},
                {"id": 2, "method": "Runtime.enable"},
                {"id": 3, "method": "Network.enable"}
            ]
            for command in enable_commands:
                await websocket.send(json.dumps(command))
                logging.info(f"Sent command: {command['method']}")

            navigate_command = {
                "id": 4,
                "method": "Page.navigate",
                "params": {"url": url_to_load}
            }
            await websocket.send(json.dumps(navigate_command))
            logging.info(f"Navigating to {url_to_load}")

            page_loaded = False
            start_time = time.time()
            logging.info("Waiting for page load event...")
            while not page_loaded:
                if time.time() - start_time > 30:
                    logging.warning("Timeout waiting for page load.")
                    break
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                    message = json.loads(response)
                    if message.get("method") == "Page.loadEventFired":
                        logging.info("Page load event fired.")
                        page_loaded = True
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logging.error(f"Error receiving message: {e}")
                    break

            if not page_loaded:
                logging.warning("Page did not load within the timeout period. Continuing with partial results...")

            js_html_content = (
                "(function() {"
                "  return document.documentElement.outerHTML;"
                "})()"
            )
            logging.info("Sending command to get page HTML content.")
            html_cmd = {
                "id": 9,
                "method": "Runtime.evaluate",
                "params": {"expression": js_html_content}
            }
            await websocket.send(json.dumps(html_cmd))

            page_html_content = ""
            start_time = time.time()
            html_timeout = 30
            logging.info("Waiting for HTML content result...")
            while True:
                if time.time() - start_time > html_timeout:
                    logging.warning("Timeout waiting for HTML content result.")
                    break
                message = json.loads(await websocket.recv())
                if message.get("id") == 9:
                    page_html_content = message.get("result", {}).get("result", {}).get("value", "")
                    logging.info(f"Received page HTML content (length: {len(page_html_content)})")
                    break

            js_generator = (
                "(function() {"
                "  var meta = document.querySelector('meta[name=\"generator\"]');"
                "  return meta ? meta.getAttribute('content') : '';"
                "})()"
            )
            logging.info("Sending command to evaluate meta generator value.")
            generator_cmd = {
                "id": 10,
                "method": "Runtime.evaluate",
                "params": {"expression": js_generator}
            }
            await websocket.send(json.dumps(generator_cmd))

            generator_value = ""
            start_time = time.time()
            generator_timeout = 30
            logging.info("Waiting for generator evaluation result...")
            while True:
                if time.time() - start_time > generator_timeout:
                    logging.warning("Timeout waiting for generator evaluation result.")
                    break
                message = json.loads(await websocket.recv())
                if message.get("id") == 10:
                    generator_value = message.get("result", {}).get("result", {}).get("value", "")
                    logging.info(f"Received generator meta value: {generator_value}")
                    break

            result["generator_meta"] = generator_value
            if "WordPress" in generator_value:
                logging.info(f"WordPress generator meta detected: {generator_value}")

            logging.info("Requesting resource tree from page.")
            resource_tree_cmd = {"id": 11, "method": "Page.getResourceTree"}
            await websocket.send(json.dumps(resource_tree_cmd))
            all_resource_urls = []
            start_time = time.time()
            resource_tree_timeout = 30
            logging.info("Waiting for resource tree response...")
            while True:
                if time.time() - start_time > resource_tree_timeout:
                    logging.warning("Timeout waiting for resource tree.")
                    break
                message = json.loads(await websocket.recv())
                if message.get("id") == 11:
                    frame_tree = message["result"]["frameTree"]
                    all_resource_urls = extract_resources(frame_tree)
                    logging.info(f"Extracted {len(all_resource_urls)} resource URLs.")
                    break

            resource_urls_with_wp_paths = []
            for url in all_resource_urls:
                for pattern in wp_patterns:
                    if pattern in url:
                        resource_urls_with_wp_paths.append(url)
                        logging.debug(f"Resource URL matching WP pattern '{pattern}': {url}")
                        break
            result["resource_urls_with_wp_paths"] = resource_urls_with_wp_paths

            html_content_lower = page_html_content.lower()
            html_has_wp_patterns = False
            for pattern in wp_patterns:
                if pattern in html_content_lower:
                    html_has_wp_patterns = True
                    logging.info(f"Found WordPress pattern in HTML content: {pattern}")
                    break

            if "wp-json/wp/v2" in html_content_lower:
                html_has_wp_patterns = True
                logging.info("Found wp-json/wp/v2 in HTML content")

            if "WordPress" in generator_value or resource_urls_with_wp_paths or html_has_wp_patterns:
                result["is_wordpress"] = True
                logging.info("Website appears to be running on WordPress.")
            else:
                logging.info("No WordPress indicators found.")

            wp_version = extract_wordpress_version(generator_value, resource_urls_with_wp_paths)
            if wp_version:
                result["wordpress_version"] = wp_version

            try:
                await websocket.send(json.dumps({"id": 12, "method": "Page.close"}))
                logging.info("Closed the page.")
            except websockets.ConnectionClosed:
                logging.warning("WebSocket closed before the page could be closed.")
    except Exception as e:
        logging.error(f"Error occurred during fingerprinting: {e}")
        logging.debug(traceback.format_exc())
        result["error"] = str(e)
    finally:
        try:
            with open(output_file, "w") as file:
                json.dump(result, file, indent=2)
            logging.info(f"Results written to {output_file}")
        except Exception as e:
            logging.error(f"Failed to write results to file: {e}")
            logging.debug(traceback.format_exc())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Detect WordPress usage (and possible WP version) via CDP and save fingerprint.json."
    )
    parser.add_argument("url", help="URL to process")
    parser.add_argument("--port", type=int, required=True, help="Chrome remote debugging port")
    parser.add_argument(
        "--output-dir",
        default=os.getenv("CDP_DATA_PATH", "output"),
        help="Directory where results will be saved (default: $CDP_DATA_PATH or 'output')"
    )
    parser.add_argument(
        "--websocket-url",
        default="",
        help="Connect to a specific target WebSocket URL instead of discovering via /json."
    )
    args = parser.parse_args()
    log_dir = os.path.join(args.output_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(log_dir, "fingerprint.log")),
            logging.StreamHandler()
        ]
    )

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    logging.info(f"Starting WordPress detection for URL: {args.url}")
    provided_ws = args.websocket_url or None
    asyncio.run(main(args.url, args.port, args.output_dir, provided_ws))
    print("Done")
