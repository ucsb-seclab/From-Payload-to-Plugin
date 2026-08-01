import gzip
import hashlib
import json
import logging
import os
import socket
import sqlite3
import threading
import time
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import redis

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "queues.db")
HTTP_PORT = int(os.getenv("HTTP_PORT", 8282))

def get_redis_connection():
    while True:
        try:
            connection = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
            if connection.ping():
                logging.info("Connected to Redis successfully.")
                return connection
        except redis.ConnectionError as e:
            logging.error(f"Redis connection error: {e}. Retrying in 5 seconds...")
            time.sleep(5)

def get_sqlite_connection():
    conn = sqlite3.connect(SQLITE_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS queue_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_queue TEXT NOT NULL,
            complete_queue TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn

def generate_queue_names():
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    task_queue = f"task-queue-{timestamp}"
    complete_queue = f"complete-queue-{timestamp}"
    return task_queue, complete_queue

def record_queues_sqlite(task_queue, complete_queue):
    try:
        sqlite_conn = get_sqlite_connection()
        cursor = sqlite_conn.cursor()
        cursor.execute(
            "INSERT INTO queue_list (task_queue, complete_queue) VALUES (?, ?)",
            (task_queue, complete_queue)
        )
        sqlite_conn.commit()
        logging.info(f"Recorded queues in SQLite: task: {task_queue}, complete: {complete_queue}")
    except Exception as e:
        logging.error(f"Error recording queues in SQLite: {e}")
    finally:
        sqlite_conn.close()

def normalize_domain_to_url(domain):
    domain = (domain or "").strip()
    if not domain:
        return ""
    if domain.startswith(("http://", "https://")):
        return domain
    return f"https://{domain}"

def bulk_enqueue_urls(redis_conn, url_stream):
    try:
        domains = [line.strip() for line in url_stream.splitlines() if line.strip()]
        if not domains:
            logging.warning("No URLs provided in the stream.")
            return False

        task_queue, complete_queue = generate_queue_names()
        pipeline = redis_conn.pipeline()

        for domain in domains:
            domain_id = hashlib.sha256(domain.encode("utf-8")).hexdigest()
            job_data = {
                "id": domain_id,
                "url": domain,
                "task_queue": task_queue,
                "complete_queue": complete_queue,
                "status": "queued",
            }
            pipeline.rpush(task_queue, json.dumps(job_data))

        pipeline.execute()
        logging.info(f"Bulk enqueued {len(domains)} URLs from stream into {task_queue}.")
        record_queues_sqlite(task_queue, complete_queue)
        return True
    except Exception as e:
        logging.error(f"Error during bulk enqueue from URL stream: {e}")
    return False

def bulk_enqueue_changed_js(redis_conn, json_payload, task_queue=None, complete_queue=None):
    try:
        entries = json.loads(json_payload)
    except json.JSONDecodeError as err:
        logging.error(f"Invalid changed JS payload: {err}")
        return False

    if not isinstance(entries, list):
        logging.error("Changed JS payload must be a list of job objects.")
        return False

    reuse_existing_queue = bool(task_queue and complete_queue)
    if not reuse_existing_queue:
        task_queue, complete_queue = generate_queue_names()
    pipeline = redis_conn.pipeline()
    enqueued = 0

    for entry in entries:
        if not isinstance(entry, dict):
            logging.warning(f"Skipping malformed entry (expected dict): {entry}")
            continue

        domain = (entry.get("domain") or "").strip()
        source_url = (entry.get("source_url") or "").strip()
        script_sha256 = (entry.get("script_sha256") or "").strip()
        diff_signature = (entry.get("diff_signature") or "").strip()

        if not domain or not source_url or not script_sha256:
            logging.warning(f"Skipping incomplete changed JS entry: {entry}")
            continue

        if source_url.startswith("loaded_js/inline"):
            logging.info(f"Skipping inline script submission for domain {domain} ({source_url}).")
            continue

        destination_url = normalize_domain_to_url(domain)
        if not destination_url:
            logging.warning(f"Unable to normalize domain '{domain}' to URL.")
            continue

        seed = f"{domain}|{source_url}|{script_sha256}|{diff_signature}"
        job_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()
        job_data = {
            "id": job_id,
            "url": destination_url,
            "task_queue": task_queue,
            "complete_queue": complete_queue,
            "status": "queued",
            "job_type": "changed_js",
            "domain": domain,
            "source_url": source_url,
            "script_sha256": script_sha256,
            "diff_signature": diff_signature,
        }
        pipeline.rpush(task_queue, json.dumps(job_data))
        enqueued += 1

    if enqueued:
        pipeline.execute()
        logging.info(f"Bulk enqueued {enqueued} changed JS jobs into {task_queue}.")
        if not reuse_existing_queue:
            record_queues_sqlite(task_queue, complete_queue)
        return True

    logging.warning("No valid changed JS jobs were queued.")
    return False

COMMAND_DEFINITIONS = [
    {
        "name": "bulk",
        "prefix": b"BULK::BEGIN",
        "sentinel": b"BULK::END",
        "handler": bulk_enqueue_urls,
        "success_response": b"Bulk submission received.\n",
        "empty_response": b"No URLs were enqueued.\n",
    },
    {
        "name": "changed_js",
        "prefix": b"CHANGEDJS::BEGIN",
        "sentinel": b"CHANGEDJS::END",
        "handler": bulk_enqueue_changed_js,
        "success_response": b"Changed JS submission received.\n",
        "empty_response": b"No changed JS jobs were enqueued.\n",
    },
]

QUEUE_HANDLES = {}
QUEUE_HANDLE_LOCK = threading.Lock()

def allocate_queue_handle():
    with QUEUE_HANDLE_LOCK:
        handle = uuid.uuid4().hex
        task_queue, complete_queue = generate_queue_names()
        QUEUE_HANDLES[handle] = (task_queue, complete_queue)
        record_queues_sqlite(task_queue, complete_queue)
    logging.info(f"Allocated queue handle {handle} -> {task_queue}/{complete_queue}")
    return handle, task_queue, complete_queue

def resolve_queue_handle(handle):
    with QUEUE_HANDLE_LOCK:
        return QUEUE_HANDLES.get(handle)

def release_queue_handle(handle):
    with QUEUE_HANDLE_LOCK:
        if handle in QUEUE_HANDLES:
            logging.info(f"Releasing queue handle {handle}")
            del QUEUE_HANDLES[handle]

def make_http_handler(redis_conn):
    class SubmissionHandler(BaseHTTPRequestHandler):
        server_version = "CompwebHTTP/1.0"

        def _set_headers(self, status_code, message=""):
            self.send_response(status_code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            if message:
                self.wfile.write(message.encode())

        def do_POST(self):
            if self.path == "/queue":
                handle, task_queue, complete_queue = allocate_queue_handle()
                response = json.dumps({
                    "queue_id": handle,
                    "task_queue": task_queue,
                    "complete_queue": complete_queue,
                })
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(response.encode())
                return
            if self.path != "/submit-changedjs":
                self._set_headers(404, "Not Found")
                return

            length = int(self.headers.get("Content-Length", 0))
            if length <= 0:
                self._set_headers(400, "Empty payload")
                return

            raw_body = self.rfile.read(length)
            encoding = (self.headers.get("Content-Encoding") or "").lower()
            try:
                if encoding == "gzip":
                    raw_body = gzip.decompress(raw_body)
                elif encoding and encoding != "identity":
                    logging.warning(f"Unsupported encoding '{encoding}' on HTTP submission.")
            except OSError as e:
                logging.error(f"Failed to decompress HTTP payload: {e}")
                self._set_headers(400, "Invalid compressed payload")
                return

            payload = raw_body.decode(errors="ignore")
            queue_id = self.headers.get("X-Queue-ID")
            final_flag = (self.headers.get("X-Queue-Final") or "").lower() == "true"
            task_queue = complete_queue = None
            if queue_id:
                resolved = resolve_queue_handle(queue_id)
                if not resolved:
                    self._set_headers(400, "Unknown queue handle.")
                    return
                task_queue, complete_queue = resolved

            handled = bulk_enqueue_changed_js(redis_conn, payload, task_queue, complete_queue)
            if handled:
                if queue_id and final_flag:
                    release_queue_handle(queue_id)
                logging.info("HTTP changed JS submission processed successfully.")
                self._set_headers(200, "Changed JS submission received.")
            else:
                logging.warning("HTTP changed JS submission failed validation.")
                self._set_headers(400, "No valid changed JS jobs were queued.")

        def log_message(self, format, *args):
            logging.info("HTTP %s - %s", self.address_string(), format % args)

    return SubmissionHandler

def start_http_server(redis_conn):
    handler_cls = make_http_handler(redis_conn)
    httpd = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), handler_cls)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    logging.info(f"HTTP server listening on port {HTTP_PORT} for changed JS submissions.")
    return httpd

def process_connection(redis_conn, connection):
    try:
        buffer = bytearray()
        first_chunk = connection.recv(4096)
        if not first_chunk:
            logging.warning("Connection closed before any data was received.")
            connection.sendall(b"No URL stream received.\n")
            return

        buffer.extend(first_chunk)

        selected_command = None
        for command in COMMAND_DEFINITIONS:
            prefix = command["prefix"]
            if buffer.startswith(prefix):
                selected_command = command
                buffer = bytearray(buffer[len(prefix):].lstrip())
                break

        if not selected_command:
            logging.error("Received unknown submission prefix.")
            connection.sendall(b"Unknown submission format.\n")
            return

        sentinel = selected_command["sentinel"]

        while True:
            end_index = buffer.find(sentinel)
            if end_index != -1:
                payload = bytes(buffer[:end_index])
                break

            chunk = connection.recv(4096)
            if not chunk:
                logging.error("Connection closed before submission sentinel was received.")
                connection.sendall(b"Error processing request.\n")
                return
            buffer.extend(chunk)

        complete_stream = payload.decode(errors="ignore")
        handled = selected_command["handler"](redis_conn, complete_stream)
        if handled:
            connection.sendall(selected_command["success_response"])
        else:
            connection.sendall(selected_command.get("empty_response", b"No jobs were enqueued.\n"))
    except Exception as e:
        logging.error(f"Error processing connection: {e}")
        connection.sendall(b"Error processing request.\n")
    finally:
        connection.close()

def main():
    redis_conn = get_redis_connection()
    http_server = start_http_server(redis_conn)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 8181))
    sock.listen(5)
    logging.info("Server listening on port 8181...")

    while True:
        try:
            connection, client_address = sock.accept()
            logging.info(f"Accepted connection from {client_address}")
            process_connection(redis_conn, connection)
        except KeyboardInterrupt:

            logging.info("Shutting down server.")
            break
        except Exception as e:
            logging.error(f"Unexpected error: {e}")

def shutdown_server(sock):
    sock.close()
    logging.info("Server socket closed.")

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )
    main()
