import json
import os
import socket
import sqlite3
import subprocess
import gzip
from pathlib import Path

import click
from click import style
import redis
import requests
from tabulate import tabulate

REDIS_HOST = "localhost"
REDIS_PORT = 6379

CONFIG_DIR = os.path.join(Path.home(), ".scanctrconfig")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.txt")

SQLITE_DB_PATH = os.path.join(CONFIG_DIR, "queues.db")
SOCKET_TIMEOUT = int(os.environ.get("SCANCTR_SOCKET_TIMEOUT_SECONDS", "300"))
HTTP_ENDPOINT = os.environ.get("SCANCTR_HTTP_ENDPOINT", "http://localhost:8282/submit-changedjs")
HTTP_QUEUE_ENDPOINT = os.environ.get("SCANCTR_HTTP_QUEUE_ENDPOINT") or (
    HTTP_ENDPOINT.rsplit("/", 1)[0] + "/queue"
)
CHANGEDJS_BATCH_SIZE = int(os.environ.get("SCANCTR_CHANGEDJS_BATCH_SIZE", "500"))
SUBMIT_METHOD = os.environ.get("SCANCTR_SUBMIT_METHOD", "http").lower()

BANNER = r"""
███████╗ ██████╗ █████╗ ███╗   ██╗ ██████╗████████╗██████╗ 
██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝╚══██╔══╝██╔══██╗
███████╗██║     ███████║██╔██╗ ██║██║        ██║   ██████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║██║        ██║   ██╔══██╗
███████║╚██████╗██║  ██║██║ ╚████║╚██████╗   ██║   ██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝

ScanCTR - code by AmmoniA
"""

def log_info(message):
    click.echo(style(message, fg="cyan"))

def log_success(message):
    click.echo(style(message, fg="green"))

def log_warn(message):
    click.echo(style(message, fg="yellow"))

def log_error(message):
    click.echo(style(message, fg="red"))

def print_banner():
    click.echo(style(BANNER, fg="cyan"))

def load_config():
    if not os.path.isfile(CONFIG_FILE):
        return None
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()

def save_config(compose_path):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        f.write(compose_path)

def fix_compose_path(path):
    if os.path.isdir(path):
        path = os.path.join(path, "docker-compose.yml")
    return path

def get_compose_file_path():
    compose_path = load_config()
    if compose_path:
        compose_path = fix_compose_path(compose_path)
        if os.path.isfile(compose_path):
            return compose_path

        click.echo(style("No valid docker-compose file path found in config.", fg="yellow"))
    compose_path = click.prompt(
        "Please enter the absolute path to your docker-compose.yml (or the directory containing it)",
        type=str
    )

    compose_path = fix_compose_path(compose_path)

    if not os.path.isfile(compose_path):
        raise click.ClickException(style(f"File not found: {compose_path}", fg="red"))

    save_config(compose_path)
    return compose_path

def get_redis_connection():
    try:
        return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
    except Exception as e:
        log_error(f"Error connecting to Redis: {e}")
        return None

def get_sqlite_connection():
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        conn = sqlite3.connect(SQLITE_DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS queue_list (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_queue TEXT NOT NULL,
                complete_queue TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
        return conn
    except Exception as e:
        log_error(f"Error connecting to SQLite at {SQLITE_DB_PATH}: {e}")
        return None

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    if not ctx.invoked_subcommand:
        print_banner()
        click.echo(ctx.command.get_help(ctx))
        ctx.exit()

@cli.command()
def deploy():
    log_info("Deploying the tool")
    compose_file_path = get_compose_file_path()
    cmd = ["docker", "compose", "-f", compose_file_path, "up", "-d", "--build"]
    subprocess.run(cmd, check=True)
    log_success("Deployment complete.")

@cli.command()
def demolish():
    if not click.confirm(style("Are you sure you want to demolish the deployment and wipe the SQLite queue database?",
                         fg="yellow"), default=False):
        log_warn("Demolish cancelled.")
        return

    log_info("Demolishing the deployment")
    compose_file_path = get_compose_file_path()
    try:
        subprocess.run(["docker", "compose", "-f", compose_file_path, "down"], check=True)
        log_success("Deployment removed.")
    except Exception as e:
        log_error(f"Error demolishing deployment: {e}")

    if os.path.isfile(SQLITE_DB_PATH):
        try:
            os.remove(SQLITE_DB_PATH)
            log_success("SQLite queue database file removed.")
        except PermissionError:
            log_error("Permission denied: Unable to remove the SQLite queue database file.")
        except Exception as e:
            log_error(f"Error removing SQLite queue database file: {e}")
    else:
        log_warn("No SQLite queue database file found.")

@cli.command()
@click.argument("service")
@click.argument("replicas", type=int)
def scale(service, replicas):
    click.echo(f"Scaling service '{service}' to {replicas} replicas")
    compose_file_path = get_compose_file_path()
    cmd = [
        "docker", "compose",
        "-f", compose_file_path,
        "up", "-d",
        "--scale", f"{service}={replicas}"
    ]
    subprocess.run(cmd, check=True)
    click.echo(f"Service '{service}' scaled to {replicas} replicas.")

@cli.command()
def wipecache():
    if os.path.isfile(CONFIG_FILE):
        os.remove(CONFIG_FILE)
        click.echo("Config file removed. You will be prompted for the compose path next time.")
    else:
        click.echo("No config file found. Nothing to remove.")

@cli.command()
def queues():
    log_info("Checking all queues from SQLite and syncing with Redis data")

    conn = get_sqlite_connection()
    if conn is None:
        return

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT task_queue, complete_queue FROM queue_list")
        rows = cursor.fetchall()
        if not rows:
            log_warn("No active queues found in SQLite.")
            return

        table_data = []
        r = get_redis_connection()
        if r is None:
            log_error("Unable to connect to Redis.")
            return

        for row in rows:
            task_queue = row["task_queue"]
            complete_queue = row["complete_queue"]

            task_count = r.llen(task_queue)
            complete_count = r.llen(complete_queue)
            task_memory = r.memory_usage(task_queue) or 0
            complete_memory = r.memory_usage(complete_queue) or 0

            table_data.append([
                task_queue,
                task_count,
                f"{task_memory / 1024:.2f} KB",
                complete_queue,
                complete_count,
                f"{complete_memory / 1024:.2f} KB"
            ])

        headers = ["Task Queue", "Pending", "Task Mem", "Complete Queue", "Completed", "Complete Mem"]
        click.echo(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
    except Exception as e:
        log_error(f"Error reading queues from SQLite: {e}")
    finally:
        conn.close()

@cli.command()
def nodes():
    log_info("Checking status of Docker containers")
    subprocess.run(["docker", "ps"])

@cli.command()
@click.argument("queue_name")
@click.option("--output", "-o", default=None, help="Output file to dump data")
def dumpqueue(queue_name, output):
    r = get_redis_connection()
    if r is None:
        log_error("Unable to connect to Redis.")
        return

    try:
        data = r.lrange(queue_name, 0, -1)
        if not data:
            log_warn(f"No data found in queue: {queue_name}")
            return

        if output is None:
            output = f"{queue_name}_dump.txt"

        with open(output, "w", encoding="utf-8") as f:
            for item in data:
                f.write(item.decode() + "\n")
        log_success(f"Queue data dumped to {output}")
    except Exception as e:
        log_error(f"Error dumping queue: {e}")

@cli.command()
@click.argument("queue_name")
def deletequeue(queue_name):
    r = get_redis_connection()
    if r is None:
        log_error("Unable to connect to Redis.")
        return

    try:
        result = r.delete(queue_name)
        if result:
            log_success(f"Queue '{queue_name}' deleted from Redis.")
        else:
            log_warn(f"Queue '{queue_name}' not found in Redis.")
    except Exception as e:
        log_error(f"Error deleting queue: {e}")
        return

    conn = get_sqlite_connection()
    if conn is None:
        return

    try:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM queue_list WHERE task_queue = ? OR complete_queue = ?",
            (queue_name, queue_name)
        )
        conn.commit()
        click.echo(f"SQLite records updated for queue '{queue_name}'.")
    except Exception as e:
        click.echo(f"Error updating SQLite: {e}")
    finally:
        conn.close()

@cli.command()
def wiperedis():
    r = get_redis_connection()
    if r is None:
        log_error("Unable to connect to Redis.")
        return

    try:
        r.flushdb()
        log_success("Entire Redis database wiped.")
    except Exception as e:
        log_error(f"Error wiping Redis: {e}")
        return

    conn = get_sqlite_connection()
    if conn is None:
        return

    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM queue_list")
        conn.commit()
        log_success("SQLite queue records cleared.")
    except Exception as e:
        log_error(f"Error updating SQLite: {e}")
    finally:
        conn.close()

def send_bulk_payload(
    begin_token: str,
    end_token: str,
    payload: str | None,
    success_label: str,
    payload_path: str | None = None,
):
    if payload is None and payload_path is None:
        raise ValueError("Either payload text or payload_path must be provided.")

    def _stream_payload(sock_file):
        if payload_path:
            chunk_size = 1024 * 1024
            log_interval = 25 * 1024 * 1024
            next_log = log_interval
            total_sent = 0
            with open(payload_path, "rb") as fh:
                while True:
                    chunk = fh.read(chunk_size)
                    if not chunk:
                        break
                    sock_file.write(chunk)
                    total_sent += len(chunk)
                    if total_sent >= next_log:
                        log_info(f"  streamed {total_sent / (1024 * 1024):.1f} MB so far")
                        next_log += log_interval
            sock_file.write(b"\n")
        else:
            sock_file.write(payload.encode())

    try:
        with socket.create_connection(("localhost", 8181), timeout=SOCKET_TIMEOUT) as sock:
            sock_file = sock.makefile("wb")
            log_info(f"Connecting to scanning main node on port 8181 (timeout {SOCKET_TIMEOUT}s)")
            log_info("Sending payload header")
            sock_file.write(begin_token.encode() + b"\n")
            _stream_payload(sock_file)
            log_info("Payload stream complete, sending sentinel")
            sock_file.write(b"\n" + end_token.encode() + b"\n")
            sock_file.flush()
            sock.settimeout(SOCKET_TIMEOUT)
            log_info("Waiting for main node response")
            response = sock.recv(4096)
            if response:
                log_success(f"Main node response: {response.decode(errors='replace').strip()}")
            else:
                log_warn(f"{success_label} submission sent, but no response received.")
    except socket.timeout:
        log_error(f"Error submitting {success_label.lower()} scan: timed out waiting for server response.")
    except Exception as e:
        log_error(f"Error submitting {success_label.lower()} scan: {e}")

def submit_changed_js_http(entries):
    if not entries:
        raise click.ClickException("No changed JS entries found to submit.")

    total = len(entries)
    batches = (total + CHANGEDJS_BATCH_SIZE - 1) // CHANGEDJS_BATCH_SIZE
    log_info(
        f"Submitting {total} changed JS jobs to {HTTP_ENDPOINT} "
        f"in batches of {CHANGEDJS_BATCH_SIZE}."
    )

    session = requests.Session()
    headers = {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
    }
    queue_info = request_http_queue_handle()
    queue_id = queue_info["queue_id"]
    log_info(
        f"Using queue handle {queue_id} "
        f"(task={queue_info['task_queue']} complete={queue_info['complete_queue']})."
    )

    for batch_index in range(batches):
        start = batch_index * CHANGEDJS_BATCH_SIZE
        chunk = entries[start:start + CHANGEDJS_BATCH_SIZE]
        payload_bytes = json.dumps(chunk).encode("utf-8")
        compressed = gzip.compress(payload_bytes)
        log_info(f"Sending batch {batch_index + 1}/{batches} ({len(chunk)} jobs, {len(compressed)/1024:.1f} KB gzip)")
        try:
            resp = session.post(
                HTTP_ENDPOINT,
                data=compressed,
                headers={
                    **headers,
                    "X-Queue-ID": queue_id,
                    "X-Queue-Final": "true" if batch_index == batches - 1 else "false",
                },
                timeout=SOCKET_TIMEOUT,
            )
            resp.raise_for_status()
            log_success(f"Batch {batch_index + 1} accepted: {resp.text.strip() or resp.status_code}")
        except requests.RequestException as exc:
            raise click.ClickException(f"HTTP submission failed on batch {batch_index + 1}: {exc}") from exc

def request_http_queue_handle():
    try:
        log_info(f"Requesting queue allocation from {HTTP_QUEUE_ENDPOINT}")
        resp = requests.post(HTTP_QUEUE_ENDPOINT, timeout=SOCKET_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if not all(k in data for k in ("queue_id", "task_queue", "complete_queue")):
            raise click.ClickException("Malformed queue allocation response.")
        log_success(f"Allocated queue handle {data['queue_id']}.")
        return data
    except requests.RequestException as exc:
        raise click.ClickException(f"Failed to allocate queue handle: {exc}") from exc

@cli.command(name="help")
@click.pass_context
def help_command(ctx):
    print_banner()
    click.echo(cli.get_help(ctx))

@cli.command()
@click.option("--file", "file_path", type=click.Path(exists=True), required=True,
              help="File containing domains to submit (one per line)")
def submit(file_path):
    click.echo(f"Submitting bulk scan from file: {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            file_contents = f.read().strip()
        send_bulk_payload("BULK::BEGIN", "BULK::END", file_contents, "Bulk")
    except Exception as e:
        click.echo(f"Error submitting bulk scan: {e}")

@cli.command(name="submit-changedjs")
@click.option("--file", "file_path", type=click.Path(exists=True), required=True,
              help="Path to changed_js.json containing the script diff entries")
def submit_changed_js(file_path):
    log_info(f"Submitting changed JS jobs from file: {file_path}")
    try:
        log_info("Parsing changed JS JSON payload")
        with open(file_path, "r", encoding="utf-8") as fh:
            entries = json.load(fh)
        if not isinstance(entries, list):
            raise click.ClickException("The changed JS file must contain a JSON list of objects.")
        log_success(f"Parsed {len(entries)} changed JS entries.")

        use_http = SUBMIT_METHOD == "http"
        if use_http:
            try:
                submit_changed_js_http(entries)
                return
            except click.ClickException as ce:
                raise ce
            except Exception as exc:
                log_error(f"HTTP submission error: {exc}")
                log_warn("Falling back to raw socket submission")
        else:
            log_warn("HTTP submission disabled via configuration; using raw socket transport.")

        send_bulk_payload(
            "CHANGEDJS::BEGIN",
            "CHANGEDJS::END",
            payload=None,
            success_label="Changed JS",
            payload_path=file_path,
        )
    except click.ClickException as ce:
        raise ce
    except Exception as e:
        log_error(f"Error submitting changed JS jobs: {e}")

if __name__ == "__main__":
    cli()
