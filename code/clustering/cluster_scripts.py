
import argparse
import json
import os
import sys
import logging
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
from tqdm import tqdm

try:
    from gensim.models import Word2Vec
except Exception as exc:
    Word2Vec = None
    _W2V_IMPORT_ERROR = exc
else:
    _W2V_IMPORT_ERROR = None

try:
    import hdbscan
except Exception as exc:
    hdbscan = None
    _HDBSCAN_IMPORT_ERROR = exc
else:
    _HDBSCAN_IMPORT_ERROR = None

import zstandard as zstd
from sklearn.manifold import TSNE

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("diffcms.cluster")

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_ROOT = SCRIPT_DIR.parent / "data" / "event_data"
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "output"

REPORT_CANDIDATES = (
    "changed_js_report_v2.json",
    "changed_json_report_v2.json",
    "changed_js_report.json",
    "changed_json_report.json",
)

IGNORED_PAYLOAD_TYPES = {"Monitoring Started"}
IGNORED_PAYLOAD_KEYS = {"type", "registrationStack", "stack", "timestamp", "note"}
TYPE_KEY_WHITELIST = {
    "Storage Event": ("key", "url"),
    "Beacon API Call": ("url",),
    "getUserMedia Call": ("constraints",),
    "enumerateDevices Call": (),
    "IndexedDB Open": ("name",),
    "Cache API Open": ("cacheName",),
    "Cache API Match": ("request",),
    "PushManager Subscribe": ("options",),
    "Notification Request Permission": (),
    "WebGL Context Creation": ("contextType",),
    "Canvas toDataURL": ("tagName",),
    "DOM Property Read": ("object", "property"),
    "DOM Property Write": ("object", "property"),
    "Cookie Update": ("value",),
    "Cookie Read": ("value",),
    "XHR Request": ("method", "url"),
    "XHR Response": ("url", "status"),
    "Fetch Request": ("url",),
    "Fetch Response": ("url", "status"),
    "Timeout (Function) Set": ("delay",),
    "Timeout (String) Set": ("delay", "codeLength"),
    "Interval (Function) Set": ("delay",),
    "Interval (String) Set": ("delay", "codeLength"),
    "History PushState": ("url",),
    "History ReplaceState": ("url",),
    "History Popstate": (),
    "WebSocket Connection": ("url",),
    "WebSocket Send": ("url", "dataType"),
    "WebSocket Receive (onmessage)": ("url", "dataType"),
    "WebSocket Receive (addEventListener)": ("url", "dataType"),
    "Error": ("message", "source"),
    "Unhandled Promise Rejection": ("reason",),
    "IntersectionObserver Created": ("options",),
    "ResizeObserver Created": (),
    "Service Worker Registration": ("scriptURL",),
    "Web Worker Created": ("scriptURL",),
    "Worker PostMessage (to worker)": ("scriptURL",),
    "Worker Message (from worker, onmessage)": ("scriptURL",),
    "Worker Message (from worker, addEventListener)": ("scriptURL",),
    "BroadcastChannel Created": ("name",),
    "Geolocation getCurrentPosition": ("options",),
    "Geolocation watchPosition": ("options",),
    "Event Listener Added": ("eventType",),
    "Object.defineProperty Called": ("property",),
    "Script Src Set": ("srcType", "srcHost"),
    "Inline Script Injected": ("contentLength",),
    "IFrame Created (Potential Context Escape)": ("iframeNumber",),
    "WARNING: Multiple IFrames Created": ("count",),
    "Form Submitted": ("action", "method", "fieldCount"),
    "Sensitive Field Read": ("fieldType", "fieldName"),
    "Sensitive Field Write": ("fieldType", "fieldName"),
    "IFrame Src Set": ("src",),
    "setAttribute Called": ("tagName", "attribute"),
    "postMessage Called": ("targetOrigin",),
    "postMessage Received": ("origin",),
    "DOM Mutation": ("method", "target"),
    "Eval Call": ("codeLength",),
    "Function Constructor": ("codeLength",),
    "Suspicious querySelector": ("selector",),
    "Suspicious getElementById": ("id",),
    "atob De-obfuscation": ("outputLength",),
    "String.fromCharCode De-obfuscation": ("outputLength",),
    "JSON.parse Suspicious Payload": ("lengthBucket", "hasHTML", "hasCodeKeyword", "hasURL"),
    "Document.write Call": ("contentLength", "isScript"),
    "Document.writeln Call": ("contentLength", "isScript"),
    "HTML Property Write (Suspicious)": ("object", "property", "target"),
    "Popup Opened": ("url", "target"),
    "Redirect via location.href": ("newUrl",),
    "Redirect via location.replace": ("newUrl",),
    "Redirect via location.assign": ("newUrl",),
    "Page Unload/Redirect Initiated": ("currentUrl",),
    "Page Unloaded": (),
    "Alert Dialog": ("message",),
    "Confirm Dialog": ("message",),
    "Prompt Dialog": ("message",),
    "Blob URL Created": ("blobType",),
    "Download Triggered": ("href",),
    "Window Blur (Possible Popup)": (),
    "Fullscreen Requested": ("element",),
    "Clipboard Write": ("textLength",),
    "Clipboard Read": (),
    "Shadow DOM Attached": ("element",),
    "Hook Detection Attempt": ("functionName",),
    "MutationObserver (Native)": ("mutationType", "target"),
    "Monitoring Script Fully Loaded": ("version",),
}

def _cpu_workers():
    return max(1, (os.cpu_count() or 1) - 1)

def parse_args():
    parser = argparse.ArgumentParser(description="Cluster script traces with DTW + HDBSCAN.")
    parser.add_argument(
        "--data-root",
        default=str(DEFAULT_DATA_ROOT),
        help="Root folder with event_data/* directories.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Folder where clustering artifacts are stored.",
    )
    parser.add_argument("--min-trace-length", type=int, default=3, help="Drop traces shorter than this many tokens.")
    parser.add_argument(
        "--distance-metric",
        choices=("doc2vec", "dtw"),
        default="doc2vec",
        help="Distance metric for clustering (Doc2Vec cosine or DTW over tokens).",
    )
    parser.add_argument("--vector-size", type=int, default=64, help="Embedding dimension for Word2Vec.")
    parser.add_argument("--window-size", type=int, default=5, help="Word2Vec window size.")
    parser.add_argument("--min-token-count", type=int, default=1, help="Ignore tokens that appear fewer times.")
    parser.add_argument("--tsne-perplexity", type=float, default=15.0, help="Perplexity for the 3D t-SNE projection.")
    parser.add_argument("--random-seed", type=int, default=42, help="Random seed for determinism.")
    parser.add_argument(
        "--token-dump",
        default=None,
        help="Optional path to write the sorted list of tokens + counts (defaults to <output-dir>/tokens.txt).",
    )
    return parser.parse_args()

def main():
    args = parse_args()

    if hdbscan is None:
        raise RuntimeError(
            "hdbscan package is required for clustering. Install it and re-run. "
            f"Original error: {_HDBSCAN_IMPORT_ERROR}"
        )
    if Word2Vec is None:
        raise RuntimeError(
            "gensim (Word2Vec) is required for embedding-based distances. "
            f"Install it and re-run. Original error: {_W2V_IMPORT_ERROR}"
        )

    data_root = Path(args.data_root)
    if not data_root.exists():
        raise FileNotFoundError(f"Data root {data_root} does not exist.")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    token_dump_path = Path(args.token_dump) if args.token_dump else output_dir / "tokens.txt"

    logger.info("Scanning traces under %s", data_root)
    traces, sequences = load_all_traces(data_root, min_length=args.min_trace_length)
    if not traces:
        logger.warning("No traces extracted. Nothing to cluster.")
        return

    logger.info("Extracted %d traces with %d total tokens", len(traces), sum(len(seq) for seq in sequences))

    logger.info("Writing token inventory to %s", token_dump_path)
    export_token_inventory(sequences, token_dump_path)

    logger.info("Training Word2Vec embeddings with %d workers", _cpu_workers())
    embedding_model = train_embeddings(
        sequences,
        vector_size=args.vector_size,
        window=args.window_size,
        min_count=args.min_token_count,
        seed=args.random_seed,
    )

    if args.distance_metric == "doc2vec":
        logger.info("Computing Doc2Vec-style cosine distance matrix")
        doc_vectors = compute_doc_vectors(sequences, embedding_model)
        dist_matrix = cosine_distance_matrix(doc_vectors)
    else:
        logger.info("Computing DTW distance matrix")
        dist_matrix = compute_distance_matrix_dtw(sequences, embedding_model)

    dist_matrix = dist_matrix.astype(np.float64, copy=False)

    logger.info("Running HDBSCAN on %s distances", args.distance_metric.upper())
    clusterer, labels = cluster_sequences(dist_matrix)

    logger.info("Projecting traces into 3D t-SNE space")
    tsne_coords = compute_tsne(dist_matrix, perplexity=args.tsne_perplexity, seed=args.random_seed)

    logger.info("Persisting clustering artifacts")
    save_artifacts(
        traces=traces,
        sequences=sequences,
        labels=labels,
        clusterer=clusterer,
        tsne_coords=tsne_coords,
        output_dir=output_dir,
    )

    logger.info("Finished. Results stored in %s/cluster_results.json", output_dir)

def load_all_traces(data_root, min_length):
    traces = []
    sequences = []

    tasks = []
    for domain_dir in sorted(p for p in data_root.iterdir() if p.is_dir()):
        domain = domain_dir.name
        for diff_dir in sorted(p for p in domain_dir.iterdir() if p.is_dir()):
            tasks.append((domain, str(diff_dir), min_length))

    if not tasks:
        return traces, sequences

    with ProcessPoolExecutor(max_workers=_cpu_workers()) as executor:
        for result in tqdm(executor.map(_process_diff_task, tasks), total=len(tasks), desc="Extracting traces"):
            if not result:
                continue
            for trace_meta, compressed in result:
                traces.append(trace_meta)
                sequences.append(compressed)

    return traces, sequences

def _process_diff_task(task):
    domain, diff_dir_str, min_length = task
    diff_dir = Path(diff_dir_str)
    report = read_changed_report(diff_dir)
    if not report or not report.get("target_found"):
        return []
    script_ids = [str(sid) for sid in report.get("script_ids", [])]
    if not script_ids:
        return []
    trace_file = diff_dir / "trace_v2.json.zst"
    if not trace_file.exists():
        trace_file = diff_dir / "trace_v2.json"
    if not trace_file.exists():
        return []
    script_tokens = extract_tokens_from_trace(trace_file=trace_file, target_script_ids=script_ids)
    results = []
    for script_id, tokens in script_tokens.items():
        compressed = compress_tokens(tokens)
        if len(compressed) < min_length:
            continue
        trace_id = f"{domain}_{diff_dir.name}_{script_id}"
        trace_meta = {
            "trace_id": trace_id,
            "domain": domain,
            "diff_hash": diff_dir.name,
            "script_id": script_id,
            "source_url": report.get("source_url", ""),
            "page_url": report.get("page_url", ""),
        }
        results.append((trace_meta, compressed))
    return results

def read_changed_report(diff_dir):
    for candidate in REPORT_CANDIDATES:
        path = diff_dir / candidate
        if path.exists():
            try:
                with path.open("r", encoding="utf-8") as fh:
                    return json.load(fh)
            except json.JSONDecodeError:
                continue
    return None

def extract_tokens_from_trace(trace_file, target_script_ids):
    events = load_trace_events(trace_file)
    if not events:
        return {}

    tokens_by_script = {sid: [] for sid in target_script_ids}

    for record in events:
        event = record.get("event") or {}
        if event.get("method") != "Runtime.consoleAPICalled":
            continue
        params = event.get("params") or {}
        frames = (params.get("stackTrace") or {}).get("callFrames") or []
        scripts_hit = {
            sid for sid in target_script_ids if any(frame.get("scriptId") == sid for frame in frames)
        }
        if not scripts_hit:
            continue
        payloads = parse_console_payloads(params.get("args") or [])
        if not payloads:
            continue
        tokens = [payload_to_token(payload) for payload in payloads]
        tokens = [token for token in tokens if token]
        if not tokens:
            continue
        for sid in scripts_hit:
            tokens_by_script[sid].extend(tokens)

    tokens_by_script = {sid: toks for sid, toks in tokens_by_script.items() if toks}
    return tokens_by_script

def load_trace_events(trace_file):
    try:
        if trace_file.suffix == ".zst":
            if zstd is None:
                logger.warning("zstandard not available; skipping %s", trace_file)
                return []
            with trace_file.open("rb") as fh:
                with zstd.ZstdDecompressor().stream_reader(fh) as reader:
                    data = reader.read()
            return json.loads(data.decode("utf-8"))
        with trace_file.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []

def parse_console_payloads(args):
    payloads = []
    for arg in args:
        if arg.get("type") != "string":
            continue
        value = arg.get("value")
        if not isinstance(value, str):
            continue
        value = value.strip()
        if not value:
            continue
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            payloads.append(payload)
    return payloads

def payload_to_token(payload):
    payload_type = payload.get("type")
    if not payload_type or payload_type in IGNORED_PAYLOAD_TYPES:
        return None

    payload = enrich_payload(payload, payload_type)

    parts = [payload_type]
    allowed_keys = TYPE_KEY_WHITELIST.get(payload_type)
    if allowed_keys is not None:
        candidate_keys = [key for key in allowed_keys if key in payload]
    else:
        candidate_keys = sorted(payload.keys())
    for key in candidate_keys:
        if key in IGNORED_PAYLOAD_KEYS:
            continue
        normalized = normalize_value(payload[key], key, payload_type)
        if normalized is None:
            continue
        parts.append(f"{key}={normalized}")
    return "|".join(parts) if len(parts) > 1 else parts[0]

def enrich_payload(payload, payload_type):
    if payload_type == "JSON.parse Suspicious Payload":
        preview = payload.get("textPreview") or ""
        enriched = dict(payload)
        enriched.pop("textPreview", None)
        enriched.update(summarize_json_preview(preview))
        return enriched
    if payload_type == "Script Src Set":
        enriched = dict(payload)
        enriched.pop("src", None)
        enriched.update(summarize_script_src(payload.get("src")))
        return enriched
    return payload

def summarize_json_preview(preview):
    text = (preview or "")[:400]
    length = len(text)
    if length == 0:
        bucket = "empty"
    elif length < 50:
        bucket = "<50"
    elif length < 100:
        bucket = "50-100"
    elif length < 200:
        bucket = "100-200"
    else:
        bucket = ">=200"

    lower = text.lower()

    def flag(condition):
        return "true" if condition else "false"

    has_html = "<script" in lower or "</" in lower or "<iframe" in lower or "<img" in lower
    code_keywords = ("function", "var ", "=>", "return", "eval", "while", "for(")
    has_code = any(keyword in lower for keyword in code_keywords)
    has_url = "http://" in lower or "https://" in lower or "www." in lower or "://" in lower

    return {
        "lengthBucket": bucket,
        "hasHTML": flag(has_html),
        "hasCodeKeyword": flag(has_code),
        "hasURL": flag(has_url),
    }

def summarize_script_src(src):
    if not src:
        return {"srcType": "empty"}
    text = src.strip()
    lowered = text.lower()
    if lowered.startswith("data:"):
        return {"srcType": "data"}
    if lowered.startswith("blob:"):
        return {"srcType": "blob"}
    if lowered.startswith("javascript:"):
        return {"srcType": "javascript"}
    if lowered.startswith("//"):
        parsed = urlparse("http:" + lowered)
    else:
        parsed = urlparse(text)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        host = parsed.hostname.lower()
        return {"srcType": "remote", "srcHost": host}
    if text.startswith("/"):
        return {"srcType": "relative"}
    return {"srcType": "other"}

def normalize_value(value, key=None, payload_type=None):
    if value is None:
        return None
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        if payload_type in {"Cookie Update", "Cookie Read"} and key == "value":
            cookie_name = cleaned.split(";", 1)[0]
            cookie_name = cookie_name.split("=", 1)[0].strip()
            return cookie_name or None
        if key == "tagName":
            return cleaned.upper()
        if key in {"attribute", "fieldName", "eventType"}:
            return cleaned.lower()
        if key and "url" in key.lower():
            parsed = urlparse(cleaned)
            host = parsed.hostname or ""
            path_bits = [segment for segment in (parsed.path or "/").split("/") if segment]
            weak_path = "/" + "/".join(path_bits[:2]) if path_bits else "/"
            if host:
                return f"{host}{weak_path}"
        if len(cleaned) > 80:
            cleaned = cleaned[:77] + "..."
        return cleaned
    if isinstance(value, dict):
        if key == "target":
            return normalize_dom_target(value)
        items = []
        for sub_key in sorted(value.keys()):
            if sub_key in IGNORED_PAYLOAD_KEYS:
                continue
            sub_val = normalize_value(value[sub_key], sub_key, payload_type)
            if sub_val is None:
                continue
            items.append(f"{sub_key}:{sub_val}")
            if len(items) >= 4:
                break
        return "{" + ",".join(items) + "}" if items else None
    if isinstance(value, list):
        parts = []
        for item in value[:4]:
            normalized = normalize_value(item, payload_type=payload_type)
            if normalized:
                parts.append(normalized)
        ellipsis = "..." if len(value) > 4 else ""
        return "[" + ",".join(parts) + ellipsis + "]" if parts else None
    return str(value)

def normalize_dom_target(node):
    if not isinstance(node, dict):
        return None
    tag = node.get("tagName") or node.get("nodeName") or ""
    if not tag:
        node_type = node.get("nodeType")
        if isinstance(node_type, str):
            tag = node_type
        else:
            tag = "node"
    tag = tag.upper()
    return tag

def compress_tokens(tokens):
    compressed = []
    last_token = None
    for token in tokens:
        if token != last_token:
            compressed.append(token)
            last_token = token
    return compressed

def export_token_inventory(sequences, path):
    counter = Counter()
    for seq in sequences:
        counter.update(seq)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for token, count in counter.most_common():
            fh.write(f"{count}\t{token}\n")

def train_embeddings(sequences, vector_size, window, min_count, seed):
    workers = max(1, (os.cpu_count() or 1) - 1)
    model = Word2Vec(
        sentences=sequences,
        vector_size=vector_size,
        window=window,
        min_count=min_count,
        sg=1,
        sample=1e-3,
        seed=seed,
        workers=workers,
    )
    return model

def compute_doc_vectors(sequences, model):
    def embed(sequence):
        embeddings = [model.wv[token] for token in sequence if token in model.wv]
        if embeddings:
            vec = np.mean(embeddings, axis=0)
            norm = np.linalg.norm(vec)
            if norm > 0.0:
                vec = vec / norm
        else:
            vec = np.zeros(model.vector_size, dtype=np.float32)
        return vec.astype(np.float32)

    vectors = []
    with ThreadPoolExecutor(max_workers=_cpu_workers()) as executor:
        for vec in tqdm(executor.map(embed, sequences), total=len(sequences), desc="Doc2Vec vectors"):
            vectors.append(vec)
    return np.vstack(vectors)

def cosine_distance_matrix(vectors):
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    normalized = vectors / np.where(norms == 0.0, 1.0, norms)
    size = normalized.shape[0]
    matrix = np.zeros((size, size), dtype=np.float64)

    def compute_row(idx):
        row = 1.0 - np.clip(np.dot(normalized[idx], normalized.T), -1.0, 1.0)
        row[idx] = 0.0
        return idx, row

    with ThreadPoolExecutor(max_workers=_cpu_workers()) as executor:
        futures = [executor.submit(compute_row, i) for i in range(size)]
        for future in tqdm(as_completed(futures), total=size, desc="Cosine distances"):
            idx, row = future.result()
            matrix[idx] = row
    matrix = (matrix + matrix.T) / 2.0
    return matrix.astype(np.float64)

def compute_distance_matrix_dtw(sequences, model):
    size = len(sequences)
    matrix = np.zeros((size, size), dtype=np.float32)
    for i in range(size):
        matrix[i, i] = 0.0
    for i in tqdm(range(size), desc="DTW distances"):
        for j in range(i + 1, size):
            dist = dtw_distance(sequences[i], sequences[j], model)
            matrix[i, j] = matrix[j, i] = dist
    return matrix

def dtw_distance(seq_a, seq_b, model):
    len_a, len_b = len(seq_a), len(seq_b)
    if len_a == 0 or len_b == 0:
        return float(max(len_a, len_b))
    dp = np.full((len_a + 1, len_b + 1), np.inf, dtype=np.float32)
    dp[0, 0] = 0.0
    for i in range(1, len_a + 1):
        dp[i, 0] = np.inf
    for j in range(1, len_b + 1):
        dp[0, j] = np.inf
    for i in range(1, len_a + 1):
        for j in range(1, len_b + 1):
            cost = substitution_cost(seq_a[i - 1], seq_b[j - 1], model)
            dp[i, j] = cost + min(dp[i - 1, j], dp[i, j - 1], dp[i - 1, j - 1])
    return float(dp[len_a, len_b] / (len_a + len_b))

def substitution_cost(token_a, token_b, model):
    if token_a == token_b:
        return 0.0
    vocab = model.wv
    if token_a in vocab and token_b in vocab:
        vec_a = vocab[token_a]
        vec_b = vocab[token_b]
        norm_a = np.linalg.norm(vec_a)
        norm_b = np.linalg.norm(vec_b)
        if norm_a > 0.0 and norm_b > 0.0:
            cosine = float(np.dot(vec_a, vec_b) / (norm_a * norm_b))
            cosine = max(-1.0, min(1.0, cosine))
            return 1.0 - cosine
    return 1.0

def cluster_sequences(dist_matrix):
    clusterer = hdbscan.HDBSCAN(metric="precomputed", min_cluster_size=2, allow_single_cluster=True)
    labels = clusterer.fit_predict(dist_matrix)
    return clusterer, labels

def compute_tsne(dist_matrix, perplexity, seed):
    n_samples = dist_matrix.shape[0]
    if n_samples <= 3:
        coords = np.zeros((n_samples, 3), dtype=np.float32)
        for idx in range(n_samples):
            coords[idx, :] = idx
        return coords
    effective_perplexity = min(perplexity, max(1.0, (n_samples - 1) / 3.0))
    tsne = TSNE(
        n_components=3,
        metric="precomputed",
        perplexity=effective_perplexity,
        init="random",
        random_state=seed,
    )
    return tsne.fit_transform(dist_matrix)

def save_artifacts(traces, sequences, labels, clusterer, tsne_coords, output_dir):
    results = []
    for idx, trace in enumerate(traces):
        tsne_point = tsne_coords[idx] if idx < len(tsne_coords) else (0.0, 0.0, 0.0)
        result = {
            **trace,
            "tokens": list(sequences[idx]),
            "cluster_label": int(labels[idx]),
            "cluster_score": float(clusterer.probabilities_[idx]),
            "tsne": {
                "x": float(tsne_point[0]),
                "y": float(tsne_point[1]),
                "z": float(tsne_point[2]),
            },
        }
        results.append(result)
    output_path = output_dir / "cluster_results.json"
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
