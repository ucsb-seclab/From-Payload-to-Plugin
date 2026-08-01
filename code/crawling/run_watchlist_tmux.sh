#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: ./run_watchlist_tmux.sh [options]

Options:
  -f <file>        Path to the watchlist to split (default: watchlist.txt in the current dir)
  -n <count>       Number of splits/panes to create (default: 20)
  -o <dir>         Base output directory for chunk runs (default: results/watchlist_batch_<timestamp>)
  -w <name>        Name for the tmux window that will host the panes (default: watchlist_<timestamp>)
  -p <bin>         Python interpreter to use (default: $PYTHON or python3)
  -t <seconds>     Total timeout passed through to crawl.py (default: crawl.py's internal default)
      --timeout <seconds>      Long-form alias for -t
  -c <count>       Concurrency to pass to crawl.py (default: crawl.py auto-tunes)
      --concurrency <count>    Long-form alias for -c
      --adaptive               Enable crawl.py's adaptive concurrency controller
      --adaptive-min <count>   Override adaptive minimum concurrency
      --adaptive-max <count>   Override adaptive maximum concurrency
      --adaptive-step <count>  Workers added/removed per adjustment
      --adaptive-interval <s>  Seconds between adaptive checks
      --adaptive-reduce <f>    Timeout ratio that triggers reductions
      --adaptive-increase <f>  Timeout ratio below which we increase concurrency
      --adaptive-min-batch <n> Minimum processed items before adapting
      --adaptive-network <mbps> Bandwidth ceiling before reducing concurrency
  -S               Do not automatically focus the new tmux window after launch
  -h               Show this help message
USAGE
}

if ! command -v tmux >/dev/null 2>&1; then
    echo "tmux is required to use this script" >&2
    exit 1
fi

if [[ -z "${TMUX:-}" ]]; then
    echo "Please run this script from inside an active tmux session" >&2
    exit 1
fi

INVOCATION_DIR=$(pwd)
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CRAWL_SCRIPT="$SCRIPT_DIR/crawl.py"
RUN_LABEL=$(date +%Y%m%d_%H%M%S)
SPLIT_COUNT=20
WATCHLIST_FILE="watchlist.txt"
OUTPUT_ROOT="crawls/watchlist_batch_${RUN_LABEL}"
WINDOW_NAME="watchlist_${RUN_LABEL}"
PYTHON_BIN="${PYTHON:-python3}"
AUTO_FOCUS=1
CRAWL_TIMEOUT=""
CRAWL_CONCURRENCY=""
CRAWL_ADAPTIVE=1
ADAPTIVE_MIN_CONC=""
ADAPTIVE_MAX_CONC=""
ADAPTIVE_STEP=""
ADAPTIVE_INTERVAL=""
ADAPTIVE_REDUCE=""
ADAPTIVE_INCREASE=""
ADAPTIVE_MIN_BATCH=""
ADAPTIVE_NET_TARGET=""
RETRY_ATTEMPTS=3
RETRY_DELAY=5
CHUNK_WAIT_TIMEOUT=7200   # seconds to wait per attempt before declaring stuck chunks timed out (0 = no limit)

# Handle long-form options before getopts parses short flags.
parsed_args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout)
            if [[ $# -lt 2 ]]; then
                echo "--timeout requires a numeric value" >&2
                exit 1
            fi
            CRAWL_TIMEOUT="$2"
            shift 2
            ;;
        --timeout=*)
            CRAWL_TIMEOUT="${1#*=}"
            shift
            ;;
        --concurrency)
            if [[ $# -lt 2 ]]; then
                echo "--concurrency requires an integer value" >&2
                exit 1
            fi
            CRAWL_CONCURRENCY="$2"
            shift 2
            ;;
        --concurrency=*)
            CRAWL_CONCURRENCY="${1#*=}"
            shift
            ;;
        --adaptive|--adaptive-concurrency)
            CRAWL_ADAPTIVE=1
            shift
            ;;
        --no-adaptive|--no-adaptive-concurrency)
            CRAWL_ADAPTIVE=0
            shift
            ;;
        --adaptive-min|--adaptive-min-concurrency)
            if [[ $# -lt 2 ]]; then
                echo "--adaptive-min requires an integer value" >&2
                exit 1
            fi
            ADAPTIVE_MIN_CONC="$2"
            shift 2
            ;;
        --adaptive-min=*|--adaptive-min-concurrency=*)
            ADAPTIVE_MIN_CONC="${1#*=}"
            shift
            ;;
        --adaptive-max|--adaptive-max-concurrency)
            if [[ $# -lt 2 ]]; then
                echo "--adaptive-max requires an integer value" >&2
                exit 1
            fi
            ADAPTIVE_MAX_CONC="$2"
            shift 2
            ;;
        --adaptive-max=*|--adaptive-max-concurrency=*)
            ADAPTIVE_MAX_CONC="${1#*=}"
            shift
            ;;
        --adaptive-step)
            if [[ $# -lt 2 ]]; then
                echo "--adaptive-step requires an integer value" >&2
                exit 1
            fi
            ADAPTIVE_STEP="$2"
            shift 2
            ;;
        --adaptive-step=*)
            ADAPTIVE_STEP="${1#*=}"
            shift
            ;;
        --adaptive-interval)
            if [[ $# -lt 2 ]]; then
                echo "--adaptive-interval requires a numeric value" >&2
                exit 1
            fi
            ADAPTIVE_INTERVAL="$2"
            shift 2
            ;;
        --adaptive-interval=*)
            ADAPTIVE_INTERVAL="${1#*=}"
            shift
            ;;
        --adaptive-reduce|--adaptive-reduce-threshold)
            if [[ $# -lt 2 ]]; then
                echo "--adaptive-reduce requires a numeric value" >&2
                exit 1
            fi
            ADAPTIVE_REDUCE="$2"
            shift 2
            ;;
        --adaptive-reduce=*|--adaptive-reduce-threshold=*)
            ADAPTIVE_REDUCE="${1#*=}"
            shift
            ;;
        --adaptive-increase|--adaptive-increase-threshold)
            if [[ $# -lt 2 ]]; then
                echo "--adaptive-increase requires a numeric value" >&2
                exit 1
            fi
            ADAPTIVE_INCREASE="$2"
            shift 2
            ;;
        --adaptive-increase=*|--adaptive-increase-threshold=*)
            ADAPTIVE_INCREASE="${1#*=}"
            shift
            ;;
        --adaptive-min-batch)
            if [[ $# -lt 2 ]]; then
                echo "--adaptive-min-batch requires an integer value" >&2
                exit 1
            fi
            ADAPTIVE_MIN_BATCH="$2"
            shift 2
            ;;
        --adaptive-min-batch=*)
            ADAPTIVE_MIN_BATCH="${1#*=}"
            shift
            ;;
        --adaptive-network|--adaptive-network-target|--adaptive-network-target-mbps)
            if [[ $# -lt 2 ]]; then
                echo "--adaptive-network requires a numeric value" >&2
                exit 1
            fi
            ADAPTIVE_NET_TARGET="$2"
            shift 2
            ;;
        --adaptive-network=*|--adaptive-network-target=*|--adaptive-network-target-mbps=*)
            ADAPTIVE_NET_TARGET="${1#*=}"
            shift
            ;;
        *)
            parsed_args+=("$1")
            shift
            ;;
    esac
done
set -- "${parsed_args[@]}"

while getopts ":f:n:o:w:p:t:c:Sh" opt; do
    case "$opt" in
        f) WATCHLIST_FILE="$OPTARG" ;;
        n) SPLIT_COUNT="$OPTARG" ;;
        o) OUTPUT_ROOT="$OPTARG" ;;
        w) WINDOW_NAME="$OPTARG" ;;
        p) PYTHON_BIN="$OPTARG" ;;
        t) CRAWL_TIMEOUT="$OPTARG" ;;
        c) CRAWL_CONCURRENCY="$OPTARG" ;;
        S) AUTO_FOCUS=0 ;;
        h)
            usage
            exit 0
            ;;
        :) echo "Option -$OPTARG requires an argument" >&2; exit 1 ;;
        *) usage >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

if [[ ! -f "$CRAWL_SCRIPT" ]]; then
    echo "Unable to find crawl.py next to this script" >&2
    exit 1
fi

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "Python interpreter '$PYTHON_BIN' not found" >&2
    exit 1
fi

if [[ ! "$SPLIT_COUNT" =~ ^[0-9]+$ ]] || (( SPLIT_COUNT < 1 )); then
    echo "Split count must be a positive integer" >&2
    exit 1
fi

if [[ -n "$CRAWL_TIMEOUT" ]] && ! [[ "$CRAWL_TIMEOUT" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "Timeout must be a positive number" >&2
    exit 1
fi

if [[ -n "$CRAWL_CONCURRENCY" ]] && ! [[ "$CRAWL_CONCURRENCY" =~ ^[0-9]+$ ]]; then
    echo "Concurrency must be a positive integer" >&2
    exit 1
fi

if [[ -n "$ADAPTIVE_MIN_CONC" ]] && ! [[ "$ADAPTIVE_MIN_CONC" =~ ^[0-9]+$ ]]; then
    echo "Adaptive minimum concurrency must be a positive integer" >&2
    exit 1
fi

if [[ -n "$ADAPTIVE_MAX_CONC" ]] && ! [[ "$ADAPTIVE_MAX_CONC" =~ ^[0-9]+$ ]]; then
    echo "Adaptive maximum concurrency must be a positive integer" >&2
    exit 1
fi

if [[ -n "$ADAPTIVE_STEP" ]] && ! [[ "$ADAPTIVE_STEP" =~ ^[0-9]+$ ]]; then
    echo "Adaptive step must be a positive integer" >&2
    exit 1
fi

if [[ -n "$ADAPTIVE_INTERVAL" ]] && ! [[ "$ADAPTIVE_INTERVAL" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "Adaptive interval must be a positive number" >&2
    exit 1
fi

if [[ -n "$ADAPTIVE_REDUCE" ]] && ! [[ "$ADAPTIVE_REDUCE" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "Adaptive reduce threshold must be numeric" >&2
    exit 1
fi

if [[ -n "$ADAPTIVE_INCREASE" ]] && ! [[ "$ADAPTIVE_INCREASE" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "Adaptive increase threshold must be numeric" >&2
    exit 1
fi

if [[ -n "$ADAPTIVE_MIN_BATCH" ]] && ! [[ "$ADAPTIVE_MIN_BATCH" =~ ^[0-9]+$ ]]; then
    echo "Adaptive min batch must be a positive integer" >&2
    exit 1
fi

if [[ -n "$ADAPTIVE_NET_TARGET" ]] && ! [[ "$ADAPTIVE_NET_TARGET" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "Adaptive network target must be numeric" >&2
    exit 1
fi

resolve_path() {
    local input_path="$1"
    if [[ "$input_path" = /* ]]; then
        printf '%s\n' "$input_path"
    else
        printf '%s/%s\n' "$INVOCATION_DIR" "$input_path"
    fi
}

WATCHLIST_PATH=$(resolve_path "$WATCHLIST_FILE")
if [[ ! -f "$WATCHLIST_PATH" ]]; then
    echo "Watchlist file '$WATCHLIST_PATH' not found" >&2
    exit 1
fi

if [[ -s "$WATCHLIST_PATH" ]]; then
    echo "Using watchlist: $WATCHLIST_PATH"
else
    echo "Warning: watchlist '$WATCHLIST_PATH' is empty" >&2
fi

if [[ "$OUTPUT_ROOT" = /* ]]; then
    OUTPUT_BASE="$OUTPUT_ROOT"
else
    OUTPUT_BASE="$SCRIPT_DIR/$OUTPUT_ROOT"
fi
mkdir -p "$OUTPUT_BASE"

echo "Chunk outputs will be stored under: $OUTPUT_BASE"

chunk_dir=$(mktemp -d -p "$OUTPUT_BASE" chunks.XXXXXX)
echo "Temporary chunks stored at: $chunk_dir"

suffix_length=${#SPLIT_COUNT}
if (( suffix_length < 2 )); then
    suffix_length=2
fi

split -n "l/${SPLIT_COUNT}" -d -a "$suffix_length" --additional-suffix=".txt" \
    "$WATCHLIST_PATH" "$chunk_dir/chunk_"

mapfile -t chunk_files < <(find "$chunk_dir" -maxdepth 1 -type f -name 'chunk_*' | sort)

existing=${#chunk_files[@]}
if (( existing < SPLIT_COUNT )); then
    for ((i=existing; i<SPLIT_COUNT; i++)); do
        chunk_path=$(printf '%s/chunk_%0*d.txt' "$chunk_dir" "$suffix_length" "$i")
        : > "$chunk_path"
        chunk_files+=("$chunk_path")
    done
fi

if (( ${#chunk_files[@]} == 0 )); then
    echo "Failed to create chunk files" >&2
    exit 1
fi

if (( ${#chunk_files[@]} != SPLIT_COUNT )); then
    echo "Internal error: expected $SPLIT_COUNT chunks but found ${#chunk_files[@]}" >&2
    exit 1
fi

window_target=$(tmux new-window -d -n "$WINDOW_NAME" -P -F '#{session_name}:#{window_index}')
if [[ -z "$window_target" ]]; then
    echo "Failed to create tmux window" >&2
    exit 1
fi

first_pane=$(tmux list-panes -t "$window_target" -F '#{pane_id}')
if [[ -z "$first_pane" ]]; then
    echo "Unable to determine initial pane id" >&2
    exit 1
fi

select_largest_pane() {
    local target="$1"
    local best=""
    local best_area=0
    while IFS=' ' read -r pane_id pane_height pane_width; do
        (( area = pane_height * pane_width ))
        if (( area > best_area )); then
            best="$pane_id"
            best_area=$area
        fi
    done < <(tmux list-panes -t "$target" -F '#{pane_id} #{pane_height} #{pane_width}')
    printf '%s\n' "$best"
}

current_panes=$(tmux list-panes -t "$window_target" | wc -l | tr -d ' ')
while (( current_panes < SPLIT_COUNT )); do
    target_pane=$(select_largest_pane "$window_target")
    if [[ -z "$target_pane" ]]; then
        echo "Failed to select a pane to split" >&2
        exit 1
    fi
    if ! new_pane=$(tmux split-window -t "$target_pane" -P -F '#{pane_id}' 2>&1); then
        echo "Failed to create pane $(( current_panes + 1 )): $new_pane" >&2
        echo "Try lowering -n or enlarging the tmux window." >&2
        exit 1
    fi
    tmux select-layout -t "$window_target" tiled >/dev/null
    current_panes=$((current_panes + 1))
done

mapfile -t pane_ids < <(tmux list-panes -t "$window_target" -F '#{pane_id}')
if (( ${#pane_ids[@]} != SPLIT_COUNT )); then
    echo "Internal error: tmux returned ${#pane_ids[@]} panes, expected $SPLIT_COUNT" >&2
    exit 1
fi

printf '\nLaunching %d crawl workers...\n' "$SPLIT_COUNT"

declare -a chunk_commands chunk_status_files chunk_labels chunk_dirs chunk_summary_files

for ((i=0; i< SPLIT_COUNT; i++)); do
    pane_id="${pane_ids[$i]}"
    chunk_file="${chunk_files[$i]}"
    chunk_label=$(printf 'chunk-%02d' "$i")
    chunk_out_dir=$(printf '%s/%s' "$OUTPUT_BASE" "$chunk_label")
    mkdir -p "$chunk_out_dir"
    summary_file="$chunk_out_dir/run_summary.json"
    line_count=$(wc -l < "$chunk_file" 2>/dev/null || printf '0')
    tmux select-pane -t "$pane_id" -T "$chunk_label" >/dev/null 2>&1 || true
    printf 'Pane %2d -> %s (%s lines) -> %s\n' "$((i+1))" "$chunk_label" "$line_count" "$chunk_out_dir"
    printf -v run_cmd 'cd %q && %q %q --targets %q --output %q' \
        "$SCRIPT_DIR" "$PYTHON_BIN" "$CRAWL_SCRIPT" "$chunk_file" "$chunk_out_dir"
    if [[ -n "$CRAWL_TIMEOUT" ]]; then
        printf -v run_cmd '%s --timeout %q' "$run_cmd" "$CRAWL_TIMEOUT"
    fi
    if [[ -n "$CRAWL_CONCURRENCY" ]]; then
        printf -v run_cmd '%s --concurrency %q' "$run_cmd" "$CRAWL_CONCURRENCY"
    fi
    if (( CRAWL_ADAPTIVE )); then
        run_cmd+=" --adaptive-concurrency"
    fi
    if [[ -n "$ADAPTIVE_MIN_CONC" ]]; then
        printf -v run_cmd '%s --adaptive-min-concurrency %q' "$run_cmd" "$ADAPTIVE_MIN_CONC"
    fi
    if [[ -n "$ADAPTIVE_MAX_CONC" ]]; then
        printf -v run_cmd '%s --adaptive-max-concurrency %q' "$run_cmd" "$ADAPTIVE_MAX_CONC"
    fi
    if [[ -n "$ADAPTIVE_STEP" ]]; then
        printf -v run_cmd '%s --adaptive-step %q' "$run_cmd" "$ADAPTIVE_STEP"
    fi
    if [[ -n "$ADAPTIVE_INTERVAL" ]]; then
        printf -v run_cmd '%s --adaptive-interval %q' "$run_cmd" "$ADAPTIVE_INTERVAL"
    fi
    if [[ -n "$ADAPTIVE_REDUCE" ]]; then
        printf -v run_cmd '%s --adaptive-reduce-threshold %q' "$run_cmd" "$ADAPTIVE_REDUCE"
    fi
    if [[ -n "$ADAPTIVE_INCREASE" ]]; then
        printf -v run_cmd '%s --adaptive-increase-threshold %q' "$run_cmd" "$ADAPTIVE_INCREASE"
    fi
    if [[ -n "$ADAPTIVE_MIN_BATCH" ]]; then
        printf -v run_cmd '%s --adaptive-min-batch %q' "$run_cmd" "$ADAPTIVE_MIN_BATCH"
    fi
    if [[ -n "$ADAPTIVE_NET_TARGET" ]]; then
        printf -v run_cmd '%s --adaptive-network-target-mbps %q' "$run_cmd" "$ADAPTIVE_NET_TARGET"
    fi
    status_file="$chunk_out_dir/.crawl_status"
    rm -f "$status_file" "$summary_file"
    chunk_commands[$i]="$run_cmd"
    chunk_status_files[$i]="$status_file"
    chunk_labels[$i]="$chunk_label"
    chunk_dirs[$i]="$chunk_out_dir"
    chunk_summary_files[$i]="$summary_file"
done

pending_indices=()
for ((i=0; i<SPLIT_COUNT; i++)); do
    pending_indices+=("$i")
done

attempt=1
focused_window=0
message_shown=0

while (( attempt <= RETRY_ATTEMPTS )) && (( ${#pending_indices[@]} > 0 )); do
    printf '\nStarting attempt %d for %d chunk(s)...\n' "$attempt" "${#pending_indices[@]}"
    for idx in "${pending_indices[@]}"; do
        pane_id="${pane_ids[$idx]}"
        status_file="${chunk_status_files[$idx]}"
        summary_file="${chunk_summary_files[$idx]}"
        run_cmd="${chunk_commands[$idx]}"
        chunk_label="${chunk_labels[$idx]}"
        rm -f "$status_file" "$summary_file"
        printf -v pane_cmd 'attempt=%d; status_file=%q; chunk=%q; rm -f "$status_file"; { %s; }; rc=$?; printf '\''%%d %%d\n'\'' %d "$rc" > "$status_file"; if (( rc != 0 )); then printf '\''[%%s] attempt %%d failed (exit %%s)\n'\'' "$chunk" "$attempt" "$rc" >&2; else printf '\''[%%s] attempt %%d succeeded\n'\'' "$chunk" "$attempt"; fi' \
            "$attempt" "$status_file" "$chunk_label" "$run_cmd" "$attempt"
        tmux send-keys -t "$pane_id" "$pane_cmd" C-m
    done

    if (( AUTO_FOCUS )) && (( focused_window == 0 )); then
        tmux select-window -t "$window_target"
        focused_window=1
    fi

    if (( message_shown == 0 )); then
        tmux display-message "crawlers running in window $WINDOW_NAME (output: $OUTPUT_BASE)"
        message_shown=1
    fi

    expected=${#pending_indices[@]}
    completed=0
    poll_start=$(date +%s)
    while (( completed < expected )); do
        completed=0
        for idx in "${pending_indices[@]}"; do
            status_file="${chunk_status_files[$idx]}"
            if [[ -s "$status_file" ]]; then
                if read attempt_id rc < "$status_file"; then
                    if [[ "$attempt_id" == "$attempt" ]]; then
                        ((completed++))
                    fi
                fi
            fi
        done
        if (( completed < expected )); then
            elapsed=$(( $(date +%s) - poll_start ))
            if (( CHUNK_WAIT_TIMEOUT > 0 && elapsed >= CHUNK_WAIT_TIMEOUT )); then
                printf 'Warning: chunk poll timeout (%ds) reached with %d/%d completed; treating remaining chunks as timed out.\n' \
                    "$CHUNK_WAIT_TIMEOUT" "$completed" "$expected" >&2
                break
            fi
            sleep 2
        fi
    done

    new_pending=()
    for idx in "${pending_indices[@]}"; do
        status_file="${chunk_status_files[$idx]}"
        summary_file="${chunk_summary_files[$idx]}"
        chunk_label="${chunk_labels[$idx]}"
        reason=""
        recorded_attempt=""
        rc=""
        if read recorded_attempt rc < "$status_file"; then
            if [[ "$recorded_attempt" != "$attempt" ]]; then
                reason="stale status (found attempt $recorded_attempt)"
            elif [[ "$rc" != "0" ]]; then
                reason="exit status $rc"
            fi
        else
            reason="missing status file"
        fi

        if [[ -z "$reason" ]]; then
            if [[ ! -f "$summary_file" ]]; then
                reason="missing run_summary.json"
            else
                failures=$("$PYTHON_BIN" -c 'import json, sys
from pathlib import Path
path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text())
except Exception:
    print("__PARSE_ERROR__")
else:
    print(data.get("failures", 0))' "$summary_file" 2>/dev/null || true)
                failures=${failures//$'\n'/}
                if [[ -z "$failures" || "$failures" == "__PARSE_ERROR__" ]]; then
                    reason="unable to parse run_summary.json"
                elif (( failures > 0 )); then
                    # We do NOT retry just because some domains failed (common on the web)
                    echo "Chunk $chunk_label finished with $failures failures (will not retry)" >&2
                fi
            fi
        fi

        if [[ -n "$reason" ]]; then
            printf '[%s] attempt %d will retry: %s\n' "$chunk_label" "$attempt" "$reason"
            new_pending+=("$idx")
        fi
    done

    if (( ${#new_pending[@]} == 0 )); then
        printf 'All chunks succeeded on attempt %d.\n' "$attempt"
        pending_indices=()
        break
    fi

    (( attempt += 1 ))
    if (( attempt > RETRY_ATTEMPTS )); then
        pending_indices=("${new_pending[@]}")
        break
    fi
    printf '%d chunk(s) failed; retrying attempt %d in %d seconds...\n' "${#new_pending[@]}" "$attempt" "$RETRY_DELAY"
    sleep "$RETRY_DELAY"
    pending_indices=("${new_pending[@]}")
done

if (( ${#pending_indices[@]} == 0 )); then
    printf '\nAll attempts completed successfully.\n'
    tmux display-message "crawlers completed in window $WINDOW_NAME (output: $OUTPUT_BASE)"
else
    echo "Warning: ${#pending_indices[@]} chunk(s) still failing after $RETRY_ATTEMPTS attempt(s):"
    for idx in "${pending_indices[@]}"; do
        echo "  - ${chunk_labels[$idx]}"
    done
    tmux display-message "crawlers finished with failures in window $WINDOW_NAME (output: $OUTPUT_BASE)"
fi
