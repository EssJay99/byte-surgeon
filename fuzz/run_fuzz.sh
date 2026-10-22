#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

TARGETS=(
    filesystem_parser
    signature_scanner
    registry_parser
    email_parser
    chat_recoverer
)

CORPUS_DIR="$SCRIPT_DIR/corpus"
ARTIFACT_DIR="$SCRIPT_DIR/artifacts"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-300}"

mkdir -p "$CORPUS_DIR" "$ARTIFACT_DIR"

usage() {
    echo "Usage: $0 [OPTIONS] [TARGET]"
    echo ""
    echo "Options:"
    echo "  --list            List available fuzz targets"
    echo "  --all             Run all targets sequentially"
    echo "  --max-time SECS   Max time per target (default: 300s)"
    echo "  --help            Show this help"
    echo ""
    echo "Targets: ${TARGETS[*]}"
    echo ""
    echo "Examples:"
    echo "  $0 signature_scanner        # Fuzz one target"
    echo "  $0 --all                    # Fuzz all targets"
    echo "  $0 --max-time 60 registry_parser  # Fuzz registry for 60s"
    exit 0
}

run_target() {
    local target="$1"
    local target_corpus="$CORPUS_DIR/$target"
    local target_artifacts="$ARTIFACT_DIR/$target"

    mkdir -p "$target_corpus" "$target_artifacts"

    echo "=== Fuzzing: $target (max ${MAX_TOTAL_TIME}s) ==="
    echo "  Corpus:    $target_corpus"
    echo "  Artifacts: $target_artifacts"

    cargo +nightly fuzz run "$target" \
        "$target_corpus" \
        "$target_artifacts" \
        -- \
        -max_total_time="$MAX_TOTAL_TIME" \
        -print_final_stats=1 \
        -artifact_prefix="$target_artifacts/"

    echo "=== Done: $target ==="
    echo ""
}

if [[ $# -eq 0 ]]; then
    usage
fi

case "${1:-}" in
    --help|-h)
        usage
        ;;
    --list)
        echo "Available fuzz targets:"
        for t in "${TARGETS[@]}"; do
            echo "  $t"
        done
        exit 0
        ;;
    --all)
        if [[ -n "${2:-}" && "$2" == --max-time ]]; then
            MAX_TOTAL_TIME="${3:-300}"
        fi
        for target in "${TARGETS[@]}"; do
            run_target "$target"
        done
        echo "All targets completed."
        exit 0
        ;;
    --max-time)
        MAX_TOTAL_TIME="${2:-300}"
        shift 2
        if [[ $# -gt 0 ]]; then
            run_target "$1"
        else
            for target in "${TARGETS[@]}"; do
                run_target "$target"
            done
        fi
        ;;
    *)
        run_target "$1"
        ;;
esac
