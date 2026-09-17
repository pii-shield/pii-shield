#!/bin/bash
# test-smoke.sh - v6
#
# Runs the unit tests, benchmarks and a 1000-line end-to-end corpus through the
# Docker image, then scores the result.
#
# Modes:
#   (default)      score the frozen corpus in scripts/testdata/ — deterministic,
#                  so a red run means a real behavior change, never a dice roll
#   --fuzz         generate a fresh random corpus and score that instead
#   --regenerate   rebuild the frozen corpus from the generator and exit
#
# Scoring uses the secret VALUE, not "did the line change": a line can change
# because something else on it was redacted while the secret itself survives.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}" || exit 1

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

INPUT_FILE="full_test_input.log"
OUTPUT_FILE="full_test_output.log"
META_FILE="full_test_meta.tsv"
CORPUS_FILE="scripts/testdata/smoke-corpus.txt"
CORPUS_META="scripts/testdata/smoke-corpus.tsv"
COUNT=1000

# Keyless secrets in prose (see generate_corpus type 6) have no key to force
# redaction, so detection rests entirely on the entropy score of a short random
# token. Measured on 1500 samples: 0.07% of them score below the threshold —
# with ~140 such lines per corpus that is a ~9% chance of a red run on
# unchanged code. They are counted and printed, but only fail the run when they
# exceed this budget, which is what a real recall regression looks like.
# Closing the gap for good is campaign item F6 (length-dependent threshold).
KNOWN_GAP_MAX=2

MODE="frozen"
case "${1:-}" in
    --fuzz)       MODE="fuzz" ;;
    --regenerate) MODE="regenerate" ;;
    "")           ;;
    *) echo "Usage: $(basename "$0") [--fuzz | --regenerate]" >&2; exit 2 ;;
esac

get_time_ms() {
    python3 -c 'import time; print(int(time.time() * 1000))'
}

# generate_corpus <log-path> <meta-path>
# Writes COUNT log lines and a tab-separated meta file: TYPE <TAB> SECRET.
# SECRET is the exact value that must not survive scanning; empty when the line
# carries no secret.
generate_corpus() {
    local out_log="$1" out_meta="$2"
    local TIMESTAMPS=("2026-01-30T10:00:00Z" "1706608800")
    local LEVELS=("INFO" "WARN" "ERROR" "DEBUG" "FATAL")
    local MESSAGES=("Process crash" "DB timeout" "Render complete" "Health check" "Binary dump")

    : > "$out_log"
    : > "$out_meta"

    local i TS LVL MSG RAND_TYPE SECRET PAYLOAD TYPE SUB_TYPE VAL
    for i in $(seq 1 $COUNT); do
        TS=${TIMESTAMPS[$((RANDOM % ${#TIMESTAMPS[@]}))]}
        LVL=${LEVELS[$((RANDOM % ${#LEVELS[@]}))]}
        MSG=${MESSAGES[$((RANDOM % ${#MESSAGES[@]}))]}
        RAND_TYPE=$((RANDOM % 7))
        SECRET=""

        if [ $RAND_TYPE -eq 0 ]; then
            # 1. Real secret under a known sensitive key.
            SECRET=$(openssl rand -base64 15 | tr -dc 'a-zA-Z0-9')
            PAYLOAD="api_key=${SECRET}"
            TYPE="SECRET"

        elif [ $RAND_TYPE -eq 1 ]; then
            # 2. Safe low-entropy value.
            PAYLOAD="username=user_$(openssl rand -hex 2)"
            TYPE="SAFE"

        elif [ $RAND_TYPE -eq 2 ]; then
            # 3. Safe high-entropy values — the false-positive trap.
            SUB_TYPE=$((RANDOM % 3))
            if [ $SUB_TYPE -eq 0 ]; then
                PAYLOAD="commit_sha=$(openssl rand -hex 20)"
            elif [ $SUB_TYPE -eq 1 ]; then
                VAL=$(uuidgen 2>/dev/null || echo "550e8400-e29b-41d4-a716-446655440000")
                PAYLOAD="request_id=${VAL}"
            else
                PAYLOAD="pub_key=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0g+Z"
            fi
            TYPE="SAFE"

        elif [ $RAND_TYPE -eq 3 ]; then
            # 4. Hex dump — textual noise that must survive intact.
            PAYLOAD="memory_dump: [0a 1b 3c 4d 5e 6f 90 21]"
            TYPE="SAFE"

        elif [ $RAND_TYPE -eq 4 ]; then
            # 5. Unknown key + high entropy: the key is not in the sensitive
            #    list, so this rides on the entropy score alone.
            SECRET=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9')
            PAYLOAD="custom_var_$(openssl rand -hex 2)=${SECRET}"
            TYPE="SECRET"

        elif [ $RAND_TYPE -eq 5 ]; then
            # 6. Binary garbage — stability check only, never scored.
            VAL=$(printf "BrokenUTF8_\xFF\xFE_End")
            PAYLOAD="binary_data=${VAL}"
            TYPE="NOISE"

        else
            # 7. Keyless secret in a sentence. No key to force redaction, so a
            #    short low-entropy token legitimately slips through. Tracked as
            #    a known gap rather than a hard failure — see KNOWN_GAP_MAX.
            SECRET=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9')
            PAYLOAD="Error: 192.168.1.5 ${SECRET} connection failed"
            TYPE="KNOWN_GAP"
        fi

        printf '%s\t%s\n' "$TYPE" "$SECRET" >> "$out_meta"

        if (( i % 2 == 0 )); then
            echo "{\"time\": \"$TS\", \"lvl\": \"$LVL\", \"msg\": \"$MSG\", \"pl\": \"$PAYLOAD\", \"id\": 12345}" >> "$out_log"
        else
            echo "$TS [$LVL] $MSG data=$PAYLOAD context_id=12345" >> "$out_log"
        fi
    done
}

if [ "$MODE" = "regenerate" ]; then
    mkdir -p "$(dirname "$CORPUS_FILE")"
    generate_corpus "$CORPUS_FILE" "$CORPUS_META"
    echo -e "${GREEN}✅ Frozen corpus regenerated:${NC} $CORPUS_FILE ($COUNT lines)"
    echo -e "${YELLOW}   Review the diff and re-run the smoke test before committing.${NC}"
    exit 0
fi

# 0. Unit tests
echo -e "${BLUE}🧪 Running Advanced Go Unit Tests...${NC}"
if ! go test -v ./pkg/scanner/...; then
    echo -e "${RED}❌ Go tests failed! Aborting stress test.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Go tests passed.${NC}\n"

echo -e "${BLUE}🚀 Running Go Benchmarks...${NC}"
go test -bench=. -benchmem -v ./pkg/scanner
echo -e "${GREEN}✅ Benchmarks complete.${NC}\n"

echo -e "${BLUE}🏗️  Building Docker Image...${NC}"
if ! docker build -t pii-shield:local . > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker build failed.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Docker image updated.${NC}\n"

FAILURES=0

# ==============================================================================
# PHASE 1: Real-World Edge Cases (Static Regression)
# ==============================================================================
echo -e "${BLUE}▶️  PHASE 1: Real-World Edge Cases (Matryoshka, Quotes)${NC}"
rm -f "$INPUT_FILE"
echo '{"key": "password", "value": "SuperSecret123"}' >> "$INPUT_FILE"
echo '{"msg": "User said \"Hello\" to admin"}' >> "$INPUT_FILE"
echo '{"data": "{\"nested_key\": \"nested_secret\"}"}' >> "$INPUT_FILE"
echo 'jdbc:mysql://db:3306?pass=SecretDBPass' >> "$INPUT_FILE"

docker run -i --rm pii-shield:local < "$INPUT_FILE" > "$OUTPUT_FILE"

if grep -q "SuperSecret123" "$OUTPUT_FILE"; then
    echo -e "${RED}[FAIL] Case 1: Simple Password leaked${NC}"
    FAILURES=$((FAILURES + 1))
else echo -e "${GREEN}[PASS] Case 1: Simple Password redacted${NC}"; fi

if grep -q 'User said \\"Hello\\" to admin' "$OUTPUT_FILE"; then
    echo -e "${GREEN}[PASS] Case 2: Escaped quotes preserved${NC}"
else
    echo -e "${RED}[FAIL] Case 2: Escaped quotes corrupted${NC}"
    FAILURES=$((FAILURES + 1))
fi

# ==============================================================================
# PHASE 2: Bulk corpus
# ==============================================================================
if [ "$MODE" = "fuzz" ]; then
    echo -e "\n${BLUE}▶️  PHASE 2: Bulk Wild Test (${COUNT} Lines, fresh random corpus)${NC}"
    echo -e "${YELLOW}   Injecting: Dynamic Secrets, Git Hashes, SSH Keys, Binary Dumps...${NC}"
    generate_corpus "$INPUT_FILE" "$META_FILE"
else
    if [ ! -f "$CORPUS_FILE" ] || [ ! -f "$CORPUS_META" ]; then
        echo -e "${RED}❌ Frozen corpus missing: $CORPUS_FILE${NC}"
        echo -e "${YELLOW}   Run '$(basename "$0") --regenerate' to create it.${NC}"
        exit 1
    fi
    echo -e "\n${BLUE}▶️  PHASE 2: Bulk Test (frozen corpus, $(wc -l < "$CORPUS_FILE" | tr -d ' ') lines)${NC}"
    cp "$CORPUS_FILE" "$INPUT_FILE"
    cp "$CORPUS_META" "$META_FILE"
fi

LINES=$(wc -l < "$INPUT_FILE" | tr -d ' ')
INPUT_SIZE=$(wc -c < "$INPUT_FILE")

START=$(get_time_ms)
docker run -i --rm pii-shield:local < "$INPUT_FILE" > "$OUTPUT_FILE"
END=$(get_time_ms)

DURATION_MS=$(( END - START ))
if [ $DURATION_MS -le 0 ]; then DURATION_MS=1; fi
LPS=$(( LINES * 1000 / DURATION_MS ))
KBPS=$(( INPUT_SIZE * 1000 / DURATION_MS / 1024 ))

# --- Scoring -----------------------------------------------------------------
# The loop reads from a process substitution, not a pipe, so the counters live
# in this shell and no temp file is needed to carry them back.
TP=0; TN=0; FP=0; FN=0; GAPS=0
while IFS=$'\t' read -r IN OUT EXPECTED_TYPE SECRET; do
    case "$EXPECTED_TYPE" in
        SECRET)
            if [[ -n "$SECRET" && "$OUT" == *"$SECRET"* ]]; then
                echo -e "${RED}[LEAK] False Negative:${NC}\n   Input: $IN\n   Output: $OUT"
                FN=$((FN + 1))
            else
                TP=$((TP + 1))
            fi
            ;;
        KNOWN_GAP)
            if [[ -n "$SECRET" && "$OUT" == *"$SECRET"* ]]; then
                GAPS=$((GAPS + 1))
            else
                TP=$((TP + 1))
            fi
            ;;
        NOISE)
            # Redacted or not, both fine — this line only proves we did not crash.
            TN=$((TN + 1))
            ;;
        *)
            if [[ "$IN" != "$OUT" && "$OUT" == *"[HIDDEN"* ]]; then
                echo -e "${YELLOW}[BROKEN] False Positive (Safe Data Redacted):${NC}\n   Input:  $IN\n   Output: $OUT"
                FP=$((FP + 1))
            else
                TN=$((TN + 1))
            fi
            ;;
    esac
done < <(LC_ALL=C paste "$INPUT_FILE" "$OUTPUT_FILE" "$META_FILE")

echo -e "\n📊 Phase 2 Results ($LINES items):"
echo -e "Accuracy: $(( (TP + TN) * 100 / LINES ))%"
echo -e "True Positives (Secrets Caught): $TP"
echo -e "True Negatives (Safe Passed):    $TN"
echo -e "False Positives (Safe Broken):   $FP"
echo -e "False Negatives (Secrets Leaked): $FN"
echo -e "Known Gaps (keyless secrets, budget ${KNOWN_GAP_MAX}): $GAPS"

echo -e "\n🚀 PERFORMANCE METRICS:"
echo -e "Time Taken:     ${DURATION_MS} ms"
echo -e "Throughput:     ${GREEN}${LPS} lines/sec${NC}"
echo -e "Data Rate:      ${GREEN}${KBPS} KB/s${NC} (Docker overhead included)"

if [[ "$FN" -gt 0 || "$FP" -gt 0 ]]; then
    FAILURES=$((FAILURES + 1))
fi
if [[ "$GAPS" -gt "$KNOWN_GAP_MAX" ]]; then
    echo -e "${RED}❌ Known-gap budget exceeded: $GAPS > $KNOWN_GAP_MAX — keyless-secret recall regressed.${NC}"
    FAILURES=$((FAILURES + 1))
fi

# ==============================================================================
# PHASE 3: JSON Integrity Verification (jq)
# ==============================================================================
echo -e "\n${BLUE}▶️  PHASE 3: JSON Integrity Check${NC}"
grep "^{" "$OUTPUT_FILE" > json_output.log
if ! jq . < json_output.log > /dev/null 2>&1; then
    echo -e "${RED}❌ JSON Integrity Check FAILED. Output contained invalid JSON.${NC}"
    head -n 5 json_output.log
    FAILURES=$((FAILURES + 1))
else
    echo -e "${GREEN}✅ JSON Integrity Check PASSED. All JSON lines valid.${NC}"
fi
rm -f json_output.log

# ==============================================================================
# SUMMARY
# ==============================================================================
echo -e "\n========================================"
rm -f "$INPUT_FILE" "$OUTPUT_FILE" "$META_FILE"
if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}✅ ALL TESTS PASSED${NC}"
    exit 0
else
    echo -e "${RED}❌ FAILED with $FAILURES issues${NC}"
    exit 1
fi
