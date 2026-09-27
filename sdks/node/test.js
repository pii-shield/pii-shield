const { PiiShield } = require('./index');
const fs = require('fs');
const path = require('path');

// Cross-entrypoint parity: load the shared golden (generated from the Go
// scanner) and assert the Node SDK produces byte-identical output. See
// sdks/parity/cases.json and sdks/parity/parity_test.go (issue #48).
const SNAKE_TO_CAMEL = {
    entropy_threshold: 'entropyThreshold',
    salt: 'salt',
    confidence_score: 'confidenceScore',
    min_secret_length: 'minSecretLength',
    sensitive_keys: 'sensitiveKeys',
    disable_bigram_check: 'disableBigramCheck',
    adaptive_threshold: 'adaptiveThreshold',
    entity_type_labels: 'entityTypeLabels',
    sensitive_key_patterns: 'sensitiveKeyPatterns',
    custom_regexes: 'customRegexes',
    safe_regexes: 'safeRegexes',
};

async function runParity() {
    const casesPath = path.join(__dirname, '..', 'parity', 'cases.json');
    const cases = JSON.parse(fs.readFileSync(casesPath, 'utf8'));
    let ok = true;
    for (const tc of cases) {
        const cfg = {};
        for (const [k, v] of Object.entries(tc.config)) {
            // An unmapped key would reach the SDK under its snake_case name
            // and be ignored silently, so the case would test the defaults.
            if (!(k in SNAKE_TO_CAMEL)) {
                throw new Error(`parity case ${tc.name}: no camelCase mapping for config key ${k}`);
            }
            cfg[SNAKE_TO_CAMEL[k]] = v;
        }
        const shield = await PiiShield.create(cfg, "../../pii-shield-wasi.wasm");
        const got = shield.redact(tc.input);
        if (got !== tc.expected) {
            console.error(`PARITY FAIL [${tc.name}]\n  input:    ${JSON.stringify(tc.input)}\n  expected: ${JSON.stringify(tc.expected)}\n  got:      ${JSON.stringify(got)}`);
            ok = false;
        } else {
            console.log(`parity ok: ${tc.name}`);
        }
    }
    return ok;
}

// Without a salt each instance draws its own random one, so the same value
// gets a different tag in each, and never the tag of the old fixed default.
async function runNoSaltCheck() {
    const input = 'password=SuperSecretValue123';
    const a = (await PiiShield.create({}, "../../pii-shield-wasi.wasm")).redact(input);
    const b = (await PiiShield.create({}, "../../pii-shield-wasi.wasm")).redact(input);
    const ok = a.startsWith('password=[HIDDEN:') && a !== b && a !== 'password=[HIDDEN:8836e2]' && b !== 'password=[HIDDEN:8836e2]';
    if (ok) {
        console.log('no-salt ok: random per instance');
    } else {
        console.error(`NO-SALT FAIL: expected two different random tags, got ${JSON.stringify(a)} and ${JSON.stringify(b)}`);
    }
    return ok;
}

async function main() {
    try {
        console.log("Loading WASM module...");
        const shield = await PiiShield.create({
            confidenceScore: 1.5,
            failPolicy: "open"
        }, "../../pii-shield-wasi.wasm");

        const testStrings = [
            'User registered with token: 123e4567-e89b-12d3-a456-426614174000',
            'Just a random UUID: 123e4567-e89b-12d3-a456-426614174000',
            'Password is mySuperSecretPassword123!',
            'Invalid payload JSON {}'
        ];

        let passed = true;

        for (const str of testStrings) {
            console.log("Original:", str);
            const redacted = shield.redact(str);
            console.log("Redacted:", redacted);
            console.log("---");
            if (redacted.includes("FATAL_ERROR")) {
                passed = false;
            }
        }
        
        // Cross-entrypoint parity against the shared golden.
        const parityOk = await runParity();
        if (!parityOk) {
            passed = false;
        }
        if (!(await runNoSaltCheck())) {
            passed = false;
        }

        if (passed) {
            console.log("SUCCESS");
        } else {
            console.error("FAILED");
            process.exit(1);
        }
    } catch (err) {
        console.error("Fatal error:", err);
        process.exit(1);
    }
}

main();
