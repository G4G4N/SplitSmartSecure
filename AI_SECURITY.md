# AI Security Layer

SplitSmart's cryptography guarantees *who* said *what* and that nobody changed
it in transit or in the ledger. It says nothing about whether a perfectly
authentic, perfectly signed request is *sensible*: a hijacked session can still
submit a $90,000 "yacht", a browser can still send `'; DROP TABLE ledger; --`
as a description, and a script can still guess passwords all night. The AI
security layer closes that gap with three local detectors and one optional
LLM analyst, all living in the `ai_security/` package.

```
                 ┌──────────────────────────────────────────────────────────┐
  request ──────▶│ 1. Cryptographic checks (session, counter, RSA-PSS sig)   │
                 └──────────────────────────────┬───────────────────────────┘
                                                ▼
                 ┌──────────────────────────────────────────────────────────┐
                 │ 2. AI security engine  (ai_security.AISecurityEngine)    │
                 │    ┌───────────────────┐  ┌──────────────────────────┐   │
                 │    │ ThreatClassifier  │  │ ExpenseAnomalyDetector   │   │
                 │    │ Naive Bayes +     │  │ per-user baselines,      │   │
                 │    │ signature rules   │  │ velocity, payer graph    │   │
                 │    └─────────┬─────────┘  └────────────┬─────────────┘   │
                 │              └──────── risk score ──────┘                 │
                 │                 allow / flag / block                      │
                 │    ┌───────────────────┐  ┌──────────────────────────┐   │
                 │    │ IntrusionDetector │  │ LLMSecurityAnalyst       │   │
                 │    │ decaying client   │  │ (optional, Claude)       │   │
                 │    │ score → response  │  │ explains events          │   │
                 │    └───────────────────┘  └──────────────────────────┘   │
                 └──────────────────────────────┬───────────────────────────┘
                                                ▼
                               ledger append + security_events table
```

## Components

### 1. Threat classifier (`ai_security/threat_classifier.py`)

Classifies every free-text field (expense description, payer) into one of
`benign`, `sql_injection`, `xss`, `command_injection`, `path_traversal` or
`prompt_injection`.

* **Model**: Multinomial Naive Bayes with Laplace smoothing over three feature
  families: word tokens, punctuation runs (`';--`, `<>`, `$(`) and character
  trigrams. Trigrams let the model generalise to payload variants it has never
  seen; out-of-vocabulary tokens are ignored so unknown English words never
  count as evidence of an attack.
* **Training data**: a built-in labelled corpus (about 250 samples) of benign
  expense descriptions and real-world payload shapes. It is trained at process
  start in a few milliseconds and needs no external files.
* **Signature rules**: 19 regular expressions for well-known attack syntax
  (`UNION ... SELECT`, `<script`, `onerror=`, `$(...)`, `../`, "ignore all
  previous instructions", ...).
* **Decision policy**: a signature match always wins and makes the verdict
  *malicious* (request rejected). The statistical model alone can only mark
  text as *suspicious*, which adds to the risk score but never blocks. This
  keeps false lock-outs at zero on ordinary descriptions while the model still
  surfaces novel payloads for review.

### 2. Behavioural anomaly detector (`ai_security/anomaly_detector.py`)

Learns an online profile for each user and for the group (Welford's running
mean/variance, maximum, hour-of-day histogram, known payers and a window of
recent submissions). Baselines are rebuilt from the persisted ledger on every
server start and updated as entries are accepted. Each submission is scored by
additive signals, capped at 100:

| Signal | Score | Meaning |
|---|---|---|
| `amount_outlier` / `amount_outlier_extreme` | 35 / 60 | z-score ≥ 2.5 / ≥ 4.0 against the user's (or group's) baseline |
| `amount_ratio` | 25 | ≥ 10× the user's average expense |
| `exceeds_historical_max` | 15 | > 3× the largest expense seen so far |
| `absolute_amount_high` / `_critical` | 20 / 50 | ≥ $5,000 / ≥ $50,000 regardless of history |
| `velocity_high` / `velocity_critical` | 20 / 45 | ≥ 6 / ≥ 15 submissions per minute |
| `duplicate_burst` | 25 | identical description + amount ≥ 3× within a minute |
| `unusual_hour` | 10 | hour of day never used before (after 20 samples) |
| `unknown_payer` / `new_payer` | 15 / 10 | payer not registered / never used by this user |
| `round_amount` | 5 | large round number (classic fraud indicator) |

Scores map to **LOW** (< 30), **MEDIUM** (< 60), **HIGH** (< 85) and
**CRITICAL** (≥ 85). Z-scores are only trusted after five samples; before
that only the absolute, velocity and payer signals apply (cold start).

### 3. Intrusion detector (`ai_security/intrusion_detector.py`)

Every security signal the application already produces is attributed to a
client (IP address on the web API, user or session id at the protocol level),
weighted, and decayed with a five-minute half-life:

| Signal | Weight | Signal | Weight |
|---|---|---|---|
| `login_failed` | 22 | `injection_detected` | 50 |
| `rate_limited` | 15 | `signature_invalid` | 40 |
| `hmac_mismatch` | 35 | `decryption_failed` | 35 |
| `replay_detected` | 30 | `anomaly_critical` / `anomaly_high` | 30 / 10 |
| `login_success` | −10 | credential stuffing (≥ 3 accounts) | +30 bonus |

The decayed score selects a graduated response: **allow** (< 40),
**challenge** (warn the UI), **throttle** (≥ 60, a two-second tarpit on the
login endpoint) and **block** (≥ 80, state-changing endpoints return 403 with
`Retry-After` for five minutes). Four wrong passwords block a client; a
password spray across three accounts blocks after three attempts.

### 4. LLM analyst (`ai_security/llm_analyst.py`, optional)

When Anthropic credentials are configured (`ANTHROPIC_API_KEY`, or an
`ant auth login` profile) and the `anthropic` package is installed, the
"Explain" button on the dashboard asks Claude (`claude-opus-5-5` by default)
for a plain-language incident summary with a structured JSON schema
(`summary`, `likely_attack`, `severity`, `indicators`, `recommended_actions`).
Without credentials the engine returns an equivalent rule-based explanation,
so nothing else depends on the LLM.

**Securing the AI itself.** Expense descriptions are attacker-controlled and
the analyst reads them, so the integration is built to resist prompt
injection:

* user-controlled fields are moved into a separate `untrusted_user_input`
  object and truncated before they reach the prompt;
* the system prompt instructs the model to treat that object strictly as data
  and never follow instructions found inside it;
* the `prompt_injection` class of the threat classifier rejects the most common
  override phrasing before it is ever stored;
* the response must validate against the JSON schema or it is discarded, and
  the local detectors (not the LLM) remain the only source of allow/block
  decisions.

The request also opts into Anthropic's server-side refusal fallback
(`fallbacks="default"`), so a safety-classifier refusal is retried on an
appropriate fallback model inside the same call.

## Where it runs

| Layer | Hook | Effect |
|---|---|---|
| Protocol server (`server/server.py`) | `handle_expense_submit` after signature verification | CRITICAL anomalies and malicious payloads return `SECURITY_POLICY_VIOLATION`; accepted entries carry a `security` block in `EXPENSE_RESPONSE`; replay / signature / decryption failures become intrusion signals |
| Web API (`web_app.py`) | `before_request` | blocked clients get 403 on `/api/login`, `/api/register`, `/api/add_expense`, `/api/ai_security/analyze` |
| Web API | `/api/login` | failed logins feed the intrusion score; throttled clients are tarpitted |
| Web API | `/api/add_expense` | HMAC mismatches and replays are recorded; submissions are screened before signing; responses include `security` and a `warning` when flagged |
| Web API | `/api/ai_security/*` | `status` (dashboard), `events`, `analyze` (dry run), `explain/<id>` |
| CLI (`cli.py`) | `security`, `analyze` | dashboard and dry-run analysis from the terminal |
| Storage (`server/storage.py`) | `security_events` table | every detection persists across restarts |

## Configuration

All thresholds are environment variables (see `ai_security/config.py`):

| Variable | Default | Purpose |
|---|---|---|
| `AI_SECURITY_BLOCK_CRITICAL` | `true` | reject CRITICAL anomalies instead of only flagging them |
| `AI_SECURITY_Z_WARN` / `AI_SECURITY_Z_CRITICAL` | `2.5` / `4.0` | z-score thresholds |
| `AI_SECURITY_AMOUNT_WARN` / `AI_SECURITY_AMOUNT_CRITICAL` | `5000` / `50000` | absolute amount guard-rails |
| `AI_SECURITY_MIN_HISTORY` | `5` | samples before z-scores are trusted |
| `AI_SECURITY_VELOCITY_WARN` / `_CRITICAL` | `6` / `15` | submissions per minute |
| `AI_SECURITY_THREAT_CONFIDENCE` | `0.85` | confidence needed to reject a payload |
| `AI_SECURITY_CHALLENGE_SCORE` / `_THROTTLE_SCORE` / `_BLOCK_SCORE` | `40` / `60` / `80` | intrusion response thresholds |
| `AI_SECURITY_BLOCK_DURATION` | `300` | seconds a blocked client waits |
| `AI_SECURITY_THROTTLE_DELAY` | `2.0` | tarpit delay in seconds |
| `AI_SECURITY_LLM_ENABLED` | `true` | allow the Claude analyst when credentials exist |
| `AI_SECURITY_LLM_MODEL` | `claude-opus-5-5` | model used for explanations |
| `ANTHROPIC_API_KEY` | unset | enables the Claude analyst |

`shared/constants.py` also exposes `AI_SECURITY_ENABLED` to bypass the
protocol-level screening entirely (the web layer still runs its checks).

## Trying it

```bash
python demos/demo_ai_security.py            # scripted attack walk-through
python cli.py analyze alice 20 "'; DROP TABLE ledger; --"
python cli.py security                      # dashboard in the terminal
python tests/test_ai_security.py            # unit + protocol integration tests
python tests/test_web_ai_security.py        # Flask API tests
```

In the web UI, the **AI Security Monitor** card shows the live threat level,
counters, model details, learned baselines and the event log with an
"Explain" button per event. The "Test the AI" panel runs any description and
amount through the engine as a dry run with one-click attack presets.

## Limitations

* The classifier is a small, hand-labelled model intended for a course
  project; it is strong on known payload *shapes* but is not a substitute for
  parameterised queries and output encoding (both of which SplitSmart already
  uses).
* Behavioural baselines need history. A brand-new group only gets the
  absolute, velocity and payer checks until five entries exist.
* Intrusion scores are process-local: with several web workers each process
  keeps its own view (persisted events are shared, the live scores are not).
* The LLM analyst only explains; it never decides.
