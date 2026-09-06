# ALU Regex Data Extraction & Secure Validation

Regex-based extraction and validation tool that processes raw, messy text
(simulating a real support-ticket / CRM export pulled from an external API)
and pulls out structured data while treating the input as untrusted by
default.

## What it extracts

| Type                           | Notes                                                                |
|---                             |---                                                                   |
| Email addresses                | Includes ALU-specific classification                                 |
| Credit card numbers            | Regex match + **Luhn checksum** validation, masked in output         |
| Phone numbers                  | Rwanda-format only (`+250` + mobile number)                          |
| URLs                           | `http(s)://` links only                                              |
| Hashtags                       |                                                                      |
| Times (12h/24h)                |                                                                      |

Emails and credit card numbers are the two required categories the
assignment explicitly asks for; phone numbers and URLs cover the "at least
two more" requirement, with hashtags and times included as extras.

### ALU-specific email rules

ALU classification uses an **exact domain lookup**, not a suffix match:

```python
ALU_DOMAINS = {
    "alueducation.com": "official",
    "alumni.alueducation.com": "alumni",
    "si.alueducation.com": "si",
}
```


## Project structure

```
alu-regex-data-extraction_Des1re-Jab0/
├── input/
│   └── raw-text.txt        # realistic, messy sample input (includes bad/hostile data on purpose)
├── src/
│   └── main.py              # extraction + validation + security screening
├── output/
│   └── sample-output.json   # generated report from the sample input
└── README.md
```

## How to run

Requires Python 3.10+ (uses `X | None` union syntax), no external
dependencies.

```bash
cd alu-regex-data-extraction_Des1re-Jab0
python3 src/main.py
```

This reads `input/raw-text.txt`, prints a console summary, and writes the
full structured report to `output/sample-output.json`.


```bash
python3 src/main.py path/to/other-input.txt -o path/to/other-output.json
```

## How the security handling works

The assignment requires the program to treat input as untrustworthy, not
just extract data from it. This is handled in several layers:

1. **Input size and encoding limits.** `load_input()` rejects files over
   1 MB and rejects any UTF-8 control character other than tab/newline/
   carriage return, before the text is used for anything.
2. **Hostile-line screening.** Every line is checked against known-hostile
   patterns (SQL injection like `DROP TABLE` / `UNION SELECT` / `'; --`,
   XSS via `<script>` or `javascript:` URIs, and path traversal like
   `../../`) *before* any extraction regex sees it. Matching lines are
   removed from the text that extraction runs on.
3. **No verbatim reflection of hostile payloads.** Flagged lines are never
   copied into the output in full — only a truncated (40-character)
   preview, so the tool can't be used to smuggle an attacker's exact
   payload into logs or downstream systems.
4. **Post-match validation, not just regex matching.** A string "looking
   like" a credit card is not treated as one until it also passes the
   **Luhn checksum** — the sample output includes a card that matched the
   shape but is correctly excluded from `valid_count` because it fails
   Luhn. Emails get additional structural checks (length limits, no
   leading/trailing/double dots, valid label shape) beyond what the regex
   alone guarantees.
5. **Masking sensitive output.** Credit card numbers and email addresses
   are never written to the console or JSON output in full — only the
   last 4 digits of a card, or the first/last character of an email's
   local part, with everything else replaced by `*`.
6. **Restricted URL schemes.** Only `http://` and `https://` are matched;
   `javascript:`, `data:`, and `file:` URIs are excluded at the regex
   level, not filtered afterward.


