#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Iterable

MAX_INPUT_BYTES = 1_000_000
MAX_MATCHES_PER_TYPE = 500

SUSPICIOUS_PATTERNS = [
    r"\bdrop\s+table\b",
    r"\bunion\s+select\b",
    r"<\s*script\b",
    r"javascript\s*:",
    r"\.\./\.\./",
    r"';\s*--",
    r"';",
]
SUSPICIOUS_RE = re.compile("|".join(SUSPICIOUS_PATTERNS), re.IGNORECASE)


def screen_lines(text: str) -> tuple[str, list[str]]:

    trusted_lines = []
    flagged = []
    for line in text.splitlines():
        if SUSPICIOUS_RE.search(line):
            preview = line.strip()[:40]
            flagged.append(preview + ("..." if len(line.strip()) > 40 else ""))
        else:
            trusted_lines.append(line)
    return "\n".join(trusted_lines), flagged

EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9](?:[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{0,62}[A-Za-z0-9])?"
    r"@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
    r"(?![A-Za-z0-9.-])"
)

URL_RE = re.compile(
    r"(?<![\w@])https?://"
    r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}"
    r"(?::\d{2,5})?"
    r"(?:/[^\s<>'\"]*)?",
    re.IGNORECASE,
)

PHONE_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:\+?250[\s.-]?|\(250\)[\s.-]?)"
    r"7\d{2}[\s.-]?\d{3}[\s.-]?\d{3}"
    r"(?![A-Za-z0-9])"
)

CARD_RE = re.compile(
    r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"
)

TIME_RE = re.compile(
    r"(?<!\w)(?:"
    r"(?:0?[1-9]|1[0-2]):[0-5]\d\s?(?:AM|PM)"
    r"|(?:[01]\d|2[0-3]):[0-5]\d"
    r")(?!\w)",
    re.IGNORECASE,
)

HASHTAG_RE = re.compile(r"(?<!\w)#[A-Za-z][A-Za-z0-9_]{1,49}")


ALU_DOMAINS = {
    "alueducation.com": "official",
    "alumni.alueducation.com": "alumni",
    "si.alueducation.com": "si",
}


def load_input(path: Path) -> str:
    raw = path.read_bytes()

    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(
            f"Input is too large ({len(raw)} bytes). Limit: {MAX_INPUT_BYTES}."
        )

    text = raw.decode("utf-8", errors="strict")

    if any(ord(ch) < 32 and ch not in "\t\n\r" for ch in text):
        raise ValueError("Input contains unsupported control characters.")

    return text


def normalize_card(candidate: str) -> str:
    return re.sub(r"[ -]", "", candidate)


def luhn_valid(number: str) -> bool:

    if not number.isdigit() or not 13 <= len(number) <= 19:
        return False

    total = 0
    parity = len(number) % 2

    for index, char in enumerate(number):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return total % 10 == 0


def valid_email(candidate: str) -> bool:
    if len(candidate) > 254:
        return False

    if candidate.count("@") != 1:
        return False

    local, domain = candidate.rsplit("@", 1)

    if not local or len(local) > 64:
        return False
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False

    if len(domain) > 253 or domain.startswith(".") or domain.endswith("."):
        return False

    labels = domain.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        for label in labels
    ):
        return False

    return True


def classify_alu_email(email: str) -> str | None:

    domain = email.rsplit("@", 1)[1].lower()

    return ALU_DOMAINS.get(domain)


def mask_email(email: str) -> str:
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def mask_card(card: str) -> str:
    return "*" * max(0, len(card) - 4) + card[-4:]


def unique_limited(items: Iterable[str], limit: int = MAX_MATCHES_PER_TYPE) -> list[str]:
    seen = set()
    result = []

    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)

        if len(result) >= limit:
            break

    return result


def extract(text: str) -> dict:
    trusted_text, flagged_previews = screen_lines(text)
    email_candidates = unique_limited(EMAIL_RE.findall(trusted_text))
    url_candidates = unique_limited(URL_RE.findall(trusted_text))
    phone_candidates = unique_limited(PHONE_RE.findall(trusted_text))
    card_candidates = unique_limited(CARD_RE.findall(trusted_text))
    time_candidates = unique_limited(TIME_RE.findall(trusted_text))
    hashtag_candidates = unique_limited(HASHTAG_RE.findall(trusted_text))

    valid_emails = [e for e in email_candidates if valid_email(e)]

    alu_emails = []
    for email in valid_emails:
        category = classify_alu_email(email)
        if category:
            alu_emails.append(
                {
                    "value": mask_email(email),
                    "category": category,
                }
            )

    valid_cards = []
    rejected_cards = []

    for candidate in card_candidates:
        normalized = normalize_card(candidate)
        if luhn_valid(normalized):
            valid_cards.append(mask_card(normalized))
        else:
            rejected_cards.append(mask_card(normalized))

    valid_urls = [
        url.rstrip(".,);")
        for url in url_candidates
        if len(url) <= 2048
    ]

    valid_phones = []
    for phone in phone_candidates:
        digits = re.sub(r"\D", "", phone)
        if len(digits) == 12 and digits.startswith("250"):
            valid_phones.append(phone.strip())

    return {
        "emails": {
            "valid_count": len(valid_emails),
            "masked_values": [mask_email(e) for e in valid_emails],
            "alu_addresses": alu_emails,
        },
        "credit_cards": {
            "valid_count": len(valid_cards),
            "masked_values": valid_cards,
            "rejected_candidate_count": len(rejected_cards),
            "rejected_masked_values": rejected_cards,
        },
        "urls": {
            "valid_count": len(valid_urls),
            "values": valid_urls,
        },
        "phone_numbers": {
            "valid_count": len(valid_phones),
            "values": valid_phones,
        },
        "times": {
            "count": len(time_candidates),
            "values": time_candidates,
        },
        "hashtags": {
            "count": len(hashtag_candidates),
            "values": hashtag_candidates,
        },
        "security": {
            "input_treated_as_untrusted": True,
            "input_size_limit_bytes": MAX_INPUT_BYTES,
            "sensitive_values_masked": True,
            "credit_cards_checked_with_luhn": True,
            "allowed_url_schemes": ["http", "https"],
            "alu_domains_checked_by_exact_domain": True,
            "hostile_lines_flagged": len(flagged_previews),
            "hostile_line_previews": flagged_previews,
            "note": (
                "Regex extraction is not a complete security boundary. "
                "Downstream systems should still use parameterized queries, "
                "context-aware output encoding, authorization, and rate limits."
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and defensively validate structured data from raw text."
    )
    project_root = Path(__file__).resolve().parent.parent
    default_input = project_root / "input" / "raw-text.txt"
    default_output = project_root / "output" / "sample-output.json"

    parser.add_argument(
        "input_file",
        nargs="?",
        default=str(default_input),
        help="Path to raw input text. Defaults to input/raw-text.txt next to this script.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=str(default_output),
        help="Path for JSON output. Defaults to output/sample-output.json next to this script.",
    )
    args = parser.parse_args()

    input_path = Path(args.input_file)
    output_path = Path(args.output)

    text = load_input(input_path)
    result = extract(text)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("Extraction completed successfully.")
    print(f"Input:  {input_path}")
    print(f"Output: {output_path}")
    print(f"Valid emails:       {result['emails']['valid_count']}")
    print(f"Valid credit cards: {result['credit_cards']['valid_count']}")
    print(f"Valid URLs:         {result['urls']['valid_count']}")
    print(f"Valid phones:       {result['phone_numbers']['valid_count']}")
    print(f"Times found:        {result['times']['count']}")
    print(f"Hashtags found:     {result['hashtags']['count']}")
    print(f"Hostile lines flagged: {result['security']['hostile_lines_flagged']}")


if __name__ == "__main__":
    main()
