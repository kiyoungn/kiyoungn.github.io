#!/usr/bin/env bash
# Fail if staged/tracked files contain secrets or private personal data.
# Usage: scripts/check-secrets.sh [staged|all]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MODE="${1:-staged}"
FAILED=0
HITS=()

note() { HITS+=("$1"); FAILED=1; }

collect_files() {
  if [[ "$MODE" == "all" ]]; then
    git ls-files -z
  else
    git diff --cached --name-only --diff-filter=ACMR -z
  fi
}

# High-risk filenames that must never be committed.
blocked_name() {
  local f="$1"
  local base
  base="$(basename "$f")"
  case "$base" in
    .env|.env.*|*.pem|*.key|*.p12|*.pfx|*.jks|*.kdbx|*.ovpn|id_rsa|id_dsa|id_ecdsa|id_ed25519|credentials.json|token.json|auth.json|client_secret*.json|service-account*.json|*-service-account.json|*.keystore|*.secret|*.credentials|secrets.json|secrets.yaml|secrets.yml|.secret-blocklist)
      return 0
      ;;
  esac
  case "$f" in
    private/*|secrets/*|.secrets/*)
      return 0
      ;;
  esac
  return 1
}

scan_content() {
  local file="$1"
  local content="$2"

  if [[ -z "$content" ]]; then
    return 0
  fi

  if printf '%s' "$content" | grep -Eq -- '-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----'; then
    note "$file: private key material"
  fi
  if printf '%s' "$content" | grep -Eq -- 'AKIA[0-9A-Z]{16}'; then
    note "$file: AWS access key id"
  fi
  if printf '%s' "$content" | grep -Eq -- 'github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}'; then
    note "$file: GitHub token"
  fi
  if printf '%s' "$content" | grep -Eq -- 'xox[baprs]-'; then
    note "$file: Slack token"
  fi
  if printf '%s' "$content" | grep -Eq -- 'sk_live_[0-9a-zA-Z]{8,}|sk_test_[0-9a-zA-Z]{8,}'; then
    note "$file: Stripe secret key"
  fi
  if printf '%s' "$content" | grep -Eq -- 'AIza[0-9A-Za-z_-]{35}'; then
    note "$file: Google API key"
  fi
  if printf '%s' "$content" | grep -Eq -- 'sk-ant-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}'; then
    note "$file: LLM API key"
  fi
  if printf '%s' "$content" | grep -Eq -- 'xkeysib-[A-Za-z0-9_-]{20,}'; then
    note "$file: Brevo/Sendinblue API key"
  fi
  if printf '%s' "$content" | grep -Eq -- 'ntn_[A-Za-z0-9]{20,}|secret_[A-Za-z0-9]{40,}'; then
    note "$file: Notion token"
  fi
  if printf '%s' "$content" | grep -Eqi -- '-----BEGIN OPENSSH PRIVATE KEY-----'; then
    note "$file: OpenSSH private key"
  fi

  # Personal contact that does not belong on this public GitHub Pages site.
  # Business matchinggo.com addresses are allowed.
  if printf '%s' "$content" | grep -Eiq -- '[A-Za-z0-9._%+\-]+@gmail\.com|[A-Za-z0-9._%+\-]+@naver\.com|[A-Za-z0-9._%+\-]+@hanmail\.net|[A-Za-z0-9._%+\-]+@daum\.net'; then
    note "$file: personal mailbox address (gmail/naver/hanmail/daum) — do not publish"
  fi
  if printf '%s' "$content" | grep -Eq -- '(^|[^0-9])010[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}([^0-9]|$)|(\+82|82)[-.\s]?10[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}'; then
    note "$file: Korean mobile number"
  fi
  if printf '%s' "$content" | grep -Eiq -- 'mailto:'; then
    if ! printf '%s' "$content" | grep -Eiq -- 'mailto:[^"'\''> ]+@matchinggo\.com'; then
      note "$file: mailto: link that is not a public matchinggo.com address"
    fi
  fi

  # Local extra blocklist (gitignored) — never commit the file itself.
  if [[ -f "$ROOT/.secret-blocklist" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ -z "$line" || "$line" == \#* ]] && continue
      if printf '%s' "$content" | grep -Fqi -- "$line"; then
        note "$file: matched local secret blocklist entry"
      fi
    done < "$ROOT/.secret-blocklist"
  fi
}

file_blob() {
  local f="$1"
  git cat-file -p ":${f}" 2>/dev/null || cat "$f" 2>/dev/null || true
}

while IFS= read -r -d '' file; do
  [[ -z "$file" ]] && continue
  if blocked_name "$file"; then
    note "$file: blocked filename (credentials/private dump)"
    continue
  fi
  # Skip the scanner itself and the example blocklist so documented patterns don't self-match.
  case "$file" in
    scripts/check-secrets.sh|.secret-blocklist.example|.githooks/*|.github/workflows/secret-scan.yml)
      continue
      ;;
    *.png|*.jpg|*.jpeg|*.gif|*.webp|*.ico|*.woff|*.woff2|*.ttf|*.eot)
      continue
      ;;
  esac
  scan_content "$file" "$(file_blob "$file")"
done < <(collect_files)

if [[ "$FAILED" -ne 0 ]]; then
  echo "Secret / private-data scan FAILED. This repo is a public GitHub Pages site." >&2
  echo "Nothing below should be committed or pushed:" >&2
  printf '  - %s\n' "${HITS[@]}" >&2
  echo "Move private files under ./private/ (gitignored) or keep them out of git." >&2
  exit 1
fi

echo "Secret / private-data scan passed ($MODE)."
