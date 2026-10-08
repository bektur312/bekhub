#!/usr/bin/env bash
# Сыр маалыматтарды (сырсөз, API ачкыч, токен, .env, кардардын жеке маалыматы)
# репого кирип кетүүдөн коргойт.
#
# Режимдер:
#   check-secrets.sh            — staged өзгөрүүлөрдү текшерет (git pre-commit үчүн)
#   check-secrets.sh --all      — HEAD'деги бардык файлдарды текшерет
#   check-secrets.sh --hook     — Claude Code PreToolUse hook: stdin'ден JSON окуйт,
#                                 `git commit` / `git push` алдында текшерет
#
# Чын эле сыр эмес сапты өткөрүп жиберүү үчүн ага `secret-scan:allow` деп жазыңыз.
# Табылган маанинин өзү эч качан чыгарылбайт — файл, сап жана түрү гана.

set -uo pipefail

SELF="scripts/check-secrets.sh"
mode="${1:---staged}"

cd "$(git rev-parse --show-toplevel 2>/dev/null)" || exit 0

if [[ "$mode" == "--hook" ]]; then
  input="$(cat)"
  cmd="$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)"
  re_push='git[[:space:]]+([^|;&]*[[:space:]])?push([[:space:]]|$)'
  re_commit='git[[:space:]]+([^|;&]*[[:space:]])?commit([[:space:]]|$)'
  re_commit_all='commit[^|;&]*[[:space:]](-a|--all|-[a-zA-Z]*a[a-zA-Z]*)([[:space:]]|$)'
  if [[ "$cmd" =~ $re_push ]]; then
    scan="all"
  elif [[ "$cmd" =~ $re_commit ]]; then
    if [[ "$cmd" =~ $re_commit_all ]]; then
      scan="worktree"
    else
      scan="staged"
    fi
  else
    exit 0
  fi
else
  case "$mode" in
    --all) scan="all" ;;
    *) scan="staged" ;;
  esac
fi

# --- Текшериле турган файлдар жана кошулган саптар ---------------------------

files_list() {
  case "$scan" in
    staged)   git diff --cached --name-only --diff-filter=ACMR ;;
    worktree) git diff HEAD --name-only --diff-filter=ACMR 2>/dev/null || git diff --cached --name-only --diff-filter=ACMR ;;
    all)      git rev-parse -q --verify HEAD >/dev/null && git ls-tree -r --name-only HEAD ;;
  esac
}

# Чыгарат: file<TAB>lineno<TAB>content
added_lines() {
  case "$scan" in
    staged|worktree)
      local range=(--cached)
      if [[ "$scan" == "worktree" ]] && git rev-parse -q --verify HEAD >/dev/null; then range=(HEAD); fi
      git diff "${range[@]}" -U0 --no-color --no-ext-diff --diff-filter=ACMR -- . ":(exclude)$SELF" |
        awk '
          /^\+\+\+ / { f = substr($0, 7); next }
          /^@@ / { split($3, a, ","); n = substr(a[1], 2) + 0; next }
          /^\+/ { print f "\t" n "\t" substr($0, 2); n++ }
        '
      ;;
    all)
      git rev-parse -q --verify HEAD >/dev/null || return 0
      git grep -n -I -e '' HEAD -- . ":(exclude)$SELF" |
        sed -E 's/^HEAD://' |
        awk -F: '{ f = $1; n = $2; sub(/^[^:]*:[^:]*:/, ""); print f "\t" n "\t" $0 }'
      ;;
  esac
}

findings=()

# --- 1. Тыюу салынган файлдар ------------------------------------------------

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  base="${f##*/}"
  case "$base" in
    .env.example|.env.sample|.env.template) continue ;;
    .env|.env.*|*.pem|*.key|*.p12|*.pfx|*.keystore|*.jks|id_rsa*|id_ed25519*|id_ecdsa*|\
    credentials.json|service-account*.json|*-sa-key.json|.netrc|.pgpass|*.kdbx)
      findings+=("$f — сыр файл (бул файл репого кирбеши керек)") ;;
  esac
done < <(files_list)

# --- 2. Саптардагы сыр маалыматтар -------------------------------------------

# name|flags|regex   (flags: i = регистрге карабайт)
patterns=(
  "Жеке ачкыч (private key)||-----BEGIN [A-Z ]*PRIVATE KEY-----"
  "AWS ачкычы||(AKIA|ASIA)[0-9A-Z]{16}"
  "GitHub токени||(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"
  "Anthropic API ачкычы||sk-ant-[A-Za-z0-9_-]{20,}"
  "OpenAI API ачкычы||sk-(proj-|svcacct-)?[A-Za-z0-9_-]{32,}"
  "Google API ачкычы||AIza[0-9A-Za-z_-]{35}"
  "Slack токени||xox[abposr]-[A-Za-z0-9-]{10,}"
  "Telegram бот токени||[0-9]{8,10}:AA[0-9A-Za-z_-]{33}"
  "Meta / WhatsApp токени||EAA[A-Za-z0-9]{60,}"
  "Stripe ачкычы||(sk|rk)_live_[0-9A-Za-z]{20,}"
  "JWT токен||eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
  "Сырсөз камтылган URL||[a-z][a-z0-9+.-]*://[^/:@[:space:]\"']+:[^/@[:space:]\"']{3,}@"
  "Сырсөз / токен / ачкыч мааниси|i|(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key|amo[_-]?(crm)?[_-]?(key|token|secret))[\"']?[[:space:]]*[:=][[:space:]]*[\"'][^\"'[:space:]]{8,}[\"']"
  "Кыргызстандык телефон номери (кардардын маалыматы?)||\+?996[[:space:]-]?\(?[0-9]{3}\)?([[:space:]-]?[0-9]){6}([^0-9]|$)"
  "Кыргызстандык телефон номери (кардардын маалыматы?)||(^|[^0-9+])0[2579][0-9]{2}([[:space:]-]?[0-9]){6}([^0-9]|$)"
  "ПИН / ИНН (14 сан, кардардын маалыматы?)||(^|[^0-9])[12][0-9]{13}([^0-9]|$)"
)

lines="$(added_lines | grep -v 'secret-scan:allow' || true)"

if [[ -n "$lines" ]]; then
  for p in "${patterns[@]}"; do
    name="${p%%|*}"; rest="${p#*|}"
    flags="${rest%%|*}"; re="${rest#*|}"
    grep_opts=(-E)
    [[ "$flags" == *i* ]] && grep_opts+=(-i)
    while IFS=$'\t' read -r f n _; do
      [[ -z "$f" ]] && continue
      findings+=("$f:$n — $name")
    done < <(printf '%s\n' "$lines" | grep "${grep_opts[@]}" -- "$re")
  done
fi

[[ ${#findings[@]} -eq 0 ]] && exit 0

# --- Отчёт ------------------------------------------------------------------

{
  echo "⚠️  СЫР МААЛЫМАТ ТАБЫЛДЫ — коммит/пуш токтотулду."
  echo
  printf '   • %s\n' "${findings[@]}" | sort -u
  echo
  echo "Эмне кылуу керек:"
  echo "  1. Маанини коддон алып салып, .env файлына көчүрүңүз (ал .gitignore'до)."
  echo "     Коддо аны айлана-чөйрө өзгөрмөсүнөн окуңуз, .env.example'ге аты гана калсын."
  echo "  2. Сыр файлды индекстен чыгарыңыз: git rm --cached <файл>"
  echo "  3. Эгер мурун пушталып кетсе — ачкычты/сырсөздү ДАРОО алмаштырыңыз (rotate):"
  echo "     репо ачык, аны ким болсо да көчүрүп алган болушу мүмкүн."
  echo "  4. Чын эле сыр эмес болсо, сапка 'secret-scan:allow' деп комментарий кошуңуз."
  if [[ "$mode" == "--hook" ]]; then
    echo
    echo "Claude: сырды тазалап, колдонуучуга чатта ⚠️ ЭСКЕРТҮҮ жаз (CLAUDE.md'деги эрежени кара)."
    echo "Маанинин өзүн чатка эч качан көчүрбө."
  fi
} >&2

[[ "$mode" == "--hook" ]] && exit 2
exit 1
