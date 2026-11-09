#!/usr/bin/env bash
set -uo pipefail

MAX_ATTEMPTS="${1:-5}"
[[ "${MAX_ATTEMPTS}" =~ ^[0-9]+$ ]] || MAX_ATTEMPTS=5
shift || true

touch_last_run=0
for arg in "$@"; do
  [ "${arg}" = "--touch-last-run" ] && touch_last_run=1
done

BRANCH="${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
STATE_FILES=(reported.txt attempted.txt users.txt .gitattributes)
[ "${touch_last_run}" = "1" ] && date +%s > .last_run_end && STATE_FILES+=(.last_run_end)

exec 9>"${TMPDIR:-/tmp}/reporter-state.lock"
flock 9

git config user.name "${GIT_AUTHOR_NAME:-github-actions[bot]}"
git config user.email "${GIT_AUTHOR_EMAIL:-github-actions[bot]@users.noreply.github.com}"

git config merge.ours.driver true
if ! grep -qs 'merge=union' .gitattributes 2>/dev/null; then
  {
    echo 'reported.txt merge=union'
    echo 'attempted.txt merge=union'
    echo 'users.txt merge=union'
    echo '.last_run_end merge=ours'
  } >> .gitattributes
fi

if ! git diff --quiet -- .gitattributes; then
  git add .gitattributes
  git commit -q -m "chore: add state merge drivers [skip ci]" || true
fi

add_args=()
for f in "${STATE_FILES[@]}"; do
  if [ -e "$f" ]; then add_args+=("$f"); else echo "skipping $f (not present)"; fi
done
if [ "${#add_args[@]}" -eq 0 ]; then
  echo "no state files present; nothing to commit"
  exit 0
fi
git add -- "${add_args[@]}"

if git diff --staged --quiet; then
  echo "nothing to commit"
  exit 0
fi
git commit -q -m "chore: checkpoint progress [skip ci]"

for attempt in $(seq 1 "${MAX_ATTEMPTS}"); do
  if git push origin "HEAD:${BRANCH}"; then
    echo "state pushed on attempt ${attempt}"
    exit 0
  fi
  echo "::warning::push rejected (attempt ${attempt}/${MAX_ATTEMPTS}); integrating origin/${BRANCH}"
  if ! git fetch origin "${BRANCH}"; then
    echo "::warning::fetch failed; backing off"
    sleep $((attempt * 5))
    continue
  fi
  if git rebase "origin/${BRANCH}"; then
    :
  else
    echo "::warning::rebase conflict; aborting and retrying"
    git rebase --abort || true
  fi
  sleep $((attempt * 5))
done

echo "::error::could not push state after ${MAX_ATTEMPTS} attempts"
exit 1
