#!/usr/bin/env bash
# One-line Telegram progress ping. Token read from Hermes .env, never printed.
TOKEN=$(grep '^TELEGRAM_BOT_TOKEN=' "/c/Users/THE M/AppData/Local/hermes/.env" | head -1 | cut -d= -f2- | tr -d '"\r')
curl -s -o /dev/null -w "telegram http=%{http_code}\n" "https://api.telegram.org/bot${TOKEN}/sendMessage" \
  --data-urlencode "chat_id=5773748280" --data-urlencode "text=$1"
