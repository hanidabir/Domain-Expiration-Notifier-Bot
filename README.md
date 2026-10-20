# Safenta Domain Notifications

A lightweight Telegram bot for tracking domain expiration dates and reminding users to renew their domains before they expire.

## Features

- Language: Persian
- Register one or multiple domains.
- Retrieve expiration dates automatically via WhoAPI when available.
- Enter expiration dates manually when automatic lookup is unavailable.
- View and remove registered domains.
- Run periodic checks and send expiration reminders.

## Requirements

- Python 3.12+
- A Telegram Bot Token from [@BotFather](https://t.me/BotFather)
- A [WhoAPI](https://whoapi.com/) API key for automatic expiration lookups

## Setup

1. Clone this repository.
2. Change env.example to .env
3. Create a virtual environment and install dependencies:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

4. Configure the environment variables:

   ```env
   TELEGRAM_BOT_TOKEN=
   WHOAPI_KEY=
   DB_PATH=/var/lib/telegram-bots/domain-expiration-bot/domains.sqlite3
   WARNING_DAYS=30
   ```

5. Ensure `schema.sql` is present beside `bot.py`.
6. Run the bot:

   ```bash
   python bot.py
   ```

## Notes

- Domain checks are scheduled every 7 days.
- Some domain extensions may require manual expiration dates.
- Email notifications require SMTP configuration.
- Keep API keys and bot tokens private; never commit secrets to Git.
