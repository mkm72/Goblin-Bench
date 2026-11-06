# Telegram for DeepSeek Harness

A two-way operator channel for DSH agents, configured from chat.

```
agent: notify_operator("Installing pytest needs a package I cannot reach. Install it, or suggest an alternative.")
you (Telegram, replying to that message): "use unittest, it is already installed"
agent's next step: Operator reply: use unittest, it is already installed
```

No approval flow: nothing is granted by a tap, and a reply is text the agent has to
interpret.

## Install

Link or copy this directory into the profile's `node_modules/@local/dsh-telegram` and add
`@local/dsh-telegram` to the profile's `dsh.profile.bundles` (and its `link:` dependency),
the same way `@local/dsh-goblin-bench` is installed. Restart DSH once so the bundle loads.
After that, configuration is live — no further restart.

## Configure it from a chat

Open any chat and say *"configure the telegram bot"*. The agent calls:

```
telegram_configure({ bot_token: "123456:ABC…", chat_id: "123456789" })
```

- The **token** goes into DSH's credential store (`ctx.credentials`), never into a config
  file, and is verified immediately with `getMe`.
- The **chat id** is written to `~/.dsh/telegram.json` (mode 0600).
- Both are resolved at call time, so every chat in the profile uses them at once, with no
  restart.

Then prove it reaches you:

```
telegram_test({ wait_minutes: 2 })
```

It sends a probe and returns your reply when you swipe-reply in Telegram.

### Getting a token and a chat id

1. Message **@BotFather**, `/newbot`, copy the token.
2. Send your new bot any message (a bot cannot message you first).
3. Read the chat id from `https://api.telegram.org/bot<TOKEN>/getUpdates` —
   `message.chat.id`. If you would rather not open that URL, call
   `telegram_test` once and copy the id from the error, or ask the agent to run it with
   your message.

The token can also come from the environment (`TELEGRAM_BOT_TOKEN`); the credential store
wins, the environment is the fallback.

## Tools

| Tool | Purpose |
|---|---|
| `telegram_configure({ bot_token?, chat_id? })` | store the token and chat id, verify with `getMe` |
| `telegram_test({ text?, wait_minutes? })` | send a probe, optionally wait for your reply |
| `notify_operator({ text, wait_minutes? })` | message you from any agent; wait or keep working |

`wait_minutes` is capped by `maxWaitMinutes` (default 30). Without it the call returns at
once and your reply is steered into the agent's session.

## How a reply reaches the agent

The plugin long-polls `getUpdates` and matches your reply by Telegram's reply context:

- **agent waiting** on that call → your text is its tool result;
- **agent busy** → `agent.steer(...)`: it arrives at the next step, the work continues;
- **agent idle** → `agent.followup(...)`: it opens a new turn.

A reply that matches no pending message gets a short explanation instead of being dropped.

## Run summaries

When a `benchmark_ai` or `benchmark_suite` tool call finishes, its rendered summary (score,
verdict, report path) is posted to the chat. No benchmark change is involved — the plugin
watches session tool events.

## One bot, all chats

Configuration is per **profile**, not per chat: one token, one chat id, every session posts
there. Messages are prefixed with the project folder (`[goblin-bench] …`) so you can tell
them apart, and replies are routed per message, so several sessions can be waiting at once.

## Security

- Only chats in `allowFrom` (default: the configured chat id) are read.
- The token lives in the credential store or the environment — never in the profile patch,
  a report, or a log.
- No approvals, no buttons: the bot cannot grant permissions.
- Sends are rate limited (default 10/min) and time out after 15 s; a Telegram outage never
  fails an agent's turn beyond the wait the agent itself asked for.

## Tests

```bash
node --check index.js
node test.mjs
```

`test.mjs` stubs `fetch` and the credential store: no network, no token, no real chat.

## Limits

- One chat per profile.
- Pending asks are matched in memory; restarting DSH forgets them.
- No media, attachments, or group threading.
