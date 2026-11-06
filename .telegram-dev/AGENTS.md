# AGENTS.md

Guidance for agents working in this repository.

`@local/dsh-telegram` is a DeepSeek Harness plugin bundle: a two-way Telegram
operator channel. Three tools (`notify_operator`, `telegram_configure`,
`telegram_test`), one long-poll loop, one summary forwarder.

## Layout

```
index.js            the whole plugin (node:* builtins and global fetch only)
cordis.patch.yml    bundle patch that inserts the plugin row
package.json        bundle manifest (dsh.bundle.patch, exports, files)
README.md           setup, config, tool contracts
test.mjs            stub-fetch tests (no network, no token)
```

## Hard rules

1. **No npm dependencies.** `node:crypto`, `node:fs`, `node:os` and `node:path` only.
2. **No approval semantics.** The bot sends text and receives text; it must never
   grant anything. No inline buttons that resolve permissions.
3. **The token comes from the credential store or the environment**, never from
   config and never logged. `telegram_configure` writes it with `ctx.credentials.set`;
   `~/.dsh/telegram.json` holds only the chat id.
4. **Settings are resolved at call time**, never cached at apply: configuring from
   one chat must take effect in every chat without a restart.
5. **Only allowlisted chats are read.** Unknown chats are dropped silently.
6. **A Telegram failure never fails an agent's turn.** Sends time out and throw a
   clear error; the poll loop backs off and keeps going.
7. **Replies go to the agent's inbox**: `agent.steer` while it runs, `agent.followup`
   when idle, the tool result when it is waiting.
8. **No secret exposure.** Never add code that scrapes sessions or reports for
   content to send.

## Testing

```bash
node --check index.js
node test.mjs
```

Assert on: the three tools registering, a clear unconfigured error, configure storing
the token and chat id and calling `getMe`, `notify_operator` using the stored values
with the project prefix, reply routing (steer vs waiting call), the probe returning
the reply, unknown-chat rejection, and summary forwarding.
