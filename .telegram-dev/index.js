/**
 * Telegram bridge for DeepSeek Harness: a two-way operator channel.
 *
 * `notify_operator` sends a message to the operator's Telegram chat; a reply is
 * delivered into the calling agent's inbox (`agent.steer`), so the agent hears
 * back at its next step without stopping its work, or becomes the tool result
 * when the agent waits. `telegram_configure` stores the bot token and chat id
 * from a chat, and `telegram_test` sends a probe and can read the reply back.
 * A finished benchmark run posts its summary to the same chat.
 *
 * Settings are resolved at call time, never cached at boot: configuring the bot
 * from any chat takes effect in every chat without a restart.
 *
 * @module @local/dsh-telegram
 */

import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join } from 'node:path';

/** Cordis plugin name. */
export const name = 'telegram';

/** Services the plugin needs at call time. */
export const inject = ['tools'];

const DEFAULT_TOKEN_ENV = 'TELEGRAM_BOT_TOKEN';
const DEFAULT_STATE_FILE = join(homedir(), '.dsh', 'telegram.json');
const DEFAULT_MAX_WAIT_MINUTES = 30;
const DEFAULT_RATE_LIMIT = 10;
/** Telegram caps a message at 4096 characters; keep room for the prefix. */
const TELEGRAM_TEXT_LIMIT = 3_500;
const POLL_TIMEOUT_SECONDS = 25;
const SEND_TIMEOUT_MS = 15_000;
const RETRY_DELAY_MS = 3_000;
const UNCONFIGURED_DELAY_MS = 5_000;
/** Tool results worth forwarding to the operator as a run summary. */
const SUMMARY_TOOLS = new Set(['benchmark_ai', 'benchmark_suite']);

/** Resolve after `ms` milliseconds. */
function sleep(ms) {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    if (typeof timer?.unref === 'function') timer.unref();
  });
}

/** Truncate text to Telegram's practical limit. */
function clip(text, limit = TELEGRAM_TEXT_LIMIT) {
  const value = String(text ?? '');
  return value.length <= limit ? value : `${value.slice(0, limit - 20)}\n… (truncated)`;
}

/** Read the small state file the configure tool writes. */
function readState(path) {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    return parsed !== null && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

/** Write the state file, owner-only. */
function writeState(path, state) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
}

/**
 * Normalize the plugin row config.
 * @param {unknown} config - raw config from the profile.
 */
function normalize(config) {
  const source = config !== null && typeof config === 'object' ? config : {};
  const rawChat = source.chatId === undefined || source.chatId === null ? undefined : String(source.chatId).trim();
  const chatId = rawChat === undefined || rawChat.length === 0 ? undefined : rawChat;
  const allowFrom = Array.isArray(source.allowFrom) && source.allowFrom.length > 0
    ? source.allowFrom.map((id) => String(id).trim()).filter((id) => id.length > 0)
    : chatId === undefined ? [] : [chatId];
  const wait = Number(source.maxWaitMinutes);
  const rate = Number(source.rateLimitPerMinute);
  return {
    botTokenEnv: typeof source.botTokenEnv === 'string' && source.botTokenEnv.trim().length > 0
      ? source.botTokenEnv.trim()
      : DEFAULT_TOKEN_ENV,
    botTokenRef: typeof source.botTokenRef === 'string' && source.botTokenRef.trim().length > 0
      ? source.botTokenRef.trim()
      : typeof source.botTokenEnv === 'string' && source.botTokenEnv.trim().length > 0 ? source.botTokenEnv.trim() : DEFAULT_TOKEN_ENV,
    stateFile: typeof source.stateFile === 'string' && source.stateFile.trim().length > 0
      ? source.stateFile.trim()
      : DEFAULT_STATE_FILE,
    ...(chatId === undefined ? {} : { chatId }),
    allowFrom,
    inbound: source.inbound !== false,
    maxWaitMinutes: Number.isFinite(wait) && wait >= 0 ? Math.min(wait, 120) : DEFAULT_MAX_WAIT_MINUTES,
    rateLimitPerMinute: Number.isFinite(rate) && rate > 0 ? Math.min(rate, 30) : DEFAULT_RATE_LIMIT,
    summary: source.summary !== false,
  };
}

/**
 * Register the tools and the Telegram polling loop.
 * @param {any} ctx - plugin context.
 * @param {Record<string, unknown>} [config] - plugin row config.
 */
export function apply(ctx, config) {
  const settings = normalize(config);
  /** Telegram message id -> the ask it belongs to. */
  const pending = new Map();
  /** Tool-call id -> tool name, so a result can be recognised. */
  const toolNames = new Map();
  const controller = new AbortController();
  let offset = 0;
  let stopped = false;
  let sendTimes = [];

  const credentials = () => (typeof ctx.get === 'function' ? ctx.get('credentials') : undefined);

  /** Token from the credential store, else the environment. */
  const resolveToken = async () => {
    const provider = credentials();
    if (provider !== undefined && typeof provider.resolve === 'function') {
      try {
        const found = await provider.resolve(settings.botTokenRef);
        if (typeof found?.value === 'string' && found.value.trim().length > 0) {
          return { token: found.value.trim(), source: found.source };
        }
      } catch {
        // Fall through to the environment.
      }
    }
    const fromEnv = String(process.env[settings.botTokenEnv] ?? '').trim();
    return fromEnv.length > 0 ? { token: fromEnv, source: 'env' } : undefined;
  };

  /** Chat id from the configure state file, else the profile config. */
  const resolveChatId = () => {
    const state = readState(settings.stateFile);
    if (typeof state.chatId === 'string' && state.chatId.trim().length > 0) return state.chatId.trim();
    return settings.chatId;
  };

  /** `[project-name]` prefix so several sessions are distinguishable in one chat. */
  const labelFor = (agent) => {
    const cwd = agent?.session?.header?.cwd;
    return cwd === undefined ? 'session' : basename(String(cwd)) || 'session';
  };

  const api = async (token, method, body, signal) => {
    const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      ...(signal === undefined ? {} : { signal }),
    });
    const payload = await response.json().catch(() => undefined);
    if (payload === undefined || payload.ok !== true) {
      throw new Error(`telegram ${method} failed: ${payload?.description ?? `HTTP ${response.status}`}`);
    }
    return payload.result;
  };

  const rateLimit = () => {
    const now = Date.now();
    sendTimes = sendTimes.filter((time) => now - time < 60_000);
    if (sendTimes.length >= settings.rateLimitPerMinute) {
      throw new Error(`telegram: rate limit (${settings.rateLimitPerMinute}/min) reached; try again shortly`);
    }
    sendTimes.push(now);
  };

  const send = async (text, agent) => {
    const resolved = await resolveToken();
    if (resolved === undefined) {
      throw new Error(`telegram: no bot token; run telegram_configure with a token, or set ${settings.botTokenEnv}`);
    }
    const chatId = resolveChatId();
    if (chatId === undefined) {
      throw new Error('telegram: no chat id; run telegram_configure with your numeric chat id');
    }
    rateLimit();
    const label = labelFor(agent);
    return api(resolved.token, 'sendMessage', {
      chat_id: chatId,
      text: clip(`[${label}] ${text}`),
      disable_web_page_preview: true,
    }, AbortSignal.timeout(SEND_TIMEOUT_MS));
  };

  /** Hand the operator's text to an agent's inbox. */
  const deliver = (agent, text) => {
    if (agent === undefined || agent === null) throw new Error('no agent to deliver to');
    const message = {
      role: 'user',
      id: randomUUID(),
      content: [{ type: 'text', text }],
      source: { kind: 'user' },
    };
    if (typeof agent.steer === 'function') {
      agent.steer(message);
      return;
    }
    if (typeof agent.followup === 'function') {
      agent.followup(message);
      return;
    }
    throw new Error('this agent cannot receive operator messages');
  };

  const handleUpdate = async (update) => {
    const message = update?.message;
    if (message === undefined || typeof message.text !== 'string') return;
    const chat = String(message.chat?.id ?? '');
    const from = String(message.from?.id ?? '');
    const allowed = settings.allowFrom.length === 0
      ? chat === resolveChatId() || from === resolveChatId()
      : settings.allowFrom.includes(chat) || settings.allowFrom.includes(from);
    if (!allowed) return;
    const text = message.text.trim();
    if (text.length === 0) return;
    const replyTo = message.reply_to_message?.message_id;
    const key = replyTo === undefined
      ? pending.size === 1 ? [...pending.keys()][0] : undefined
      : String(replyTo);
    const entry = key === undefined ? undefined : pending.get(key);
    if (entry === undefined) {
      await send('No agent is waiting for that reply. Reply directly to a message an agent sent.');
      return;
    }
    pending.delete(key);
    if (entry.timer !== undefined) clearTimeout(entry.timer);
    if (typeof entry.resolve === 'function') {
      entry.resolve({ replied: true, text });
      return;
    }
    try {
      deliver(entry.agent, `Operator reply: ${text}`);
    } catch (error) {
      ctx.logger?.warn?.(`telegram: could not deliver the reply: ${String(error?.message ?? error)}`);
    }
  };

  const poll = async () => {
    while (!stopped) {
      const resolved = await resolveToken();
      if (resolved === undefined || resolveChatId() === undefined) {
        await sleep(UNCONFIGURED_DELAY_MS);
        continue;
      }
      try {
        const updates = await api(resolved.token, 'getUpdates', {
          offset,
          timeout: POLL_TIMEOUT_SECONDS,
          allowed_updates: ['message'],
        }, controller.signal);
        if (!Array.isArray(updates) || updates.length === 0) {
          await sleep(1_000);
          continue;
        }
        for (const update of updates) {
          if (typeof update?.update_id === 'number') offset = Math.max(offset, update.update_id + 1);
          await handleUpdate(update);
        }
      } catch (error) {
        if (stopped) return;
        ctx.logger?.warn?.(`telegram: polling failed: ${String(error?.message ?? error)}`);
        await sleep(RETRY_DELAY_MS);
      }
    }
  };

  /** Ask the operator and optionally wait; shared by the tools. */
  const ask = async (text, agent, waitMinutes) => {
    const sent = await send(text, agent);
    const key = String(sent.message_id);
    const entry = { agent };
    pending.set(key, entry);
    if (waitMinutes <= 0) return { sent: true, message_id: sent.message_id, replied: false };
    return await new Promise((resolve) => {
      entry.timer = setTimeout(() => {
        pending.delete(key);
        resolve({ sent: true, message_id: sent.message_id, replied: false, timed_out: true });
      }, waitMinutes * 60_000);
      entry.resolve = (value) => resolve({ sent: true, message_id: sent.message_id, ...value });
    });
  };

  const waitFor = (args) => {
    const requested = Number(args?.wait_minutes);
    return Number.isFinite(requested) && requested > 0 ? Math.min(requested, settings.maxWaitMinutes) : 0;
  };

  const answerOutput = {
    schema: {
      type: 'object',
      properties: {
        sent: { type: 'boolean' },
        message_id: { type: 'integer' },
        replied: { type: 'boolean' },
        text: { type: 'string' },
        timed_out: { type: 'boolean' },
      },
      required: ['sent'],
    },
    render: (_args, value) => [{
      type: 'text',
      text: value.replied
        ? `operator replied: ${value.text}`
        : value.timed_out
          ? 'operator did not reply in time; continue or try again later'
          : `sent to operator (message ${value.message_id})`,
    }],
  };

  ctx.effect(() => ctx.tools.register({
    name: 'notify_operator',
    description: 'Send a message to the operator on Telegram. Use it for a decision only a human can make (installing a package, granting access, picking between two options) or for something they should know. With `wait_minutes` the call blocks until they reply or the wait runs out; without it the reply is delivered to this session as a user message, so keep working.',
    parameters: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'What to tell the operator. Plain text; say what you need and what you tried.' },
        wait_minutes: { type: 'number', description: `How long to wait for a reply (0 or omitted = do not wait; max ${settings.maxWaitMinutes}).` },
      },
      required: ['text'],
      additionalProperties: false,
    },
    output: answerOutput,
    timeoutMs: (settings.maxWaitMinutes + 2) * 60_000,
    async execute(args, exec) {
      const text = typeof args?.text === 'string' ? args.text.trim() : '';
      if (text.length === 0) throw new Error('notify_operator needs a non-empty `text`');
      return ask(text, exec?.agent, waitFor(args));
    },
  }));

  ctx.effect(() => ctx.tools.register({
    name: 'telegram_configure',
    description: 'Configure the Telegram bridge from a chat: store the bot token (in the credential store) and the numeric chat id, then verify the token with getMe. Works once per profile — every chat shares it.',
    parameters: {
      type: 'object',
      properties: {
        bot_token: { type: 'string', description: 'Telegram bot token from @BotFather. Stored in the credential store, never written to config.' },
        chat_id: { type: 'string', description: 'Numeric chat id the bot should post to (message the bot, then read getUpdates).' },
      },
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          bot: { type: 'string' },
          chat_id: { oneOf: [{ type: 'string' }, { type: 'null' }] },
          token_source: { type: 'string' },
          token_saved: { type: 'boolean' },
          chat_saved: { type: 'boolean' },
        },
        required: ['token_saved', 'chat_saved'],
      },
      render: (_args, value) => [{
        type: 'text',
        text: `telegram: bot @${value.bot ?? '?'}${value.chat_id === null || value.chat_id === undefined ? ', no chat id yet' : `, chat ${value.chat_id}`} (token from ${value.token_source ?? 'unknown'})`,
      }],
    },
    async execute(args) {
      const token = typeof args?.bot_token === 'string' ? args.bot_token.trim() : '';
      const chatId = args?.chat_id === undefined ? '' : String(args.chat_id).trim();
      let tokenSaved = false;
      let chatSaved = false;
      if (token.length > 0) {
        const provider = credentials();
        if (provider === undefined || typeof provider.set !== 'function') {
          throw new Error(`telegram: no credential store in this profile; set ${settings.botTokenEnv} in the environment instead`);
        }
        await provider.set(settings.botTokenRef, token);
        tokenSaved = true;
      }
      if (chatId.length > 0) {
        const state = readState(settings.stateFile);
        state.chatId = chatId;
        writeState(settings.stateFile, state);
        chatSaved = true;
      }
      const resolved = await resolveToken();
      if (resolved === undefined) throw new Error('telegram: no bot token stored and none in the environment');
      const me = await api(resolved.token, 'getMe', {}, AbortSignal.timeout(SEND_TIMEOUT_MS));
      return {
        ...(typeof me?.username === 'string' ? { bot: me.username } : {}),
        chat_id: resolveChatId() ?? null,
        token_source: resolved.source,
        token_saved: tokenSaved,
        chat_saved: chatSaved,
      };
    },
  }));

  ctx.effect(() => ctx.tools.register({
    name: 'telegram_test',
    description: 'Send a test message to the configured Telegram chat and, optionally, wait for the operator to reply. Use it right after telegram_configure to prove the bot reaches the human.',
    parameters: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'Optional probe text; defaults to a test sentence.' },
        wait_minutes: { type: 'number', description: `How long to wait for a reply (0 or omitted = do not wait; max ${settings.maxWaitMinutes}).` },
      },
      additionalProperties: false,
    },
    output: answerOutput,
    timeoutMs: (settings.maxWaitMinutes + 2) * 60_000,
    async execute(args, exec) {
      const text = typeof args?.text === 'string' && args.text.trim().length > 0
        ? args.text.trim()
        : 'test message from Goblin Bench — reply here and the agent gets it.';
      return ask(text, exec?.agent, waitFor(args));
    },
  }));

  if (settings.inbound) {
    ctx.effect(() => {
      void poll();
      return () => {
        stopped = true;
        controller.abort();
      };
    });
  }

  if (settings.summary) {
    ctx.on('session/event', (session, event) => {
      if (event?.type === 'tool/call') {
        const callId = event.data?.callId;
        if (callId !== undefined) toolNames.set(String(callId), String(event.data?.name ?? ''));
        return;
      }
      if (event?.type !== 'tool/result') return;
      const message = event.data?.message;
      const callId = message?.toolCallId === undefined ? undefined : String(message.toolCallId);
      if (callId === undefined) return;
      const toolName = toolNames.get(callId);
      if (toolName === undefined || !SUMMARY_TOOLS.has(toolName)) return;
      toolNames.delete(callId);
      const blocks = Array.isArray(message?.content) ? message.content : [];
      const text = blocks
        .filter((block) => block?.type === 'text' && typeof block.text === 'string')
        .map((block) => block.text)
        .join('\n')
        .trim();
      if (text.length === 0) return;
      void send(`${toolName} finished\n\n${text}`).catch((error) => {
        ctx.logger?.warn?.(`telegram: summary not sent: ${String(error?.message ?? error)}`);
      });
    });
  }
}
