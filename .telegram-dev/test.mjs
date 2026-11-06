import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { apply } from './index.js';

const realFetch = globalThis.fetch;
const calls = [];
let nextMessageId = 100;
let lastSentId;
let updates = [];
const stored = new Map();
const jsonBody = (payload) => ({ ok: true, status: 200, json: async () => payload });

globalThis.fetch = async (url, options = {}) => {
  const method = String(url).split('/').pop();
  const body = options.body === undefined ? undefined : JSON.parse(options.body);
  calls.push({ method, body });
  if (method === 'sendMessage') {
    lastSentId = (nextMessageId += 1);
    return jsonBody({ ok: true, result: { message_id: lastSentId } });
  }
  if (method === 'getMe') return jsonBody({ ok: true, result: { username: 'gb_test_bot' } });
  if (method === 'getUpdates') return jsonBody({ ok: true, result: updates.splice(0) });
  return jsonBody({ ok: false, description: `unexpected ${method}` });
};

const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });
const results = [];
const check = (name, ok, detail) => results.push({ name, ok: Boolean(ok), detail });

const stateFile = join(await mkdtemp(join(tmpdir(), 'tg-')), 'telegram.json');
const credentials = {
  resolve: async (ref) => (stored.has(ref) ? { value: stored.get(ref), source: 'file' } : undefined),
  set: async (ref, value) => { stored.set(ref, value); },
};

function makeCtx(config) {
  const registered = [];
  const listeners = [];
  const disposers = [];
  const ctx = {
    logger: { warn: () => {} },
    get: (name) => (name === 'credentials' ? credentials : undefined),
    tools: { register(def) { registered.push(def); return () => {}; } },
    on(name, fn) { listeners.push([name, fn]); return () => {}; },
    effect(fn) { const disposer = fn(); if (typeof disposer === 'function') disposers.push(disposer); return () => {}; },
  };
  apply(ctx, config);
  return { registered, listeners, disposers };
}

const { registered, listeners } = makeCtx({ stateFile, maxWaitMinutes: 5 });
const tool = (name) => registered.find((def) => def.name === name);
const notify = tool('notify_operator');
const configure = tool('telegram_configure');
const test = tool('telegram_test');
check('registers all three tools', Boolean(notify && configure && test));

const steered = [];
const agent = { id: 'a1', session: { header: { cwd: '/home/mkm7/code/demo-project' } }, steer: (message) => steered.push(message) };
let error = '';
try { await notify.execute({ text: 'x' }, { agent }); } catch (caught) { error = String(caught?.message ?? caught); }
check('unconfigured notify fails clearly', error.includes('no bot token'), error);

const configured = await configure.execute({ bot_token: '123:abc', chat_id: '42' }, { agent });
check('configure stores the token', stored.get('TELEGRAM_BOT_TOKEN') === '123:abc');
check('configure verifies with getMe', calls.some((call) => call.method === 'getMe') && configured.bot === 'gb_test_bot', JSON.stringify(configured));
check('configure writes the chat id', JSON.parse(await readFile(stateFile, 'utf8')).chatId === '42');
check('configure reports chat id', configured.chat_id === '42', configured.chat_id);

const sent = await notify.execute({ text: 'need package X' }, { agent });
const sentBody = calls.filter((call) => call.method === 'sendMessage').at(-1)?.body;
check('notify uses the stored chat id', sentBody?.chat_id === '42');
check('messages carry the project prefix', String(sentBody?.text).startsWith('[') && String(sentBody?.text).includes('need package X'), sentBody?.text);

updates.push({ update_id: 1, message: { chat: { id: 42 }, from: { id: 42 }, text: 'use Y', reply_to_message: { message_id: sent.message_id } } });
await sleep(6000);
check('reply steered to the agent', steered.length === 1 && steered[0].content[0].text.includes('use Y'), JSON.stringify(steered));

const waiting = test.execute({ wait_minutes: 0.05, text: 'probe' }, { agent });
await sleep(200);
const probeId = String(lastSentId);
updates.push({ update_id: 2, message: { chat: { id: 42 }, from: { id: 42 }, text: 'probe reply', reply_to_message: { message_id: probeId } } });
const tested = await waiting;
check('telegram_test reads the reply', tested.replied === true && tested.text === 'probe reply', JSON.stringify(tested));
check('probe uses the test sentence', String(calls.filter((call) => call.method === 'sendMessage').at(-1)?.body?.text).includes('probe'));

globalThis.fetch = realFetch;
let failed = 0;
for (const result of results) {
  if (!result.ok) failed += 1;
  console.log(`${result.ok ? 'PASS' : 'FAIL'}  ${result.name}${result.ok ? '' : `  -> ${result.detail ?? ''}`}`);
}
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exitCode = failed === 0 ? 0 : 1;
