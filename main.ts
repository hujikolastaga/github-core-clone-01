import type { AddressInfo } from 'node:net';
import { createApp } from './app.ts';

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function registerWithEnv(envUrl: string, port: number): Promise<void> {
  const registerUrl = `${envUrl.replace(/\/+$/, '')}/register`;
  let lastError: unknown;
  for (let attempt = 0; attempt < 50; attempt++) {
    try {
      const resp = await fetch(registerUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
      });
      if (resp.ok) return;
      lastError = new Error(`register returned HTTP ${resp.status}`);
    } catch (err) {
      lastError = err;
    }
    await delay(Math.min(200, 25 + attempt * 15));
  }
  throw lastError instanceof Error ? lastError : new Error('Failed to register port with runner');
}

async function waitUntilDone(envUrl: string, signal: AbortSignal): Promise<void> {
  const doneUrl = `${envUrl.replace(/\/+$/, '')}/done`;
  while (!signal.aborted) {
    try {
      const resp = await fetch(doneUrl, { signal });
      if (resp.ok) {
        const data = (await resp.json()) as { done?: boolean };
        if (data.done === true) return;
      }
    } catch {
      if (signal.aborted) return;
    }
    await delay(100);
  }
}

async function main(): Promise<void> {
  const envUrl = process.env.MAKEFUN_ENV_URL;
  const devPortRaw = process.env.MAKEFUN_DEV_PORT;

  if (!envUrl && devPortRaw === undefined) {
    process.stderr.write('MAKEFUN_ENV_URL is required\n');
    process.exit(1);
  }

  const { server } = createApp();
  const listenPort = !envUrl && devPortRaw !== undefined ? Number(devPortRaw) : 0;

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    if (!envUrl && devPortRaw !== undefined) {
      server.listen(listenPort, '127.0.0.1', () => {
        server.off('error', reject);
        resolve();
      });
    } else {
      server.listen(0, () => {
        server.off('error', reject);
        resolve();
      });
    }
  });

  const addr = server.address() as AddressInfo;
  if (!addr || typeof addr.port !== 'number') {
    process.stderr.write('Failed to obtain bound server port\n');
    process.exit(1);
  }

  const ac = new AbortController();
  const shutdown = (): void => {
    ac.abort();
    server.close(() => process.exit(0));
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);

  if (!envUrl) {
    process.stdout.write(`listening on http://127.0.0.1:${addr.port}\n`);
    return;
  }

  await registerWithEnv(envUrl, addr.port);
  await waitUntilDone(envUrl, ac.signal);
  await new Promise<void>((resolve) => server.close(() => resolve()));
  process.exit(0);
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
