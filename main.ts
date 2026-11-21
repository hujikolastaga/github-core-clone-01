import { spawn, type ChildProcess } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
let activeChild: ChildProcess | null = null;
let exiting = false;

function shutdown(sig: NodeJS.Signals): void {
  exiting = true;
  if (activeChild && !activeChild.killed) {
    activeChild.kill(sig);
  }
}

process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));

function launch(binPath: string, allowTmpFallback: boolean): void {
  const child = spawn(binPath, {
    stdio: 'inherit',
    env: process.env,
  });
  activeChild = child;

  child.once('error', (err: NodeJS.ErrnoException) => {
    if (
      allowTmpFallback &&
      (err.code === 'EACCES' || err.code === 'ENOEXEC' || err.code === 'EPERM')
    ) {
      try {
        const tmpBin = '/tmp/forge-linux-amd64';
        copyFileSync(binPath, tmpBin);
        chmodSync(tmpBin, 0o755);
        launch(tmpBin, false);
        return;
      } catch (copyErr) {
        process.stderr.write(`Failed fallback launch: ${String(copyErr)}\n`);
      }
    } else {
      process.stderr.write(`Failed to launch ${binPath}: ${err.message}\n`);
    }
    process.exit(1);
  });

  child.once('exit', (code, signal) => {
    if (exiting || code !== null) {
      process.exit(code ?? 0);
    }
    if (signal) {
      process.exit(1);
    }
    process.exit(0);
  });
}

if (process.platform === 'win32') {
  const altWin = join(here, 'forge-win-local.exe');
  const winExe = existsSync(altWin)
    ? altWin
    : process.env.MAKEFUN_WIN_FORGE_EXE || join(here, 'target', 'release', 'forge.exe');
  launch(winExe, false);
} else {
  launch(join(here, 'forge-linux-amd64'), true);
}
