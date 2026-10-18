export const MIN_NODE_MAJOR = 22;
export const MIN_NODE_MINOR = 18;

export function nodeMeetsRequirement(version = process.versions.node): boolean {
  const parts = version.split('.').map(value => Number(value));
  const major = parts[0] ?? 0;
  const minor = parts[1] ?? 0;
  return major > MIN_NODE_MAJOR || (major === MIN_NODE_MAJOR && minor >= MIN_NODE_MINOR);
}

export function isSqliteExperimentalWarning(warning: { name?: string; message?: string }): boolean {
  return warning.name === 'ExperimentalWarning' && /SQLite/i.test(String(warning.message ?? ''));
}

let installed = false;

export function installRuntimeGuards(): void {
  if (installed) return;
  installed = true;
  if (!nodeMeetsRequirement()) {
    process.stderr.write(
      `Stackey requires Node.js ${MIN_NODE_MAJOR}.${MIN_NODE_MINOR} or later. This process is ${process.versions.node}.\n`,
    );
    process.exit(1);
  }
  const existing = process.listeners('warning').slice() as Array<(warning: Error) => void>;
  process.removeAllListeners('warning');
  process.on('warning', warning => {
    if (isSqliteExperimentalWarning(warning)) return;
    if (existing.length === 0) {
      process.stderr.write(`${warning.stack ?? warning.message}\n`);
      return;
    }
    for (const listener of existing) listener(warning);
  });
}

installRuntimeGuards();
