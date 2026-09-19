/**
 * Entry point.
 *
 * Runs the .ts sources directly under Node's native type stripping, so there is no build step and
 * no dist directory. See tsconfig.json: erasableSyntaxOnly keeps the source inside the subset that
 * stripping can handle, and CI runs tsc --noEmit to prove it.
 */

import { loadConfig } from './config.ts';
import { log } from './log.ts';
import { createRelay } from './server.ts';

const config = loadConfig();
const relay = createRelay(config);

relay.httpServer.listen(config.port, config.host, () => {
  log.info('listening', { port: relay.port() });
});

// Loopback only, whatever the main host is: the numbers are for the operator, not the internet.
relay.metricsServer?.listen(config.metricsPort, '127.0.0.1');

let shuttingDown = false;

async function shutdown(): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  await relay.close();
  process.exit(0);
}

process.on('SIGTERM', () => {
  void shutdown();
});
process.on('SIGINT', () => {
  void shutdown();
});
