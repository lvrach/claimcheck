import http from 'node:http';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { CLAIMCHECK_AUDIENCE, CLAIMCHECK_BASE_URL, CLAIMCHECK_ISSUER, LOCAL_SERVER_PORT, discoverIssuer } from './config.js';

const jwks = createRemoteJWKSet(new URL(`${CLAIMCHECK_BASE_URL}/.well-known/jwks.json`));
const issuerPromise = CLAIMCHECK_ISSUER ? Promise.resolve(CLAIMCHECK_ISSUER) : discoverIssuer();

function sendJSON(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(payload);
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    sendJSON(res, 200, { ok: true });
    return;
  }

  if (req.method === 'POST' && req.url === '/verify') {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
    });

    req.on('end', async () => {
      try {
        const parsed = JSON.parse(raw) as { token?: string };
        const token = parsed.token;
        if (!token) {
          sendJSON(res, 400, { error: 'token is required' });
          return;
        }

        const issuer = await issuerPromise;
        const result = await jwtVerify(token, jwks, {
          issuer,
          audience: CLAIMCHECK_AUDIENCE
        });

        sendJSON(res, 200, {
          verified: true,
          header: result.protectedHeader,
          payload: result.payload
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        sendJSON(res, 401, { verified: false, error: message });
      }
    });
    return;
  }

  sendJSON(res, 404, { error: 'not found' });
});

server.listen(LOCAL_SERVER_PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Verifier server listening on http://127.0.0.1:${LOCAL_SERVER_PORT}`);
});
