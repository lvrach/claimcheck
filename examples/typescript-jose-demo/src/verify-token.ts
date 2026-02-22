import { readFileSync } from 'node:fs';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { CLAIMCHECK_AUDIENCE, CLAIMCHECK_BASE_URL, CLAIMCHECK_ISSUER, discoverIssuer } from './config.js';

async function main(): Promise<void> {
  const tokenFile = process.argv[2];
  if (!tokenFile) {
    console.error('Usage: npm run verify -- <token-file>');
    process.exit(1);
  }

  const token = readFileSync(tokenFile, 'utf8').trim();
  const jwks = createRemoteJWKSet(new URL(`${CLAIMCHECK_BASE_URL}/.well-known/jwks.json`));
  const issuer = CLAIMCHECK_ISSUER ?? (await discoverIssuer());

  const result = await jwtVerify(token, jwks, {
    issuer,
    audience: CLAIMCHECK_AUDIENCE
  });

  console.log(JSON.stringify({
    verified: true,
    header: result.protectedHeader,
    payload: result.payload
  }, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
