import { CLAIMCHECK_AUDIENCE, CLAIMCHECK_BASE_URL, CLAIMCHECK_PROVIDER, LOCAL_SERVER_PORT } from './config.js';

type MintResponse = {
  token: string;
  expirationTimestamp: string;
};

async function main(): Promise<void> {
  const skillsURL = `${CLAIMCHECK_BASE_URL}/skills.md`;
  const skillsText = await fetch(skillsURL).then((r) => r.text());

  console.log(`Fetched ${skillsURL}`);
  console.log('--- skills.md preview ---');
  console.log(skillsText.split('\n').slice(0, 14).join('\n'));
  console.log('-------------------------');

  const mintURL = `${CLAIMCHECK_BASE_URL}/api/v1/providers/${CLAIMCHECK_PROVIDER}/mint`;
  const mintResponse = await fetch(mintURL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      namespace: 'default',
      serviceAccount: 'ts-demo',
      audiences: [CLAIMCHECK_AUDIENCE],
      expirationSeconds: 900,
      extraClaims: { 'extra.client': 'typescript-demo' }
    })
  });

  if (!mintResponse.ok) {
    throw new Error(`Mint failed (${mintResponse.status}): ${await mintResponse.text()}`);
  }

  const minted = (await mintResponse.json()) as MintResponse;
  console.log('Minted token, expires at:', minted.expirationTimestamp);

  const verifyURL = `http://127.0.0.1:${LOCAL_SERVER_PORT}/verify`;
  const verifyResponse = await fetch(verifyURL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: minted.token })
  });

  const verifyBody = await verifyResponse.json();
  console.log('Verifier response status:', verifyResponse.status);
  console.log(JSON.stringify(verifyBody, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
