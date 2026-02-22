export const CLAIMCHECK_BASE_URL = process.env.CLAIMCHECK_BASE_URL ?? 'https://claimcheck.fly.dev';
export const CLAIMCHECK_PROVIDER = process.env.CLAIMCHECK_PROVIDER ?? 'k8s-sa';
export const CLAIMCHECK_ISSUER = process.env.CLAIMCHECK_ISSUER;
export const CLAIMCHECK_AUDIENCE = process.env.CLAIMCHECK_AUDIENCE ?? 'kubernetes.default.svc';

export const LOCAL_SERVER_PORT = Number(process.env.LOCAL_SERVER_PORT ?? 4040);

export async function discoverIssuer(): Promise<string> {
  const discoveryURL = `${CLAIMCHECK_BASE_URL}/.well-known/openid-configuration`;
  const response = await fetch(discoveryURL);
  if (!response.ok) {
    throw new Error(`OIDC discovery failed (${response.status}) at ${discoveryURL}`);
  }
  const body = (await response.json()) as { issuer?: string };
  if (!body.issuer) {
    throw new Error(`OIDC discovery missing issuer at ${discoveryURL}`);
  }
  return body.issuer;
}
