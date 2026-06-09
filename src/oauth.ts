// Feature 3: OAuth — Kiro Authentication
//
// Supports multiple auth methods:
//   - "idc": AWS Builder ID or IAM Identity Center (SSO) via device code flow
//   - "desktop": Google/GitHub social login via Kiro auth service (delegates to kiro-cli)
//
// When no existing credentials are found (no Kiro IDE, no kiro-cli), falls back
// to the interactive login flow in login.ts (Feature 10).

import type { OAuthCredentials, OAuthLoginCallbacks } from "@earendil-works/pi-ai";
import { getKiroIdeCredentials, getKiroIdeCredentialsAllowExpired } from "./kiro-ide.js";
import { interactiveLogin, loginViaKiroCli } from "./login.js";

export const SSO_OIDC_ENDPOINT = "https://oidc.us-east-1.amazonaws.com";
export const BUILDER_ID_START_URL = "https://view.awsapps.com/start";
export const KIRO_DESKTOP_REFRESH_URL = "https://prod.{region}.auth.desktop.kiro.dev/refreshToken";
export const SSO_SCOPES = [
  "codewhisperer:completions",
  "codewhisperer:analysis",
  "codewhisperer:conversations",
  "codewhisperer:transformations",
  "codewhisperer:taskassist",
];

export type KiroAuthMethod = "idc" | "desktop";
export type KiroLoginMethod = "auto" | "builder-id" | "google" | "github";

export interface KiroCredentials extends OAuthCredentials {
  clientId: string;
  clientSecret: string;
  region: string;
  authMethod: KiroAuthMethod;
  /** Required for Google/GitHub social profiles; ListAvailableProfiles may return empty for these tokens. */
  profileArn?: string;
  /** Kiro service region (us-east-1 or eu-central-1). Independent of the IDC/SSO region used for auth. */
  kiroRegion?: string;
}

/**
 * Login to Kiro using the specified method.
 *
 * - "auto": Use existing kiro-cli credentials if available (any method)
 * - "builder-id": AWS Builder ID via device code flow
 * - "google" | "github": Social login via kiro-cli (requires kiro-cli installed)
 */
export async function loginKiro(
  callbacks: OAuthLoginCallbacks,
  preferredMethod: KiroLoginMethod = "auto",
): Promise<OAuthCredentials> {
  const creds = await loginKiroInternal(callbacks, preferredMethod);
  if (!process.env.VITEST) {
    const kc = creds as KiroCredentials;
    // Discover kiroRegion if not already set
    if (!kc.kiroRegion && !kc.profileArn && kc.access) {
      const discovered = await discoverKiroRegion(kc.access);
      if (discovered) {
        kc.kiroRegion = discovered.region;
        kc.profileArn = discovered.profileArn;
        console.error(`[pi-provider-kiro] Discovered kiroRegion: ${discovered.region}`);
      } else {
        console.error(`[pi-provider-kiro] Failed to discover kiroRegion via ListAvailableProfiles`);
      }
    }
    // Persist kiroRegion to cache file for modifyModels (pi may not pass custom fields)
    if (kc.kiroRegion) {
      const { writeCachedKiroRegion } = await import("./models.js");
      writeCachedKiroRegion(kc.kiroRegion);
      console.error(`[pi-provider-kiro] Wrote kiroRegion cache: ${kc.kiroRegion}`);
    }
    try {
      const { resolveApiRegion, updateKiroModelsCache } = await import("./models.js");
      const region = resolveApiRegion(kc.region, kc.kiroRegion);
      updateKiroModelsCache(creds.access, region, kc.profileArn).catch(() => {});
    } catch {
      // Ignore cache errors
    }
  }
  return creds;
}

async function loginKiroInternal(
  callbacks: OAuthLoginCallbacks,
  preferredMethod: KiroLoginMethod = "auto",
): Promise<OAuthCredentials> {
  const { getKiroCliCredentials, getKiroCliCredentialsAllowExpired, saveKiroCliCredentials, getKiroCliSocialToken } =
    await import("./kiro-cli.js");

  // If user explicitly wants social login, delegate to kiro-cli
  if (preferredMethod === "google" || preferredMethod === "github") {
    return loginViaKiroCli(callbacks, preferredMethod);
  }

  // 1. Kiro IDE token (~/.aws/sso/cache/kiro-auth-token.json)
  //    Checked first because the IDE keeps it continuously fresh and it already
  //    covers IAM Identity Center logins — no extra prompts needed.
  const ideCreds = getKiroIdeCredentials();
  if (ideCreds && (preferredMethod === "auto" || preferredMethod === "builder-id")) {
    (callbacks as unknown as { onProgress?: (msg: string) => void }).onProgress?.(
      "Using existing Kiro IDE credentials",
    );
    return ideCreds;
  }

  // 2. kiro-cli DB credentials (social / Builder ID / IdC)
  let cliCreds = getKiroCliSocialToken();
  if (!cliCreds) {
    cliCreds = getKiroCliCredentials();
  }

  if (cliCreds && (preferredMethod === "auto" || cliCreds.authMethod === "idc")) {
    (callbacks as unknown as { onProgress?: (msg: string) => void }).onProgress?.(
      cliCreds.authMethod === "desktop"
        ? "Using existing kiro-cli social credentials"
        : "Using existing kiro-cli credentials",
    );
    return cliCreds;
  }

  // 3. Expired IDE token — attempt a silent AWS OIDC refresh
  const expiredIdeCreds = getKiroIdeCredentialsAllowExpired();
  if (expiredIdeCreds) {
    try {
      (callbacks as unknown as { onProgress?: (msg: string) => void }).onProgress?.(
        "Refreshing Kiro IDE credentials...",
      );
      return await refreshKiroTokenDirect(expiredIdeCreds);
    } catch {
      // Fall through to kiro-cli refresh
    }
  }

  // 4. Expired kiro-cli credentials — attempt a silent refresh
  const expiredCreds = getKiroCliCredentialsAllowExpired();
  if (expiredCreds) {
    try {
      (callbacks as unknown as { onProgress?: (msg: string) => void }).onProgress?.(
        "Refreshing expired kiro-cli credentials...",
      );
      const refreshed = await refreshKiroTokenDirect(expiredCreds);
      saveKiroCliCredentials(refreshed as KiroCredentials);
      return refreshed;
    } catch {
      // Refresh failed, fall through to device code flow
    }
  }

  // Fall back to interactive login (Feature 10)
  return interactiveLogin(callbacks);
}

/**
 * Backward-compatible alias for loginKiro with Builder ID.
 * @deprecated Use loginKiro instead.
 */
export async function loginKiroBuilderID(callbacks: OAuthLoginCallbacks): Promise<OAuthCredentials> {
  return loginKiro(callbacks, "builder-id");
}

// Token refresh buffer (5 minutes) baked into our expires timestamps at creation time.
// The actual AWS token is valid for this much longer than credentials.expires indicates.
const EXPIRES_BUFFER_MS = 5 * 60 * 1000;

export async function refreshKiroToken(credentials: OAuthCredentials): Promise<OAuthCredentials> {
  const refreshed = await refreshKiroTokenInternal(credentials);

  // Ensure kiroRegion is always available — IDE layer may return creds without it
  const rc = refreshed as KiroCredentials;
  if (!rc.kiroRegion && !rc.profileArn) {
    const inputKc = credentials as KiroCredentials;
    if (inputKc.kiroRegion || inputKc.profileArn) {
      rc.kiroRegion = inputKc.kiroRegion;
      rc.profileArn = rc.profileArn || inputKc.profileArn;
    } else {
      // Input also lacked it (pre-upgrade creds); try kiro-cli
      const { getKiroCliCredentials, getKiroCliCredentialsAllowExpired } = await import("./kiro-cli.js");
      const cli = getKiroCliCredentials() ?? getKiroCliCredentialsAllowExpired();
      if (cli?.kiroRegion) rc.kiroRegion = cli.kiroRegion;
      else if (cli?.profileArn) rc.profileArn = cli.profileArn;
    }
  }

  // Last resort: probe both API regions to discover where the profile lives
  if (!rc.kiroRegion && !rc.profileArn && rc.access) {
    const discovered = await discoverKiroRegion(rc.access);
    if (discovered) {
      rc.kiroRegion = discovered.region;
      rc.profileArn = discovered.profileArn;
    }
  }
  // Persist kiroRegion to cache file for modifyModels (pi may not pass custom fields)
  if (rc.kiroRegion) {
    const { writeCachedKiroRegion } = await import("./models.js");
    writeCachedKiroRegion(rc.kiroRegion);
  }
  if (!process.env.VITEST) {
    try {
      const { resolveApiRegion, updateKiroModelsCache } = await import("./models.js");
      const kc = refreshed as KiroCredentials;
      const region = resolveApiRegion(kc.region, kc.kiroRegion);
      updateKiroModelsCache(refreshed.access, region, kc.profileArn).catch(() => {});
    } catch {
      // Ignore cache errors
    }
  }
  return refreshed;
}

async function refreshKiroTokenInternal(credentials: OAuthCredentials): Promise<OAuthCredentials> {
  const { getKiroCliCredentials, getKiroCliCredentialsAllowExpired, saveKiroCliCredentials, getKiroCliSocialToken } =
    await import("./kiro-cli.js");

  // Layer 0: Kiro IDE token — freshest source, covers IAM Identity Center
  const ideCreds = getKiroIdeCredentials();
  if (ideCreds) return ideCreds;

  // Layer 1: Pre-refresh check — prefer social token if available (user logged in that way)
  // Otherwise check for any valid kiro-cli token
  let preCheckCreds = getKiroCliSocialToken();
  if (!preCheckCreds) {
    preCheckCreds = getKiroCliCredentials();
  }
  if (preCheckCreds) {
    return preCheckCreds;
  }

  try {
    const refreshed = await refreshKiroTokenDirect(credentials);

    // Layer 2: Write refreshed tokens back to kiro-cli's SQLite DB so both stay in sync.
    saveKiroCliCredentials(refreshed as KiroCredentials);

    return refreshed;
  } catch (refreshError) {
    // Layer 3: Refresh token may have been rotated by kiro-cli between our
    // Layer 1 check and the network call. Re-read kiro-cli's DB.
    const retryCreds = getKiroCliCredentials();
    if (retryCreds) {
      return retryCreds;
    }

    // Layer 4: kiro-cli may have a newer refresh token (expired access token).
    // Try refreshing with those credentials instead of the stale ones from auth.json.
    const expiredCliCreds = getKiroCliCredentialsAllowExpired();
    if (expiredCliCreds && expiredCliCreds.refresh !== credentials.refresh) {
      try {
        const refreshedFromCli = await refreshKiroTokenDirect(expiredCliCreds);
        saveKiroCliCredentials(refreshedFromCli as KiroCredentials);
        return refreshedFromCli;
      } catch {
        // Also failed, continue to remaining fallbacks
      }
    }

    // Layer 5: Graceful degradation — our expires has a 5-min buffer, so the
    // actual AWS token may still be valid. Return it to buy time.
    const actualExpiry = credentials.expires + EXPIRES_BUFFER_MS;
    if (credentials.access && Date.now() < actualExpiry) {
      return { ...credentials, expires: actualExpiry };
    }

    throw refreshError;
  }
}

async function refreshKiroTokenDirect(credentials: OAuthCredentials): Promise<OAuthCredentials> {
  const { regionFromProfileArn, resolveApiRegion } = await import("./models.js");
  const parts = credentials.refresh.split("|");
  const refreshToken = parts[0] ?? "";
  const authMethod = (parts[parts.length - 1] ?? "idc") as KiroAuthMethod;
  const kc = credentials as KiroCredentials;
  const region = kc.region || "us-east-1";
  const kiroRegion = kc.kiroRegion || regionFromProfileArn(kc.profileArn);

  if (authMethod === "desktop") {
    // Desktop refresh uses the Kiro service region, not the IDC region
    const desktopRegion = resolveApiRegion(region, kiroRegion);
    const url = KIRO_DESKTOP_REFRESH_URL.replace("{region}", desktopRegion);
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "pi-cli" },
      body: JSON.stringify({ refreshToken }),
    });
    if (!response.ok) throw new Error(`Desktop token refresh failed: ${response.status}`);
    const data = (await response.json()) as {
      accessToken: string;
      refreshToken?: string;
      expiresIn: number;
      profileArn?: string;
    };
    if (!data.accessToken) throw new Error("Desktop token refresh: missing accessToken");
    const newProfileArn = data.profileArn || kc.profileArn;
    return {
      refresh: `${data.refreshToken || refreshToken}|desktop`,
      access: data.accessToken,
      expires: Date.now() + data.expiresIn * 1000 - 5 * 60 * 1000,
      clientId: "",
      clientSecret: "",
      region,
      authMethod: "desktop" as KiroAuthMethod,
      profileArn: newProfileArn,
      kiroRegion: kiroRegion || regionFromProfileArn(newProfileArn),
    };
  }

  // IDC auth method — SSO OIDC refresh
  const clientId = parts[1] ?? "";
  const clientSecret = parts[2] ?? "";
  const ssoEndpoint = `https://oidc.${region}.amazonaws.com`;
  const response = await fetch(`${ssoEndpoint}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": "pi-cli" },
    body: JSON.stringify({ clientId, clientSecret, refreshToken, grantType: "refresh_token" }),
  });
  if (!response.ok) throw new Error(`Token refresh failed: ${response.status}`);
  const data = (await response.json()) as { accessToken: string; refreshToken: string; expiresIn: number };
  return {
    refresh: `${data.refreshToken}|${clientId}|${clientSecret}|idc`,
    access: data.accessToken,
    expires: Date.now() + data.expiresIn * 1000 - 5 * 60 * 1000,
    clientId: clientId,
    clientSecret: clientSecret,
    region,
    authMethod: "idc" as KiroAuthMethod,
    profileArn: kc.profileArn,
    kiroRegion,
  };
}

const KIRO_API_REGIONS = ["us-east-1", "eu-central-1"];

/** Probe both Kiro API regions to find which one has the user's profile. */
async function discoverKiroRegion(
  accessToken: string,
): Promise<{ region: string; profileArn: string } | undefined> {
  for (const region of KIRO_API_REGIONS) {
    try {
      const r = await fetch(`https://q.${region}.amazonaws.com/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-amz-json-1.0",
          Authorization: `Bearer ${accessToken}`,
          "X-Amz-Target": "AmazonCodeWhispererService.ListAvailableProfiles",
        },
        body: "{}",
      });
      if (!r.ok) continue;
      const j = (await r.json()) as { profiles?: Array<{ arn?: string }> };
      const arn = j.profiles?.find((p) => p.arn)?.arn;
      if (arn) return { region, profileArn: arn };
    } catch {
      continue;
    }
  }
  return undefined;
}
