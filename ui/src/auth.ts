import { UserManager, WebStorageStateStore, type User } from "oidc-client-ts";

export interface OIDCMetadata {
  issuer: string;
  audience: string;
  client_id: string;
  mode: string;
}

let manager: UserManager | undefined;

export async function getAuthManager(): Promise<UserManager> {
  if (manager) return manager;
  const response = await fetch("/v1/auth/oidc", { headers: { Accept: "application/json" } });
  if (!response.ok) {
    throw new Error(response.status === 404
      ? "OIDC is not configured on this gateway. Configure an issuer and a public client ID to sign in."
      : `Could not load gateway sign-in settings (${response.status}).`);
  }
  const metadata = await response.json() as OIDCMetadata;
  if (!metadata.issuer || !metadata.client_id) {
    throw new Error("Gateway sign-in is incomplete. Set the OIDC issuer and browser client ID, then register this UI's callback URL with the identity provider.");
  }
  manager = new UserManager({
    authority: metadata.issuer,
    client_id: metadata.client_id,
    redirect_uri: `${window.location.origin}/auth/callback`,
    post_logout_redirect_uri: window.location.origin,
    response_type: "code",
    scope: "openid profile",
    automaticSilentRenew: false,
    userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  });
  return manager;
}

export async function completeSignIn(): Promise<User> {
  const oidc = await getAuthManager();
  const user = await oidc.signinRedirectCallback();
  window.history.replaceState({}, document.title, "/");
  return user;
}

export async function currentUser(): Promise<User | null> {
  return (await getAuthManager()).getUser();
}

export async function signIn(): Promise<void> {
  await (await getAuthManager()).signinRedirect();
}

export async function signOut(): Promise<void> {
  const oidc = await getAuthManager();
  await oidc.removeUser();
}
