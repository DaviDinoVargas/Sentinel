import { Injectable, inject, signal } from '@angular/core';
import { HttpClient, HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { Router } from '@angular/router';
import { catchError, firstValueFrom, throwError } from 'rxjs';
import type { User, UserManager } from 'oidc-client-ts';

export interface Organization {
  id: string;
  name: string;
  createdAtUtc: string;
}
export interface IdentityProfile {
  subject: string;
  name: string;
  roles: string[];
  organization: Organization;
  permissions: string[];
  limitations: string[];
}
export interface IdentityConfiguration {
  authority: string;
  clientId: string;
  audience: string;
  redirectUri: string;
  postLogoutRedirectUri: string;
  development: boolean;
}

@Injectable({ providedIn: 'root' })
export class AuthSessionService {
  private readonly http = inject(HttpClient);
  private readonly router = inject(Router);
  readonly ready = signal(false);
  readonly profile = signal<IdentityProfile | null>(null);
  readonly configuration = signal<IdentityConfiguration | null>(null);
  readonly error = signal('');
  readonly busy = signal(false);
  private manager: UserManager | null = null;
  private accessToken: string | null = null;
  private generation = 0;
  private managerVersion = 0;
  token(): string | null {
    return this.accessToken;
  }
  can(permission: string): boolean {
    return this.profile()?.permissions.includes(permission) ?? false;
  }

  async start(): Promise<void> {
    const managerVersion = ++this.managerVersion;
    this.ready.set(false);
    this.manager?.stopSilentRenew();
    if (this.manager) await this.manager.events.unload();
    try {
      const config = await firstValueFrom(
        this.http.get<IdentityConfiguration>('/api/v1/identity/configuration'),
      );
      this.configuration.set(config);
      const { UserManager, WebStorageStateStore, InMemoryWebStorage } =
        await import('oidc-client-ts');
      if (
        new URL(config.redirectUri).origin !== location.origin ||
        new URL(config.postLogoutRedirectUri).origin !== location.origin
      )
        throw new Error('Abra a aplicação no endereço configurado para login.');
      this.manager = new UserManager({
        authority: config.authority,
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        post_logout_redirect_uri: config.postLogoutRedirectUri,
        response_type: 'code',
        scope: 'openid profile',
        userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
        stateStore: new WebStorageStateStore({
          store: sessionStorage,
          prefix: 'sentinel.oidc.state.',
        }),
        automaticSilentRenew: true,
        loadUserInfo: false,
        revokeTokensOnSignout: true,
      });
      if (location.pathname === '/auth/callback') {
        const user = await this.manager.signinRedirectCallback();
        await this.accept(user, managerVersion);
        await this.router.navigateByUrl('/identity', { replaceUrl: true });
      } else if (
        location.pathname === '/identity' &&
        new URLSearchParams(location.search).has('state')
      ) {
        await this.manager.signoutRedirectCallback();
        await this.router.navigateByUrl('/identity', { replaceUrl: true });
      }
      this.manager.events.addUserLoaded((user) => {
        if (managerVersion === this.managerVersion) void this.accept(user, managerVersion);
      });
      this.manager.events.addAccessTokenExpired(() => {
        if (managerVersion === this.managerVersion)
          this.invalidate('Sessão expirada. Entre novamente.');
      });
      this.manager.events.addSilentRenewError(() => {
        if (managerVersion === this.managerVersion)
          this.invalidate('Não foi possível renovar a sessão. Entre novamente.');
      });
      this.manager.events.addUserUnloaded(() => {
        if (managerVersion === this.managerVersion) this.invalidate();
      });
      await this.manager.clearStaleState();
    } catch {
      this.error.set(
        'Não foi possível preparar ou validar o login. Verifique o provedor e abra http://localhost:4200 no ambiente local.',
      );
      // Remove authorization codes and protocol errors from the visible URL even on failure.
      if (location.pathname === '/auth/callback')
        await this.router.navigateByUrl('/identity', { replaceUrl: true });
    } finally {
      this.ready.set(true);
    }
  }
  private async accept(user: User, managerVersion = this.managerVersion): Promise<void> {
    if (managerVersion !== this.managerVersion) return;
    const generation = ++this.generation;
    this.accessToken = user.access_token;
    try {
      const profile = await firstValueFrom(this.http.get<IdentityProfile>('/api/v1/identity'));
      if (generation !== this.generation || managerVersion !== this.managerVersion) return;
      this.profile.set(profile);
      this.error.set('');
      this.manager?.startSilentRenew();
    } catch {
      if (generation !== this.generation || managerVersion !== this.managerVersion) return;
      this.invalidate(
        'A identidade não possui organização e papel autorizados, ou a API recusou a sessão.',
      );
    }
  }
  async login(): Promise<void> {
    if (!this.manager || this.busy()) return;
    this.busy.set(true);
    this.error.set('');
    try {
      await this.manager.signinRedirect();
    } catch {
      this.busy.set(false);
      this.error.set('Não foi possível iniciar o login no provedor.');
    }
  }
  async logout(): Promise<void> {
    if (!this.manager || this.busy()) return;
    this.managerVersion++;
    this.busy.set(true);
    try {
      await this.manager.signoutRedirect();
    } catch {
      this.error.set('Sessão local encerrada; não foi possível confirmar a saída no provedor.');
    } finally {
      this.invalidate();
      this.busy.set(false);
    }
  }
  invalidate(message = ''): void {
    this.generation++;
    this.manager?.stopSilentRenew();
    this.accessToken = null;
    this.profile.set(null);
    if (message) this.error.set(message);
  }
}

export const authInterceptor: HttpInterceptorFn = (request, next) => {
  const auth = inject(AuthSessionService);
  // Never attach credentials to targets, arbitrary URLs or the OIDC provider.
  const isApi =
    request.url.startsWith('/api/v1/') || request.url.startsWith(location.origin + '/api/v1/');
  const token = isApi ? auth.token() : null;
  return next(
    token ? request.clone({ setHeaders: { Authorization: `Bearer ${token}` } }) : request,
  ).pipe(
    catchError((error: HttpErrorResponse) => {
      if (isApi && error.status === 401 && token)
        auth.invalidate('Sessão recusada ou expirada. Entre novamente.');
      return throwError(() => error);
    }),
  );
};
