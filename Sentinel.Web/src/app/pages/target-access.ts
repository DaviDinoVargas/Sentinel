import { Component, computed, DestroyRef, effect, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Subject, takeUntil } from 'rxjs';
import { WorkspaceService } from '../core/workspace.service';
import { AuthSessionService } from '../core/auth-session.service';
import { TargetCredential } from '../core/sentinel-api.service';
import { OptionalPluginPicker } from '../design-system/optional-plugin-picker';
import { Badge, EmptyState } from '../design-system/ui';
import {
  TargetLoginFields,
  loginForm,
  loginInput,
  resetLogin,
  clearLoginSecrets,
} from './target-login-fields';

@Component({
  imports: [
    CommonModule,
    ReactiveFormsModule,
    RouterLink,
    Badge,
    EmptyState,
    TargetLoginFields,
    OptionalPluginPicker,
  ],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">WORKSPACE / ACESSOS DO ALVO</p>
        <h1>Acessos do alvo</h1>
        <p>Perfis sintéticos e cenários autenticados com expectativas explícitas.</p>
      </div>
      <button class="button" (click)="refresh.update(increment)">Atualizar perfis</button>
    </div>
    @if (!ws.projectId()) {
      <section class="panel">
        <s-empty
          title="Selecione um projeto"
          description="Credenciais e cenários pertencem ao projeto ativo."
        />
      </section>
    } @else {
      <div class="banner">
        <span
          >Use tokens ou usuário/senha da aplicação testada e contas sintéticas. O login OIDC do
          Sentinel é separado. O segredo é cifrado no backend, nunca retornado pela consulta e usado
          somente pelo gateway.</span
        >
      </div>
      @if (error()) {
        <p class="banner warning" role="alert">{{ error() }}</p>
      }
      @if (notice()) {
        <p class="help" role="status">{{ notice() }}</p>
      }
      <section class="panel panel-pad section-gap" aria-labelledby="credentials-title">
        <div class="panel-header">
          <div>
            <h2 id="credentials-title">Perfis de credenciais</h2>
            <p>Até 100 perfis · Bearer ou login JSON · laboratório em loopback</p>
          </div>
        </div>
        @if (loading()) {
          <p role="status">Consultando perfis…</p>
        }
        @if (profiles().length) {
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Perfil / identidade</th>
                  <th>Validade</th>
                  <th>Estado</th>
                  <th>Ações</th>
                </tr>
              </thead>
              <tbody>
                @for (profile of profiles(); track profile.id) {
                  <tr>
                    <td>
                      <strong>{{ profile.name }}</strong
                      ><span class="subline"
                        >{{ profile.persona }} · {{ profile.tenantLabel }} · v{{
                          profile.version
                        }}</span
                      >
                      <span class="subline mono">Escopo {{ profile.scopeId.slice(0, 8) }}</span>
                      <span class="subline">{{
                        profile.credentialType === 'JsonLogin'
                          ? 'Usuário/senha · POST JSON'
                          : 'Bearer'
                      }}</span>
                      @if (profile.credentialType === 'JsonLogin') {
                        <span class="subline"
                          >Último login: {{ loginStatus(profile.lastLoginStatus) }} ·
                          {{
                            (profile.lastLoginAtUtc | date: 'dd/MM HH:mm:ss') || 'Não testado'
                          }}</span
                        >
                      }
                      <span class="subline"
                        >Referência protegida:
                        {{
                          (profile.baselineVerifiedAtUtc | date: 'HH:mm:ss') ||
                            'Validar acesso próprio'
                        }}</span
                      >
                    </td>
                    <td>{{ profile.expiresAtUtc | date: 'dd/MM HH:mm' }}</td>
                    <td>
                      <s-badge
                        [value]="available(profile) ? 'healthy' : 'unavailable'"
                        [text]="availabilityLabel(profile)"
                      />
                    </td>
                    <td>
                      <button
                        class="button small"
                        [disabled]="!auth.can('scopes.manage') || !!profile.revokedAtUtc || busy()"
                        (click)="selectRotation(profile)"
                      >
                        Rotacionar
                      </button>
                      <button
                        class="button small"
                        [disabled]="!auth.can('scopes.manage') || !!profile.revokedAtUtc || busy()"
                        (click)="revoke(profile)"
                      >
                        Revogar
                      </button>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        } @else if (!loading()) {
          <p class="help">Nenhum perfil cadastrado neste projeto.</p>
        }
        @if (auth.can('scopes.manage')) {
          <details class="section-gap">
            <summary>Cadastrar perfil de acesso</summary>
            <form class="form-stack section-gap" [formGroup]="credentialForm" (ngSubmit)="create()">
              <label
                >Tipo de acesso<select [value]="credentialType()" (change)="changeType($event)">
                  <option value="Bearer">Token Bearer</option>
                  <option value="JsonLogin">Usuário/senha e empresa</option>
                </select></label
              >
              <div class="form-grid">
                <label
                  >Nome do perfil<input
                    formControlName="name"
                    maxlength="100"
                    placeholder="Empresa A — leitura"
                /></label>
                <label
                  >Escopo autorizado<select formControlName="scopeId">
                    <option value="">Selecione o laboratório</option>
                    @for (scope of ws.activeScopes(); track scope.id) {
                      @if (scope.environment === 'laboratorio') {
                        <option [value]="scope.id">{{ scope.targetBaseUri }}</option>
                      }
                    }
                  </select></label
                ><label
                  >Papel / persona<input
                    formControlName="persona"
                    maxlength="100"
                    placeholder="Empresa ou operador sintético"
                /></label>
                <label
                  >Empresa de teste<input
                    formControlName="tenantLabel"
                    maxlength="100"
                    placeholder="Empresa A"
                /></label>
                @if (credentialType() === 'Bearer') {
                  <label
                    >Token Bearer do alvo<input
                      type="password"
                      autocomplete="off"
                      formControlName="token"
                      maxlength="16000"
                  /></label>
                }
                <label
                  >Expira em (horário local)<input type="datetime-local" formControlName="expires"
                /></label>
              </div>
              @if (credentialType() === 'JsonLogin') {
                <s-target-login-fields [form]="login" />
              }
              <p class="help">
                Informe a validade real do token: máximo 24 horas, dentro do escopo. O Sentinel não
                renova sessões do alvo automaticamente. O campo secreto é limpo após o envio.
              </p>
              <button
                class="button primary"
                [disabled]="
                  busy() ||
                  credentialForm.invalid ||
                  (credentialType() === 'JsonLogin' && login.invalid)
                "
              >
                Cadastrar perfil
              </button>
            </form>
          </details>
          @if (rotating(); as profile) {
            <form class="form-stack section-gap" [formGroup]="rotationForm" (ngSubmit)="rotate()">
              <h3>Rotacionar {{ profile.name }}</h3>
              @if (profile.credentialType === 'JsonLogin') {
                <s-target-login-fields [form]="rotationLogin" />
              } @else {
                <label
                  >Novo token Bearer<input
                    type="password"
                    autocomplete="off"
                    formControlName="token"
                    maxlength="16000"
                /></label>
              }
              <label
                >Nova expiração (horário local)<input
                  type="datetime-local"
                  formControlName="expires"
              /></label>
              <p class="help">
                Rotacionar invalida o uso da versão anterior em auditorias ainda em andamento.
              </p>
              <div class="actions">
                <button class="button" type="button" (click)="closeRotation()">
                  Fechar rotação</button
                ><button
                  class="button primary"
                  [disabled]="
                    busy() ||
                    rotationForm.invalid ||
                    (profile.credentialType === 'JsonLogin' && rotationLogin.invalid)
                  "
                >
                  Salvar nova versão
                </button>
              </div>
            </form>
          }
        } @else {
          <p class="help">
            Seu papel permite consultar os perfis. Cadastrar, rotacionar e revogar exige permissão
            de escopo.
          </p>
        }
      </section>
      <section class="panel panel-pad section-gap" aria-labelledby="scenario-title">
        <h2 id="scenario-title">Testar autenticação e acesso</h2>
        <p class="help">
          Teste uma URL com uma identidade: acesso próprio esperado ou negação esperada para outro
          papel/empresa. Cada execução preserva perfil e versão nas evidências de acompanhamento.
          Primeiro valide acesso permitido em recurso protegido. A referência vale por cinco minutos
          e é testada novamente, com e sem credencial, antes de cada cenário de negação.
        </p>
        <form class="form-stack" [formGroup]="scenarioForm" (ngSubmit)="execute()">
          <div class="form-grid">
            <label
              >Perfil de identidade<select formControlName="profileId">
                <option value="">Selecione um perfil disponível</option>
                @for (profile of activeProfiles(); track profile.id) {
                  <option [value]="profile.id">
                    {{ profile.name }} · {{ profile.persona }} · {{ profile.tenantLabel }}
                  </option>
                }
              </select></label
            ><label
              >Expectativa<select
                formControlName="expectedAccess"
                (change)="scenarioForm.controls.includeLoad.setValue(false)"
              >
                <option value="allow">Acesso permitido (2xx)</option>
                <option value="deny">Acesso negado (403 ou 404)</option>
              </select></label
            >
          </div>
          <label
            >Segunda identidade opcional (Bearer)
            <select
              formControlName="secondaryProfileId"
              (change)="scenarioForm.controls.includeLoad.setValue(false); optionalPlugins.set([])"
            >
              <option value="">Sem segunda identidade</option>
              @for (secondary of secondaryProfiles(); track secondary.id) {
                <option [value]="secondary.id">
                  {{ secondary.name }} · {{ secondary.persona }} · {{ secondary.tenantLabel }}
                </option>
              }
            </select>
          </label>
          <p class="help">
            Duas identidades exigem o mesmo escopo, acesso permitido e ausência de carga. A segunda
            identidade aceita Bearer; login JSON secundário será ampliado.
          </p>
          <label
            >URL exata do recurso<input
              type="url"
              formControlName="targetUrl"
              maxlength="2048"
              placeholder="https://localhost:8080/api/recursos/id-sintetico"
          /></label>
          <label class="check-field"
            ><input
              type="checkbox"
              formControlName="includeLoad"
              [attr.aria-disabled]="scenarioForm.controls.expectedAccess.value !== 'allow'"
            /><span
              >Incluir carga autenticada: até 40 GETs adicionais, concorrência 2, teto global 10/s.
              Somente para acesso permitido.</span
            ></label
          >
          <s-optional-plugin-picker
            action="authenticated-lab"
            [selected]="optionalPlugins()"
            [secondary]="!!scenarioForm.controls.secondaryProfileId.value"
            [disabled]="busy()"
            (selectionChange)="optionalPlugins.set($event)"
          />
          <label class="check-field"
            ><input type="checkbox" formControlName="confirmed" /><span
              >Confirmo as identidades sintéticas e as operações dos plugins selecionados no
              laboratório autorizado. Perfis de usuário/senha enviam POST de login por plugin,
              dentro do orçamento global de taxa. Operações opcionais continuam sujeitas ao escopo e
              ao manifesto aprovado.</span
            ></label
          >
          <button
            class="button primary"
            [disabled]="busy() || scenarioForm.invalid || !auth.can('audits.execute-active')"
          >
            Executar cenário
          </button>
          @if (!auth.can('audits.execute-active')) {
            <p class="help">
              Cenários autenticados exigem permissão para testes ativos de laboratório.
            </p>
          }
        </form>
      </section>
      <section class="panel panel-pad section-gap">
        <h2>Proteções e limitações</h2>
        <p class="help">
          Até três GETs de referência/verificação, dentro do escopo do perfil. Resposta 401 não
          comprova isolamento; resulta inconclusiva. Sem enumeração nem escrita de dados de negócio;
          o POST de login pode criar uma sessão no alvo. Corpo e cabeçalhos da resposta autenticada
          não são entregues ao plugin. O resultado por status não comprova o conteúdo nem toda a
          autorização da aplicação.
        </p>
        <p class="help">
          Token expirado, revogado ou rotacionado é recusado antes das novas permissões. Uma
          requisição já autorizada pode concluir. A carga só inicia após confirmar o acesso;
          interrompe em 429, 5xx, redirect, timeout ou latência acima de 1500 ms.
        </p>
        <p class="help">
          Chaves locais protegidas por DPAPI no Windows; outros hosts exigem certificado
          configurado. Workers distribuídos precisam compartilhar o keyring e a proteção de chaves.
          Login JSON é preparado pelo gateway antes do plugin, em até dez segundos. Refresh,
          cookies, MFA e outros mecanismos ainda não têm adaptador.
        </p>
        <a class="text-link" routerLink="/audits">Histórico e evidências das execuções</a> ·
        <a class="text-link" routerLink="/performance">Métricas no Performance Lab</a>
      </section>
    }
  `,
})
export class TargetAccessPage {
  readonly credentialType = signal('Bearer');
  readonly login = loginForm();
  readonly rotationLogin = loginForm();
  changeType(event: Event): void {
    this.credentialType.set((event.target as HTMLSelectElement).value);
    const token = this.credentialForm.controls.token;
    token.setValidators(this.credentialType() === 'Bearer' ? [Validators.required] : []);
    token.reset();
    token.updateValueAndValidity();
    resetLogin(this.login);
  }
  loginStatus(status?: string | null): string {
    const labels: Record<string, string> = {
      Authenticated: 'Token obtido; acesso avaliado no cenário',
      InvalidCredentials: 'Credenciais recusadas (401)',
      TenantOrAccessDenied: 'Empresa ou acesso recusado (403)',
      AccountLocked: 'Conta bloqueada (423)',
      RateLimited: 'Limite do alvo (429)',
      RedirectUnsupported: 'Redirecionamento não suportado',
      Unavailable: 'Indisponível',
      UnsupportedResponse: 'Resposta não suportada',
      TokenMissingOrUnsupported: 'Token ausente ou incompatível',
      UnavailableOrRevoked: 'Indisponível, cancelado ou revogado',
      ResponseTooLarge: 'Resposta excede limite',
      OutsideScope: 'Fora do escopo',
      CancelledOrBudgetDenied: 'Cancelamento ou limite',
    };
    return status ? (labels[status] ?? 'Não concluído') : 'Não testado';
  }
  private readonly contextChanged = new Subject<void>();
  readonly ws = inject(WorkspaceService);
  readonly auth = inject(AuthSessionService);
  private readonly router = inject(Router);
  private readonly destroy = inject(DestroyRef);
  private readonly fb = inject(FormBuilder).nonNullable;
  readonly profiles = signal<TargetCredential[]>([]);
  readonly rotating = signal<TargetCredential | null>(null);
  readonly refresh = signal(0);
  readonly increment = (value: number) => value + 1;
  readonly loading = signal(false);
  readonly busy = signal(false);
  readonly error = signal('');
  readonly notice = signal('');
  readonly activeProfiles = computed(() =>
    this.profiles().filter((profile) => this.available(profile)),
  );
  readonly credentialForm = this.fb.group({
    name: ['', Validators.required],
    scopeId: ['', Validators.required],
    persona: ['', Validators.required],
    tenantLabel: ['', Validators.required],
    token: ['', Validators.required],
    expires: [this.defaultExpiry(), Validators.required],
  });
  readonly rotationForm = this.fb.group({
    token: ['', Validators.required],
    expires: [this.defaultExpiry(), Validators.required],
  });
  readonly scenarioForm = this.fb.group({
    profileId: ['', Validators.required],
    secondaryProfileId: [''],
    expectedAccess: ['allow'],
    targetUrl: ['', [Validators.required, Validators.pattern(/^https?:\/\/[^\s]+$/i)]],
    includeLoad: [false],
    confirmed: [false, Validators.requiredTrue],
  });
  readonly optionalPlugins = signal<string[]>([]);
  constructor() {
    this.scenarioForm.controls.expectedAccess.valueChanges
      .pipe(takeUntilDestroyed(this.destroy))
      .subscribe((value) => {
        const load = this.scenarioForm.controls.includeLoad;
        load.setValue(false, { emitEvent: false });
        this.scenarioForm.controls.secondaryProfileId.setValue('', { emitEvent: false });
        this.optionalPlugins.set([]);
        if (value === 'allow') load.enable({ emitEvent: false });
        else load.disable({ emitEvent: false });
      });
    this.scenarioForm.controls.profileId.valueChanges
      .pipe(takeUntilDestroyed(this.destroy))
      .subscribe(() => {
        this.scenarioForm.controls.secondaryProfileId.setValue('', { emitEvent: false });
        this.scenarioForm.controls.confirmed.setValue(false, { emitEvent: false });
        this.optionalPlugins.set([]);
      });
    this.scenarioForm.controls.secondaryProfileId.valueChanges
      .pipe(takeUntilDestroyed(this.destroy))
      .subscribe(() => {
        this.scenarioForm.controls.includeLoad.setValue(false, { emitEvent: false });
        this.scenarioForm.controls.confirmed.setValue(false, { emitEvent: false });
        this.optionalPlugins.set([]);
      });
    let previous = '';
    effect((cleanup) => {
      const id = this.ws.projectId();
      this.refresh();
      const user = this.auth.profile();
      const identity = user
        ? user.subject + ':' + user.organization.id + ':' + user.permissions.join(',')
        : '';
      this.profiles.set([]);
      this.loading.set(!!id && !!identity);
      if (previous !== id + identity) {
        this.contextChanged.next();
        this.busy.set(false);
        this.credentialForm.reset({ expires: this.defaultExpiry() });
        this.credentialType.set('Bearer');
        this.credentialForm.controls.token.setValidators([Validators.required]);
        this.credentialForm.controls.token.updateValueAndValidity();
        resetLogin(this.login);
        resetLogin(this.rotationLogin);
        this.rotationForm.reset({ expires: this.defaultExpiry() });
        this.scenarioForm.reset();
        this.optionalPlugins.set([]);
        this.rotating.set(null);
        this.error.set('');
        this.notice.set('');
        previous = id + identity;
      }
      if (!id || !identity) return;
      const subscription = this.ws.api.targetCredentials(id).subscribe({
        next: (profiles) => {
          this.profiles.set(profiles);
          this.loading.set(false);
        },
        error: () => {
          this.error.set('Não foi possível consultar perfis deste projeto.');
          this.loading.set(false);
        },
      });
      cleanup(() => subscription.unsubscribe());
    });
    this.destroy.onDestroy(() => {
      this.contextChanged.complete();
      this.credentialForm.controls.token.reset();
      this.rotationForm.controls.token.reset();
      clearLoginSecrets(this.login);
      clearLoginSecrets(this.rotationLogin);
    });
  }
  available(profile: TargetCredential): boolean {
    return this.availabilityLabel(profile) === 'Disponível';
  }
  availabilityLabel(profile: TargetCredential): string {
    if (profile.revokedAtUtc) return 'Credencial revogada';
    if (new Date(profile.expiresAtUtc).getTime() <= this.ws.now()) return 'Credencial expirada';
    const scope = this.ws.scopes().find((s) => s.id === profile.scopeId);
    if (!scope) return 'Escopo não consultado';
    if (scope.revokedAtUtc) return 'Escopo revogado';
    if (scope.rules?.startsAtUtc && new Date(scope.rules.startsAtUtc).getTime() > this.ws.now())
      return 'Escopo aguardando início';
    return new Date(scope.expiresAtUtc).getTime() > this.ws.now()
      ? 'Disponível'
      : 'Escopo expirado';
  }
  private defaultExpiry(): string {
    const date = new Date(Date.now() + 10 * 60_000);
    date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
    return date.toISOString().slice(0, 16);
  }
  private expiry(value: string): string | null {
    const date = new Date(value);
    return Number.isFinite(date.getTime()) ? date.toISOString() : null;
  }
  private complete(message: string): void {
    this.busy.set(false);
    this.notice.set(message);
    this.refresh.update(this.increment);
  }
  private fail(): void {
    this.busy.set(false);
    this.error.set(
      'Operação recusada. Confira escopo, validade, versão e permissões. Nenhum segredo é exibido no diagnóstico.',
    );
  }
  create(): void {
    if (this.busy() || this.credentialForm.invalid || !this.auth.can('scopes.manage')) return;
    if (this.credentialType() === 'JsonLogin' && this.login.invalid) return;
    const value = this.credentialForm.getRawValue();
    const expiresAtUtc = this.expiry(value.expires);
    if (!expiresAtUtc) return;
    this.busy.set(true);
    this.error.set('');
    this.ws.api
      .createTargetCredential(this.ws.projectId(), {
        ...value,
        expiresAtUtc,
        credentialType: this.credentialType(),
        ...(this.credentialType() === 'JsonLogin' ? { login: loginInput(this.login) } : {}),
      })
      .pipe(takeUntil(this.contextChanged), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: () => this.complete('Perfil cadastrado; segredo cifrado no backend.'),
        error: () => this.fail(),
      });
    this.credentialForm.controls.token.reset();
    clearLoginSecrets(this.login);
  }
  selectRotation(profile: TargetCredential): void {
    this.rotating.set(profile);
    this.rotationForm.reset({ expires: this.defaultExpiry() });
    this.rotationForm.controls.token.setValidators(
      profile.credentialType === 'JsonLogin' ? [] : [Validators.required],
    );
    this.rotationForm.controls.token.updateValueAndValidity();
    resetLogin(this.rotationLogin, profile.loginConfiguration);
  }
  closeRotation(): void {
    this.rotating.set(null);
    this.rotationForm.reset();
    resetLogin(this.rotationLogin);
  }
  rotate(): void {
    const profile = this.rotating();
    if (!profile || this.busy() || this.rotationForm.invalid || !this.auth.can('scopes.manage'))
      return;
    const value = this.rotationForm.getRawValue();
    if (profile.credentialType === 'JsonLogin' && this.rotationLogin.invalid) return;
    const expiresAtUtc = this.expiry(value.expires);
    if (!expiresAtUtc) return;
    this.busy.set(true);
    this.error.set('');
    this.ws.api
      .rotateTargetCredential(this.ws.projectId(), profile.id, {
        expectedVersion: profile.version,
        token: value.token,
        expiresAtUtc,
        ...(profile.credentialType === 'JsonLogin'
          ? { login: loginInput(this.rotationLogin) }
          : {}),
      })
      .pipe(takeUntil(this.contextChanged), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: () => {
          this.closeRotation();
          this.complete('Nova versão salva; versão anterior recusada.');
        },
        error: () => this.fail(),
      });
    this.rotationForm.controls.token.reset();
    clearLoginSecrets(this.rotationLogin);
  }
  revoke(profile: TargetCredential): void {
    if (this.busy() || !this.auth.can('scopes.manage')) return;
    this.busy.set(true);
    this.error.set('');
    this.ws.api
      .revokeTargetCredential(this.ws.projectId(), profile.id)
      .pipe(takeUntil(this.contextChanged), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: () =>
          this.complete('Perfil revogado; novas permissões recusadas e segredo removido.'),
        error: () => this.fail(),
      });
  }
  secondaryProfiles(): TargetCredential[] {
    const primary = this.profiles().find(
      (profile) => profile.id === this.scenarioForm.controls.profileId.value,
    );
    if (!primary) return [];
    return this.activeProfiles().filter(
      (profile) =>
        profile.id !== primary.id &&
        profile.scopeId === primary.scopeId &&
        (profile.credentialType ?? 'Bearer') === 'Bearer',
    );
  }
  execute(): void {
    const value = this.scenarioForm.getRawValue();
    const profile = this.profiles().find((profile) => profile.id === value.profileId);
    const secondary = value.secondaryProfileId
      ? this.secondaryProfiles().find((item) => item.id === value.secondaryProfileId)
      : undefined;
    if (
      this.busy() ||
      this.scenarioForm.invalid ||
      !this.auth.can('audits.execute-active') ||
      !profile ||
      !this.available(profile)
    )
      return;
    if (
      value.secondaryProfileId &&
      (!secondary || value.expectedAccess !== 'allow' || value.includeLoad)
    ) {
      this.error.set(
        'Segunda identidade exige perfil Bearer disponível no mesmo escopo, acesso permitido e ausência de carga.',
      );
      return;
    }
    if (value.includeLoad && value.expectedAccess !== 'allow') {
      this.error.set('Carga exige expectativa de acesso permitido.');
      return;
    }
    if (
      value.expectedAccess === 'deny' &&
      (!profile.baselineVerifiedAtUtc ||
        new Date(profile.baselineVerifiedAtUtc).getTime() <= Date.now() - 5 * 60_000)
    ) {
      this.error.set(
        'Execute primeiro acesso permitido em recurso protegido com este perfil; a referência vale por cinco minutos.',
      );
      return;
    }
    this.busy.set(true);
    this.error.set('');
    this.ws.api
      .requestAudit(
        this.ws.projectId(),
        value.targetUrl,
        'authenticated-lab',
        true,
        {
          credentialProfileId: profile.id,
          expectedAccess: value.expectedAccess,
          includeAuthenticatedLoad: value.includeLoad,
          ...(secondary ? { secondaryCredentialProfileId: secondary.id } : {}),
        },
        this.ws.dataOrigin(),
        this.optionalPlugins().filter((id) =>
          this.ws
            .catalog()
            ?.plugins.some(
              (plugin) =>
                plugin.id === id &&
                plugin.activation === 'explicit' &&
                plugin.eligibleProfiles?.includes('authenticated-lab') &&
                (plugin.capabilities.gateway?.identity !== 'dual' || !!secondary),
            ),
        ),
      )
      .pipe(takeUntil(this.contextChanged), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (audit) => {
          this.busy.set(false);
          this.ws.updateAudit(audit);
          void this.router.navigate(['/audits', audit.id]);
        },
        error: () => this.fail(),
      });
  }
}
