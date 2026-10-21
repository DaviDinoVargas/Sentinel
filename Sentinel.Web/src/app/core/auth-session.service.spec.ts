import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { AuthSessionService, authInterceptor } from './auth-session.service';
import { adminIdentity } from '../testing/identity-fixture';
import { WorkspaceService } from './workspace.service';

describe('Proteção da sessão OIDC', () => {
  beforeEach(() =>
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    }),
  );
  it('envia bearer somente à API da própria origem', () => {
    const auth = TestBed.inject(AuthSessionService);
    vi.spyOn(auth, 'token').mockReturnValue('fixture-token');
    const http = TestBed.inject(HttpClient);
    const testing = TestBed.inject(HttpTestingController);
    http.get('/api/v1/projects').subscribe();
    const own = testing.expectOne('/api/v1/projects');
    expect(own.request.headers.get('Authorization')).toBe('Bearer fixture-token');
    own.flush([]);
    for (const url of [
      'https://target.example/api/v1/projects',
      '//target.example/api/v1/projects',
      'http://localhost:18080/realms/sentinel',
    ]) {
      http.get(url).subscribe();
      const external = testing.expectOne(url);
      expect(external.request.headers.has('Authorization')).toBe(false);
      external.flush({});
    }
    testing.verify();
  });
  it('encerra a sessão após 401 e preserva autenticação após 403', () => {
    const auth = TestBed.inject(AuthSessionService);
    auth.profile.set(adminIdentity);
    vi.spyOn(auth, 'token').mockReturnValue('fixture-token');
    const http = TestBed.inject(HttpClient);
    const testing = TestBed.inject(HttpTestingController);
    http.get('/api/v1/operations').subscribe({ error: () => undefined });
    testing.expectOne('/api/v1/operations').flush({}, { status: 403, statusText: 'Forbidden' });
    expect(auth.profile()).toEqual(adminIdentity);
    http.get('/api/v1/projects').subscribe({ error: () => undefined });
    testing.expectOne('/api/v1/projects').flush({}, { status: 401, statusText: 'Unauthorized' });
    expect(auth.profile()).toBeNull();
    expect(auth.error()).toContain('Sessão');
    testing.verify();
  });
  it('cancela consultas pendentes e limpa contexto ao trocar ou encerrar identidade', () => {
    const ws = TestBed.inject(WorkspaceService);
    const testing = TestBed.inject(HttpTestingController);
    ws.selectProject('old-organization-project');
    const requests = testing.match((request) => request.url.includes('old-organization-project'));
    expect(requests.length).toBe(1);
    ws.reset();
    expect(requests.every((request) => request.cancelled)).toBe(true);
    expect(ws.projectId()).toBe('');
    expect(ws.context()).toBeNull();
    expect(ws.history()).toBeNull();
    testing.verify();
  });
});
