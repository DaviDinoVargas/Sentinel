import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { App } from './app';
import { AuthSessionService } from './core/auth-session.service';
import { adminIdentity } from './testing/identity-fixture';

describe('Central Sentinel', () => {
  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({
      imports: [App],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    const auth = TestBed.inject(AuthSessionService);
    auth.profile.set(adminIdentity);
    auth.ready.set(true);
    vi.spyOn(auth, 'start').mockResolvedValue(undefined);
  });
  afterEach(() => {
    TestBed.inject(HttpTestingController).verify();
    document.documentElement.removeAttribute('data-theme');
  });
  function render() {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/projects?limit=100').flush([]);
    http
      .expectOne('/api/v1/plugins')
      .flush({ plugins: [], rejectedCount: 0, approvalMode: 'automatic-schema-validation' });
    http.expectOne('/api/v1/operations').flush({
      status: 'healthy',
      sampledAtUtc: '2026-10-19T12:00:00Z',
      database: { status: 'healthy' },
      broker: { status: 'healthy', queues: [] },
    });
    fixture.detectChanges();
    return fixture;
  }
  it('apresenta navegação para todas as capacidades implementadas', () => {
    const fixture = render();
    const element = fixture.nativeElement as HTMLElement;
    expect(element.querySelectorAll('nav a').length).toBe(14);
    expect(element.textContent).toContain('Fontes e segredos');
    expect(element.textContent).toContain('Infraestrutura e filas');
    expect(element.textContent).toContain('Evidências e relatórios');
    expect(element.querySelector('select')?.disabled).toBe(true);
    fixture.destroy();
  });
  it('alterna tema e persiste apenas a preferência visual', () => {
    const fixture = render();
    fixture.componentInstance.toggleTheme();
    expect(document.documentElement.dataset['theme']).toBe('dark');
    expect(localStorage.getItem('sentinel.theme')).toBe('dark');
    fixture.componentInstance.toggleTheme();
    expect(document.documentElement.dataset['theme']).toBe('light');
    fixture.destroy();
  });
});
