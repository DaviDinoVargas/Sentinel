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
    http
      .expectOne('/api/v1/projects/search?limit=25&offset=0&sort=newest')
      .flush({ items: [], totalCount: 0, limit: 25, offset: 0 });
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
    expect(element.querySelector('nav a[href="/dependencies"]')).not.toBeNull();
    expect(element.querySelector('nav a[href="/api-surface"]')).not.toBeNull();
    expect(element.textContent).toContain('Fontes e segredos');
    expect(element.textContent).toContain('Infraestrutura e filas');
    expect(element.textContent).toContain('Evidências e relatórios');
    expect(element.querySelector('header select')).toBeNull();
    expect(element.querySelector('nav a[href="/run"]')).not.toBeNull();
    fixture.destroy();
  });
  it('alterna tema e persiste apenas a preferência visual', () => {
    const fixture = render();
    expect(document.documentElement.dataset['theme']).toBe('dark');
    fixture.componentInstance.toggleTheme();
    expect(document.documentElement.dataset['theme']).toBe('light');
    expect(localStorage.getItem('sentinel.theme')).toBe('light');
    fixture.componentInstance.toggleTheme();
    expect(document.documentElement.dataset['theme']).toBe('dark');
    fixture.destroy();
  });
  it('mantém links acessíveis no menu recolhido e isola o drawer aberto', () => {
    const fixture = render(),
      page = fixture.componentInstance,
      element = fixture.nativeElement as HTMLElement;
    page.toggleSidebar();
    fixture.detectChanges();
    expect(localStorage.getItem('sentinel.sidebar')).toBe('collapsed');
    expect(element.querySelector('nav a[href="/run"]')?.getAttribute('aria-label')).toBe(
      'Rodar testes',
    );
    page.mobileOpen.set(true);
    fixture.detectChanges();
    expect(element.querySelector('aside')?.getAttribute('aria-modal')).toBe('true');
    expect(element.querySelector('.workspace')?.hasAttribute('inert')).toBe(true);
    page.closeMobileMenu();
    fixture.detectChanges();
    expect(element.querySelector('.workspace')?.hasAttribute('inert')).toBe(false);
    fixture.destroy();
  });
});
