import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { OperationsPage } from './operations';
import { WorkspaceService } from '../core/workspace.service';
import { AuthSessionService } from '../core/auth-session.service';
import { adminIdentity } from '../testing/identity-fixture';
import { OperationsSnapshot } from '../core/sentinel-api.service';

describe('Amostras operacionais reais', () => {
  beforeEach(() =>
    TestBed.configureTestingModule({
      imports: [OperationsPage],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }),
  );
  function setup() {
    const auth = TestBed.inject(AuthSessionService);
    auth.profile.set(adminIdentity);
    const fixture = TestBed.createComponent(OperationsPage);
    const ws = TestBed.inject(WorkspaceService);
    return { auth, fixture, ws, page: fixture.componentInstance };
  }
  function sample(second: number, ready = 0): OperationsSnapshot {
    return {
      sampledAtUtc: new Date(Date.UTC(2026, 9, 25, 12, 0, second)).toISOString(),
      status: 'healthy',
      database: {
        status: 'healthy',
        projects: 1,
        queuedAudits: 0,
        failedAudits: 0,
        pendingOutbox: 0,
        dispatchedOutbox: 0,
        oldestPendingAtUtc: null,
      },
      broker: {
        status: 'healthy',
        deliveryLimit: 3,
        queues: [{ name: 'jobs', readyMessages: ready, consumers: 1 }],
      },
    };
  }
  it('deduplica timestamps e usa distância temporal real no gráfico', () => {
    const { fixture, ws, page } = setup();
    for (const s of [sample(0, 0), sample(5, 5), sample(20, 10), sample(20, 10)]) {
      ws.operations.set(s);
      fixture.detectChanges();
    }
    expect(page.samples().length).toBe(3);
    expect(page.chartPoints()).toBe('0,110 150,60 600,10');
    expect(page.consumers()).toBe(1);
    fixture.destroy();
  });
  it('mantém apenas 60 amostras e não transforma indisponibilidade em zero saudável', () => {
    const { fixture, ws, page } = setup();
    for (let i = 0; i < 65; i++) {
      ws.operations.set(sample(i, i));
      fixture.detectChanges();
    }
    expect(page.samples().length).toBe(60);
    expect(page.samples()[0].ready).toBe(5);
    ws.operations.set({
      ...sample(70),
      broker: { ...sample(70).broker, status: 'unavailable', queues: [] },
    });
    fixture.detectChanges();
    expect(page.readyMessages()).toBeNull();
    expect(page.samples().length).toBe(60);
    fixture.destroy();
  });
  it('remove a série quando a sessão deixa de ter acesso administrativo', () => {
    const { fixture, ws, page, auth } = setup();
    ws.operations.set(sample(0, 7));
    fixture.detectChanges();
    auth.profile.set({ ...adminIdentity, permissions: [], roles: ['ReadOnly'] });
    fixture.detectChanges();
    expect(page.samples()).toEqual([]);
    expect(fixture.nativeElement.textContent).toContain('Acesso restrito');
    fixture.destroy();
  });
});
