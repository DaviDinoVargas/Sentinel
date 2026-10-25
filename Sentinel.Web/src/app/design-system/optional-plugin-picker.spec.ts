import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { OptionalPluginPicker } from './optional-plugin-picker';
import { WorkspaceService } from '../core/workspace.service';

describe('Seleção explícita de verificações', () => {
  const plugin = (
    id: string,
    profiles: string[],
    identity = 'none',
    activation = 'explicit',
    isFixture = false,
  ) => ({
    id,
    name: id,
    riskClass: 'medium',
    eligibleProfiles: profiles,
    activation,
    isFixture,
    capabilities: { gateway: { identity } },
  });
  function setup() {
    const catalog = signal({
      plugins: [
        plugin('passive', ['simulated']),
        plugin('active', ['lab-active']),
        plugin('primary', ['authenticated-lab'], 'primary'),
        plugin('dual', ['authenticated-lab'], 'dual'),
        plugin('default', ['simulated'], 'none', 'default'),
        plugin('fixture', ['simulated'], 'none', 'explicit', true),
      ],
    });
    TestBed.configureTestingModule({
      imports: [OptionalPluginPicker],
      providers: [{ provide: WorkspaceService, useValue: { catalog } }],
    });
    const fixture = TestBed.createComponent(OptionalPluginPicker);
    fixture.componentRef.setInput('action', 'simulated');
    fixture.detectChanges();
    return fixture;
  }
  it('mostra somente opcionais compatíveis, sem seleção automática ou corpus', () => {
    const fixture = setup();
    expect(fixture.componentInstance.available().map((p) => p.id)).toEqual(['passive']);
    expect(fixture.nativeElement.querySelector('input').checked).toBe(false);
    fixture.componentRef.setInput('action', 'authenticated-lab');
    fixture.detectChanges();
    expect(fixture.componentInstance.available().map((p) => p.id)).toEqual(['primary']);
    fixture.componentRef.setInput('secondary', true);
    fixture.detectChanges();
    expect(fixture.componentInstance.available().map((p) => p.id)).toEqual(['primary', 'dual']);
  });
  it('remove seleções obsoletas e recusa IDs desconhecidos ou interação desabilitada', () => {
    const fixture = setup();
    const page = fixture.componentInstance;
    fixture.componentRef.setInput('selected', ['old', 'active']);
    const emit = vi.spyOn(page.selectionChange, 'emit');
    const checked = { target: { checked: true } } as unknown as Event;
    page.toggle('passive', checked);
    expect(emit).toHaveBeenLastCalledWith(['passive']);
    emit.mockClear();
    page.toggle('unknown', checked);
    fixture.componentRef.setInput('disabled', true);
    page.toggle('passive', checked);
    expect(emit).not.toHaveBeenCalled();
  });
});
