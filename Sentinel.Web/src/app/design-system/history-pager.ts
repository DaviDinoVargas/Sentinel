import { Component, inject } from '@angular/core';
import { WorkspaceService } from '../core/workspace.service';
@Component({
  selector: 's-history-pager',
  template: `@if (ws.history(); as page) {
    <div class="pagination">
      <span
        >Execuções {{ page.totalCount ? page.offset + 1 : 0 }}–{{
          page.offset + page.items.length
        }}
        de {{ page.totalCount }}</span
      ><button
        class="button small"
        [disabled]="page.offset === 0 || ws.loading()"
        (click)="ws.refreshProject(page.offset - page.limit)"
      >
        Anterior</button
      ><button
        class="button small"
        [disabled]="page.offset + page.limit >= page.totalCount || ws.loading()"
        (click)="ws.refreshProject(page.offset + page.limit)"
      >
        Próxima
      </button>
    </div>
  }`,
})
export class HistoryPager {
  readonly ws = inject(WorkspaceService);
}
