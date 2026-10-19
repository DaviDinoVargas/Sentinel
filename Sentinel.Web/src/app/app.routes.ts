import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'overview' },
  {
    path: 'overview',
    title: 'Visão geral · Sentinel',
    loadComponent: () => import('./pages/overview').then((m) => m.OverviewPage),
  },
  {
    path: 'projects',
    title: 'Projetos · Sentinel',
    loadComponent: () => import('./pages/projects').then((m) => m.ProjectsPage),
  },
  {
    path: 'scopes',
    title: 'Escopos e políticas · Sentinel',
    loadComponent: () => import('./pages/scopes').then((m) => m.ScopesPage),
  },
  {
    path: 'audits',
    title: 'Central de auditorias · Sentinel',
    loadComponent: () => import('./pages/audits').then((m) => m.AuditsPage),
  },
  {
    path: 'audits/:id',
    title: 'Detalhe da auditoria · Sentinel',
    loadComponent: () => import('./pages/audits').then((m) => m.AuditDetailPage),
  },
  {
    path: 'findings',
    title: 'Resultados e achados · Sentinel',
    loadComponent: () => import('./pages/findings').then((m) => m.FindingsPage),
  },
  {
    path: 'evidence',
    title: 'Evidências e relatórios · Sentinel',
    loadComponent: () => import('./pages/evidence').then((m) => m.EvidencePage),
  },
  {
    path: 'score',
    title: 'Security Score · Sentinel',
    loadComponent: () => import('./pages/score').then((m) => m.ScorePage),
  },
  {
    path: 'plugins',
    title: 'Plugins e controles · Sentinel',
    loadComponent: () => import('./pages/plugins').then((m) => m.PluginsPage),
  },
  {
    path: 'operations',
    title: 'Infraestrutura e filas · Sentinel',
    loadComponent: () => import('./pages/operations').then((m) => m.OperationsPage),
  },
  {
    path: 'coverage',
    title: 'Capacidades · Sentinel',
    loadComponent: () => import('./pages/coverage').then((m) => m.CoveragePage),
  },
  { path: '**', redirectTo: 'overview' },
];
