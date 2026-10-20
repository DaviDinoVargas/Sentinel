import { IdentityProfile } from '../core/auth-session.service';
export const adminIdentity: IdentityProfile = {
  subject: 'test',
  name: 'Operador de teste',
  roles: ['PlatformAdmin'],
  organization: {
    id: 'organization',
    name: 'Organização de teste',
    createdAtUtc: '2026-10-19T12:00:00Z',
  },
  permissions: [
    'workspace.read',
    'projects.manage',
    'scopes.manage',
    'audits.execute',
    'audits.execute-active',
    'platform.manage',
  ],
  limitations: ['Ambiente de teste.'],
};
