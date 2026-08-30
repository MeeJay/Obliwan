/**
 * ┌───────────────────────────────────────────────────────────────────────────┐
 * │ The M10 contract, re-exported once so the rest of the ACS imports from    │
 * │ ONE place instead of scattering `@obliwan/shared/dist/cwmp` across twenty │
 * │ files. Same reason and same shape as `services/logs/contract.ts`.         │
 * │                                                                          │
 * │ The `/dist/` in the path is not an accident: `shared/src/index.ts` is a   │
 * │ barrel this milestone is not allowed to touch, so the CWMP module is      │
 * │ reached by its subpath — exactly as M7 does for `rollout` and M9 for      │
 * │ `query`. When someone eventually adds `export * from './cwmp'` to the     │
 * │ barrel, this file is the only import that has to change.                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

export * from '@obliwan/shared/dist/cwmp';
