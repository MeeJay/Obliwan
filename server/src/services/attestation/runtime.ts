// ============================================================================
// ObliWAN — Evidence runtime (F1 + F2)
// ============================================================================
//
// ┌─ THE DUTY THIS ARMS, AND WHY IT IS NOT OPTIONAL ──────────────────────────┐
// │ `exception.service.sweep()` is what turns an EXPIRED exception back into  │
// │ a visible drift finding. It runs at the head of the exception screens'    │
// │ reads too — but the exceptions screen is not the screen that has to be    │
// │ right. The DRIFT screen is, and the drift screen knows nothing about this │
// │ feature: it reads `drift_findings.ignored` and always will.                │
// │                                                                           │
// │ Without this timer, an exception that expired on Tuesday keeps hiding a   │
// │ critical until somebody happens to open the exceptions page. That is a    │
// │ dead guard — a rule the code states and never enforces — and it is the    │
// │ single most common defect this project has already paid for.              │
// │                                                                           │
// │   src/index.ts, after leaderElection.start():                             │
// │     startEvidenceRuntime();                                               │
// │   and in the graceful shutdown:                                           │
// │     stopEvidenceRuntime();                                                │
// └───────────────────────────────────────────────────────────────────────────┘
//
// Leader-gated, like every other background duty (arbitrage A5). The sweep only
// WRITES — it never dials an equipment — so two replicas running it would not
// be dangerous, merely wasteful and noisy in the log. Gating it also means the
// `applied` / `revived` counters in the log come from one place and can be read
// as a rate.
//
// The read-path sweep inside `exception.service` is NOT gated and must not be:
// a `web` replica that never wins the election still has to show an honest
// exception list.

import { leaderElection } from '../leaderElection';
import { logger } from '../../utils/logger';
import { startExceptionSweeper, stopExceptionSweeper, sweep } from '../drift/exception.service';

let unsubscribe: (() => void) | null = null;

export function startEvidenceRuntime(): void {
  if (unsubscribe) return;
  unsubscribe = leaderElection.onChange((isLeader) => {
    if (isLeader) {
      startExceptionSweeper();
      // One pass immediately on taking leadership rather than waiting a full
      // interval: a process that just took over from a crashed leader may be
      // inheriting exceptions that expired while nobody was sweeping.
      void sweep()
        .then((r) => logger.info({ ...r, trigger: 'leadership' }, 'Drift exception sweep'))
        .catch((err) => logger.error({ err }, 'Initial drift exception sweep failed'));
    } else {
      stopExceptionSweeper();
    }
  });
  logger.info('Evidence runtime wired to leadership (drift exception expiry)');
}

export function stopEvidenceRuntime(): void {
  unsubscribe?.();
  unsubscribe = null;
  stopExceptionSweeper();
}
