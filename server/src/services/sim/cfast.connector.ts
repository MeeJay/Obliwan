/**
 * ObliWAN F9 — CFAST connector. NOT IMPLEMENTED, AND IT SAYS SO OUT LOUD.
 *
 * ┌─ THIS FILE EXISTS TO REFUSE, AND THE REFUSAL IS THE FEATURE ──────────────┐
 * │ The alternative to a file like this is no file at all — and then an       │
 * │ account configured against CFAST either crashes with "no connector for    │
 * │ platform cfast" somewhere in a sweep, or, far worse, is quietly skipped.  │
 * │ A skipped account is a fleet of SIMs that appears in no list, raises no   │
 * │ alert, and looks exactly like a fleet with nothing wrong.                 │
 * │                                                                           │
 * │ So CFAST is a first-class platform in the vocabulary, its accounts can be │
 * │ created, and every read against one fails with a message that names what  │
 * │ is missing. `SIM_PLATFORM_CATALOG` carries the same fact as DATA, so the  │
 * │ UI greys the platform out instead of implying it is watched.              │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌── WHAT IS KNOWN ABOUT CFAST, AND WHAT STILL IS NOT ───────────────────────┐
 * │ This block used to reason from one screenshot. CFAST's own PUBLIC         │
 * │ developer portal has since been read — developers.cfast.fr, no login, an  │
 * │ index at /llms.txt, a Postman collection downloadable without an account  │
 * │ — and it contradicted the guess. The old reasoning is named at the        │
 * │ bottom rather than deleted, because the mistake it made is reusable.      │
 * │                                                                           │
 * │ READ, from the vendor's own documentation:                                │
 * │   • CFAST is not an operator and not a SIM platform. It is a French       │
 * │     telecom BSS / billing SaaS — quote-to-cash, provisioning, CDR         │
 * │     rating. The portal screenshot is its OPERATOR back-office.            │
 * │   • The integration is POLLED: OAuth2 / OIDC password grant against       │
 * │     v2.cfast.fr, Bearer JWT, a few hundred REST endpoints.                │
 * │   • Webhooks exist and their event catalogue is published IN FULL. It     │
 * │     carries entity CRUD, order status and billing events. It carries NO   │
 * │     consumption, quota, volume or threshold event of any kind. A webhook  │
 * │     from CFAST can say a line was re-provisioned; it can never say a      │
 * │     line is low on data — which is the only thing F9 needs.               │
 * │   • Beware `service-data-updated`: "data" there is a SERVICE TYPE         │
 * │     (xDSL/fibre), sitting in an enum beside `sip` and `copieur`. It is    │
 * │     not data consumption, and wiring it to a balance handler would be     │
 * │     building on a misreading.                                             │
 * │   • Webhook callbacks are UNSIGNED. The only documented authenticity      │
 * │     control is a source-IP allowlist — which ObliWAN cannot use, because  │
 * │     the Docker bridge NATs the source address (A6). An inbound CFAST      │
 * │     route would be a THIRD unauthenticated ingestion path, and that       │
 * │     needs an explicit decision rather than a drift into one.              │
 * │   • Rate limit: 2 requests/second, global across all endpoints, per       │
 * │     account. Any polling design must fetch wide and filter locally.       │
 * │   • CFAST integrates PHENIX PARTNERS as a supplier — the same Phenix      │
 * │     this module already reads directly. So the two CFAST accounts may     │
 * │     front the SAME lines, which would make CFAST an inventory and         │
 * │     re-invoicing source rather than a second balance source.              │
 * │                                                                           │
 * │ NOT KNOWN, and each one blocks this connector:                            │
 * │   • WHETHER A REMAINING-DATA FIGURE IS EXPOSED AT ALL. No documented      │
 * │     endpoint returns an included or a remaining volume. The nearest       │
 * │     surface returns alerts ALREADY RAISED — an alert log, not a balance   │
 * │     — and a healthy line may return nothing there, which under this       │
 * │     module's own rule is `unknown` and never `0`. This is the crux: if    │
 * │     the answer is no, F9 cannot run on CFAST and this file stays a        │
 * │     refusal, with its reason rewritten from "nothing is known" to "the    │
 * │     partner does not expose a balance".                                   │
 * │   • Credentials: `client_id` / `client_secret` are issued by CFAST        │
 * │     support by email, not self-served. Two accounts, two requests.        │
 * │                                                                           │
 * │ THE MISTAKE, NAMED: "the portal has a Webhooks menu, therefore expect     │
 * │ push" read a menu label as an architecture. The menu was real and the     │
 * │ conclusion was wrong, because the events behind it are about objects,     │
 * │ not about consumption. A vendor's published event list settles a          │
 * │ question that a screenshot only appears to.                               │
 * │                                                                           │
 * │ WHAT FINISHING THIS LOOKS LIKE: one authenticated GET against one real    │
 * │ mobile line, answering whether remaining data exists anywhere. Then the   │
 * │ poll, a token cache (close to Phenix's; the grant differs) and a 2 req/s  │
 * │ budget — and `SIM_PLATFORM_CATALOG` flips `readImplemented` IN THE SAME   │
 * │ COMMIT. Do not flip that flag before the code behind it exists: it is     │
 * │ what the dashboard believes, and now that `ingestion` below says `pull`   │
 * │ it is also the only thing keeping a refusing connector off the sweep.     │
 * │                                                                           │
 * │ Full evidence, every claim marked read or inferred: docs/cfast.md.        │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import type { SimIngestionKind } from '@obliwan/shared';
import { SimConnectorError, type SimConnector, type SimSession } from './types';

const PLATFORM = 'cfast' as const;

class CfastConnector implements SimConnector {
  readonly platform = PLATFORM;
  // `pull` — what CFAST's documentation actually describes. Declaring it does
  // NOT arm the sweep: `isPollable` in the registry requires `readImplemented`
  // as well, and the catalogue says false. That second condition was added WITH
  // this correction, precisely so that describing a partner more honestly can
  // never be the thing that starts dialling it.
  readonly ingestion: readonly SimIngestionKind[] = ['pull'];

  async open(): Promise<SimSession> {
    throw new SimConnectorError(
      // No "load them from an export" instruction: there is no importer, and an
      // error message that tells an operator to do something impossible is
      // worse than one that simply says what is missing.
      'CFAST is not implemented. Its REST API is publicly documented and polled, ' +
        'but no endpoint returning the data REMAINING on a line has been found ' +
        'there, and no account has been read yet. This account can hold lines and ' +
        'assignments; nothing reads balances for it.',
      'NOT_IMPLEMENTED',
      PLATFORM,
    );
  }
}

export const cfastConnector: SimConnector = new CfastConnector();
