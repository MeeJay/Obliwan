/**
 * ObliWAN — brand coverage, as a number an operator can read. Risk R2.
 *
 * ┌─ THE RISK THIS FILE IS THE MITIGATION FOR ────────────────────────────────┐
 * │ R2, verbatim: "Périmètre TR-069 fantasmé : RouterOS et SonicWall n'ont    │
 * │ pas de client CWMP." The mitigation the architecture asks for is not a    │
 * │ paragraph in a document — it is "afficher la couverture par marque dans   │
 * │ l'UI". This service is that sentence as an endpoint.                      │
 * │                                                                          │
 * │ It deliberately reports BOTH halves:                                      │
 * │  - the STRUCTURAL truth (`ACS_BRAND_COVERAGE`, shared, static): which     │
 * │    brands have a CWMP client at all. Nothing will change this; it is a    │
 * │    property of the hardware.                                              │
 * │  - the OBSERVED truth (`fleet`, per tenant): of the devices this customer │
 * │    actually has, how many are enrolled and how many have informed in the  │
 * │    last 24 h.                                                             │
 * │                                                                          │
 * │ Reporting only the first would be a brochure; only the second would look  │
 * │ like a bug ("why are 0 of my 40 MikroTiks in the ACS"). Both together are │
 * │ the answer to the question the operator is actually asking.               │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import { db } from '../../db';
import {
  ACS_BRAND_COVERAGE,
  CWMP_NO_CONNECTION_REQUEST_EXPLANATION,
  type AcsCoverageReport,
} from './contract';

export async function coverageReport(tenantId: number): Promise<AcsCoverageReport> {
  // One query, grouped by brand: devices, enrolled CPEs, and CPEs that have
  // informed in the last day. The LEFT JOIN is what makes a brand with zero
  // enrolments appear with a zero rather than vanish from the table — which is
  // the whole point, since the interesting rows are the empty ones.
  const rows = (await db('devices as d')
    .leftJoin('cwmp_devices as c', 'c.device_id', 'd.id')
    .where('d.tenant_id', tenantId)
    .groupBy('d.brand')
    .select('d.brand')
    .count<{ brand: string; devices: string; enrolled: string; informed: string }[]>(
      'd.id as devices',
    )
    .countDistinct({ enrolled: 'c.device_id' })
    .select(
      db.raw(
        "count(*) FILTER (WHERE c.last_inform_at > now() - interval '24 hours') as informed",
      ),
    )) as Array<{
    brand: string;
    devices: string;
    enrolled: string;
    informed: string;
  }>;

  const byBrand = new Map(rows.map((r) => [r.brand, r]));

  // Every brand the product knows about appears, in the order of the shared
  // coverage table — including the two with zero devices, because "you have no
  // DrayTek" is also an answer.
  const fleet = ACS_BRAND_COVERAGE.map((c) => {
    const row = byBrand.get(c.brand);
    return {
      brand: c.brand,
      devices: Number(row?.devices ?? 0),
      cwmpEnrolled: Number(row?.enrolled ?? 0),
      informedLast24h: Number(row?.informed ?? 0),
    };
  });

  // A brand in the fleet that the coverage table does not list at all. Should
  // be impossible (`devices.brand` has a CHECK) but a silent drop here would
  // make the numbers not add up, and numbers that do not add up are how a
  // report loses its reader.
  for (const [brand, row] of byBrand) {
    if (fleet.some((f) => f.brand === brand)) continue;
    fleet.push({
      brand,
      devices: Number(row.devices),
      cwmpEnrolled: Number(row.enrolled),
      informedLast24h: Number(row.informed),
    });
  }

  return {
    brands: ACS_BRAND_COVERAGE,
    fleet,
    connectionRequestSupported: false,
    connectionRequestExplanation: CWMP_NO_CONNECTION_REQUEST_EXPLANATION,
  };
}
