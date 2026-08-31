/**
 * ObliWAN — the bench tool, command line (M15).
 *
 * Run: npx tsx src/services/../bench/cli.ts   (packaged as an .exe for the
 * preparation workstation; see `000-RegularUpdate.bat` for the signing chain —
 * exe signed BEFORE the MSI is built, then the MSI signed too).
 *
 * ┌─ THE ORDER OF THE STEPS IS THE SAFETY ───────────────────────────────────┐
 * │  1. READ the identity. Nothing is written yet. A preparer who picked the  │
 * │     wrong family in the dropdown finds out here, from the hardware.       │
 * │  2. SHOW what will be sent, redacted, and wait for a yes. The one moment  │
 * │     review is cheap is before the socket opens.                           │
 * │  3. WRITE the account, then ENROL — in that order. A box that received an │
 * │     account and never reached the platform is recoverable (it is on the   │
 * │     bench); a platform row with no account behind it is a device ObliWAN  │
 * │     can see and never enter.                                              │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The generated password is printed ONCE, at the end, and goes into the vault
 * by hand. It is not in the enrolment payload and it is not written to disk:
 * a preparation workstation is a shared machine.
 */

import { createInterface } from 'node:readline/promises';
import { stdin, stdout, exit } from 'node:process';
import type { DeviceFamily } from '@obliwan/shared';
import { DEVICE_FAMILIES } from '@obliwan/shared';
import { readBenchIdentity, buildEnrolment, submitEnrolment, type BenchTarget } from './enroll';
import { planProvisioning, generateServicePassword } from './provision';

const rl = createInterface({ input: stdin, output: stdout });
const ask = async (q: string, dflt = ''): Promise<string> => {
  const a = (await rl.question(dflt ? `${q} [${dflt}] ` : `${q} `)).trim();
  return a || dflt;
};
const confirm = async (q: string): Promise<boolean> =>
  /^(y|yes|o|oui)$/i.test((await rl.question(`${q} (y/N) `)).trim());

function fail(message: string): never {
  console.error(`\n  REFUS — ${message}\n`);
  rl.close();
  exit(1);
}

async function main(): Promise<void> {
  console.log('\nObliWAN — préparation d\'un équipement neuf\n');

  const baseUrl = await ask('URL ObliWAN :', process.env.OBLIWAN_URL ?? 'https://obliwan.local');
  const token = process.env.OBLIWAN_ENROLMENT_TOKEN
    ?? await ask('Jeton d\'enrôlement :');
  if (!token) fail('aucun jeton : rien ne sera enrôlé.');

  console.log(`\n  Familles : ${DEVICE_FAMILIES.join(', ')}\n`);
  const family = (await ask('Famille :')) as DeviceFamily;
  if (!(DEVICE_FAMILIES as readonly string[]).includes(family)) fail(`famille inconnue "${family}".`);

  const target: BenchTarget = {
    host: await ask('Adresse sur l\'établi :', '192.168.88.1'),
    family,
    username: await ask('Compte d\'usine :', 'admin'),
    password: await ask('Mot de passe d\'usine :'),
  };
  const portRaw = await ask('Port (vide = défaut) :');
  if (portRaw) target.port = Number(portRaw);

  // ── 1. Lire, avant d'écrire quoi que ce soit ─────────────────────────────
  console.log('\n  Lecture de l\'identité…');
  const identity = await readBenchIdentity(target).catch((e: unknown) =>
    fail(`la lecture a échoué : ${e instanceof Error ? e.message : String(e)}`));

  console.log('\n  L\'équipement se déclare :');
  console.log(`    marque .............. ${identity.brand ?? '—'}`);
  console.log(`    modèle .............. ${identity.model ?? '—'}`);
  console.log(`    version ............. ${identity.osVersion ?? '—'}`);
  console.log(`    numéro de série ..... ${identity.serial ?? '—'}`);
  console.log(`    identité système .... ${identity.systemIdentity ?? '—'}`);
  if (!identity.serial && !identity.systemIdentity) {
    fail('ni numéro de série ni identité système : ObliWAN ne pourrait jamais le reconnaître (D5).');
  }
  if (!(await confirm('\n  Est-ce bien l\'équipement attendu ?'))) fail('abandon demandé.');

  // ── 2. Montrer ce qui sera envoyé ────────────────────────────────────────
  const svcUser = await ask('Compte de service à créer :', 'obliwan-svc');
  const svcPassword = generateServicePassword();
  const plan = planProvisioning(family, [{ username: svcUser, password: svcPassword, group: 'full' }]);

  console.log('\n  Lignes qui seront envoyées :');
  for (const line of plan.redacted) console.log(`    ${line}`);
  if (!plan.verified) {
    console.log(`\n  ATTENTION — dialecte NON VÉRIFIÉ sur matériel réel.`);
    console.log(`  ${plan.note}`);
    console.log('  Garde une console ouverte sur l\'équipement avant de continuer.');
  }
  if (!(await confirm('\n  Envoyer ces lignes ?'))) fail('abandon demandé.');

  // ── 3. Écrire, puis enrôler — dans cet ordre ─────────────────────────────
  console.log('\n  Écriture du compte de service…');
  // Le pousseur réel est branché ici : `applyOverSsh` pour DrayTek/Zyxel/
  // SonicOS avec le dialecte de `SSH_DIALECTS`, la connexion RouterOS pour
  // MikroTik. Volontairement non câblé tant qu'aucun dialecte non-MikroTik n'a
  // été confirmé sur matériel : un push aveugle sur un routeur neuf ne fait
  // rien ou le verrouille, et les deux se découvrent trop tard.
  fail(
    'le pousseur n\'est pas encore branché — cette version lit l\'identité, prépare et MONTRE '
    + 'les lignes, et s\'arrête là. Rien n\'a été écrit sur l\'équipement, rien n\'a été enrôlé.',
  );

  // Ce qui suit s'exécutera dès que le pousseur sera branché :
  //   const enrolment = buildEnrolment(identity, { now: new Date().toISOString(), ... });
  //   const r = await submitEnrolment(baseUrl, token, enrolment);
  //   console.log(`  enrôlé en quarantaine : device #${r.deviceId} (${r.status})`);
  //   console.log(`  MOT DE PASSE À METTRE AU COFFRE : ${svcPassword}`);
  void buildEnrolment; void submitEnrolment; void baseUrl; void token; void svcPassword;
}

main()
  .catch((err: unknown) => {
    console.error(`\n  ERREUR — ${err instanceof Error ? err.message : String(err)}\n`);
    exit(1);
  })
  .finally(() => rl.close());
