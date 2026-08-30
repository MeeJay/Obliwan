# ObliWAN — Document d'architecture

**Version 1.0 — 2026-08-28 — Architecte en chef**
Cible : `D:\Obliwan` (vide). Socle repris de `D:\Obliguard`. SSO centralisé via `D:\Obligate`.

---

## 0. Décisions structurantes (à lire en premier)

Sept décisions cadrent tout le reste. Elles sont prises, pas ouvertes.

| # | Décision | Justification |
|---|---|---|
| D1 | **Le NCM (Normalized Config Model) est le cœur du produit**, pas le diff de texte. Toute fonctionnalité de config passe par lui. | Sur un parc à 4 marques, le diff textuel est structurellement inutilisable : la config DrayTek n'est même pas du texte. Sans NCM, ObliWAN n'est qu'un Oxidized de plus. |
| D2 | **Abstraction `DeviceDriver` obligatoire ; TR-069 n'est qu'un transport parmi cinq.** | RouterOS n'a **pas** de client TR-069, SonicWall non plus. L'ACS ne couvre en pratique que DrayTek et Zyxel CPE. Cadrer cette attente maintenant évite un échec de projet. |
| D3 | **Rien n'écrit sur un équipement hors de la file `change_jobs`**, avec verrou par device, plan figé, garde anti-lockout et dead-man armé. | Le risque n°1 est de se verrouiller hors d'un site à travers le tunnel qu'on modifie. C'est aussi ce qui rend le produit vendable à un MSP. |
| D4 | **Le CHR est la source de vérité de la présence** (`/ppp/active` en `listen` + réconciliation 60 s), pas le ping. On ne compose jamais un device dont la session PPP est down. | Économise 90 % du polling inutile, donne une reconnexion sub-seconde, et évite de confondre `UNREACHABLE` et `DOWN`. |
| D5 | **Identité device = `ppp_username` + `system_identity` + `serial`**, jamais l'IP de tunnel. Vérification par reconnexion fraîche avant toute écriture. | Les pools PPP dynamiques réattribuent les adresses : une IP périmée pousse la config du client A sur le routeur du client B. |
| D6 | **Postgres seul** : partitionnement natif + BRIN pour les séries, `pg-boss` + advisory locks pour les files et le leader. Pas de Redis, pas de TimescaleDB, pas de Mongo. | Le socle Obliguard n'a aucune de ces dépendances ; les volumes visés (≤ 500 sites) ne les justifient pas. |
| D7 | **Renommage propre à la copie** : `@obliwan/shared`, `device_groups` (et non `monitor_groups`), clé de chiffrement dédiée `OBLIWAN_ENCRYPTION_KEY`. | Migration `001` neuve = seul moment où c'est gratuit. Obliguard traîne encore `@obliview/shared` par défaut d'arbitrage initial. |

---

## 1. Jugement des 36 features

### 1.1 CORE — le produit n'existe pas sans

| Feature | Contenu consolidé (sources dédupliquées) |
|---|---|
| **C1. Socle suite Obli\*** | Auth + SSO Obligate, tenants, groupes + closure, settings hérités, notifications 10 plugins, live alerts, UI Obli Design v1. Copie quasi conforme d'Obliguard. |
| **C2. Inventaire + coffre de credentials** | `sites` / `devices` / `device_transports`, secrets AES-256-GCM, un enregistrement par canal (API, SSH, SNMP, REST, TR-069). *(fusionne « Secrets hors config » et la partie coffre de « Accès sans mot de passe »)* |
| **C3. Transport Arbiter** | Pool de connexions RouterOS API taggé (multiplexage + `listen`), SSH `ssh2`, SNMP, REST SonicOS, session CWMP. Backoff, circuit breaker persisté, file d'intentions différées. *(= « Transport Arbiter », « routerosPool »)* |
| **C4. Découverte CHR + présence PPP** | `/ppp/secret` + `/ppp/active` + `/ppp/active/listen` sur le concentrateur, quarantaine `pending` avant rattachement à un tenant, historique de sessions. |
| **C5. NCM + collecte + normalisation** | Modèle sémantique Zod versionné, un parser par marque, snapshots gzip + `ncm jsonb` + hash canonique, règles de normalisation éditables en base. *(= « Rosetta » + « CCM » + « Intent Diff »)* |
| **C6. Templates + variables héritées + révisions** | Nunjucks sandboxé, héritage global → tenant → chaîne de groupes → device (portage exact de `settings.service.ts`), révisions immuables, partiels épinglés à la publication. |
| **C7. Plan & Drift** | `diff(NCM désiré, NCM observé)` → `PlanOp[]` ordonnées, `base_state_hash` (refus d'un plan périmé), drift_runs / drift_findings avec ignorés conservés. *(= « obliwan plan » + drift)* |
| **C8. Job queue d'application** | `change_jobs` + `change_job_steps`, un job en vol par device, fenêtres de maintenance, kill-switch global, reprise après crash. |
| **C9. SNMP + séries temporelles** | net-snmp v2c/v3, découverte IF-MIB à identité stable `(device_id, ifName)`, compteurs HC 64 bits, détection reboot/wrap, tables partitionnées + rollups 1m/5m/1h, seuils avec `for` + hystérésis. |
| **C10. ACS TR-069 minimal** | Listener 7547 séparé, Inform/InformResponse, GPV/SPV, Download, Reboot, file de tâches par CPE. Périmètre **DrayTek + Zyxel CPE uniquement**, assumé et affiché dans l'UI. |
| **C11. Audit** | `audit_log` append-only chaîné par hash + `command_audit` (toute commande envoyée, secrets caviardés). |

### 1.2 KILLER — 8, pas une de plus

Critère : **différenciant ET implémentable dans les 12 mois** avec l'équipe et le socle décrits.

| # | Feature | Pourquoi elle est retenue (une phrase) |
|---|---|---|
| **K1** | **Safe-Apply — commit-confirm universel** (dead-man armé *sur* l'équipement, confirmation par un canal **indépendant** de celui qui a poussé, désarmement seulement après soak) | C'est la seule chose qui transforme « on ne touche à rien en prod » en « on pousse le mardi » ; RouterOS n'a que le safe-mode interactif, DrayTek/Zyxel/SonicWall n'ont rien, personne ne l'a fait de façon homogène sur ce segment. |
| **K2** | **Management-Path Guard** (analyse statique du plan : mini-moteur de forwarding sur le NCM cible, paquet synthétique CHR → IP mgmt, refus si `ACCEPT` devient `DROP`/no-route) | 90 % des lockouts viennent de cinq motifs identifiables avant tout accès réseau, et la topologie L2TP mono-chemin rend la preuve rigoureuse — aucun concurrent ne l'adresse. |
| **K3** | **Rollout par vagues canari** (1 → 5 % → 25 % → reste, portes de santé mesurées entre vagues, pause et rollback automatiques, écran de rayon d'impact avant lancement) | Le bulk change existe partout mais en mode « feu à volonté » ; le déploiement progressif à portes est standard côté logiciel depuis quinze ans et inexistant côté réseau. |
| **K4** | **Intent Compiler** (une intention de site → RouterOS / DrayTek / Zyxel / SonicWall, échec à la compilation si le matériel ne sait pas faire) | Seule feature qui divise réellement le coût d'un parc multi-marque : un technicien qui ne connaît que MikroTik déploie un DrayTek, et la connaissance constructeur quitte la tête du senior pour entrer dans le produit. |
| **K5** | **Fleet Query** (DSL typé compilé en SQL sur le `ncm jsonb` indexé GIN : « qui a encore un any/any en entrée WAN », « qui est en SNMP v1 public ») | Coût marginal quasi nul une fois le NCM là, et il transforme une réponse d'audit de trois semaines en trois minutes — c'est le ROI le plus visible du NCM. |
| **K6** | **Attribution du drift** (corrélation diff ↔ logs de login équipement ↔ sessions ↔ identités Obligate, avec `unattributed` explicite plutôt qu'un coupable inventé) | Tous les outils s'arrêtent à « drift détecté », c'est-à-dire exactement là où le problème d'exploitation commence ; et sans auteur, personne n'ose activer la remédiation automatique. |
| **K7** | **Verdict d'accessibilité** (table de vérité sur 4 signaux indépendants : session PPP côté CHR, SNMP via tunnel, sonde externe, dernier Inform TR-069 → `TUNNEL_DOWN_SITE_UP`, `SITE_DOWN`, `WAN_FAILOVER`, `CONCENTRATOR_DEGRADED`) | Le CHR est un SPOF qui ment : sans ce croisement, une panne de tunnel se lit comme 300 sites morts et une bascule WAN silencieuse ne se lit pas du tout. |
| **K8** | **Reprise de parc / Golden Site** (clustering des NCM existants, extraction automatique des variables, brouillons de templates + liste des écarts par site) | C'est le mur d'adoption : sans lui il faut écrire les templates à la main avant que l'outil ne serve à quoi que ce soit, et le projet meurt à la troisième semaine. |

**Écartés du top 8 de justesse** : Failover Forensics (excellent, mais valeur seulement après plusieurs mois de données — passe en backlog prioritaire), Enrôlement zéro-touch (XL, dépend de K1+K4 mûrs).

### 1.3 PLUS TARD — backlog, par ordre de valeur décroissante

| Feature | Condition d'entrée / note |
|---|---|
| **Failover Forensics** (chronologie des bascules WAN, bascule silencieuse jamais revenue, SLA par opérateur) | Après M3 (SNMP) + M8. Très vendeur en MSP. |
| **Enrôlement Zéro-Touch multi-marque** (bootstrap `.rsc` MikroTik + tunnel auto-provisionné sur le CHR ; ACS pour DrayTek/Zyxel) | Après K1 + K4 stables. Assumer que MikroTik exige un geste atelier ou Netinstall. |
| **Time Machine / plan inverse + Config Bisect** | Presque gratuit une fois C7 + K1 en place : `restorePlan = diff(actualNow, stateAt(t))`. |
| **Network CI / conformité as code** | DSL déclaratif sur le NCM, évalué à chaque collecte et en pré-check de plan. Se greffe sur K5. |
| **Change Request + approbation** (four-eyes, re-plan au merge, refus si état périmé) | Nécessaire dès le premier client grand compte. |
| **Rotation de masse des credentials** | Après K3 : c'est un rollout comme un autre, avec vérification de reconnexion au nouveau secret. |
| **Console broker enregistrée** (xterm.js + asciinema, identifiants jamais révélés) | Fort argument audit/assurance cyber, mais indépendant du cœur. |
| **Dossier Client / rapport SLA PDF** | Assemblage pur, aucune collecte nouvelle. Rentable dès qu'il y a 3 mois de données. |
| **Exposition réelle (CVE × config vivante)** | Nécessite le catalogue d'avis + prédicats JSONPath ; dépend de K5. |
| **Météo Opérateurs** (sondes embarquées, corrélation ASN/région) | Ne vaut rien sous ~100 sites. |
| **Git bidirectionnel** (miroir YAML, PR → plan commenté) | Utile pour une équipe déjà « git-native » seulement ; Postgres reste l'autorité. |
| **Digital Twin CHR** (rejeu réel du plan sur un CHR jetable) | XL. À reconsidérer quand le taux d'échec de plan MikroTik sera mesuré. |
| **Blast Radius cross-suite** (monitors Obliview / IPAM Oblimap impactés) | Dépend d'APIs d'autres produits ; à traiter comme intégration, pas comme cœur. |

### 1.4 bis — REJETS ANNULÉS par arbitrage utilisateur (2026-08-28)

Trois features sortent de la liste des rejetées et entrent au périmètre. Le motif d'origine est conservé
pour mémoire, avec la raison de l'annulation.

| Feature | Motif du rejet initial | Pourquoi il est annulé | Où elle atterrit |
|---|---|---|---|
| **Import/export — repris ET monté au niveau** | « Repris et monté, ou pas repris du tout. Pas de code mort. » | Arbitrage : on le monte. C'est ce qui permet de migrer un client d'une instance à l'autre. | Périmètre v1. Sauvegarde/restauration de tenants, templates, révisions, inventaire, variables. Résolution de conflits comme dans Obliguard, mais avec les entités ObliWAN. **Pas d'entité orpheline : tout ce qui est exporté doit être réimportable et testé.** |
| **Assistant LLM d'écriture de templates — HORS chemin d'exécution** | « Non déterministe sur le chemin critique. » | Le rejet du transpileur en ligne **tient toujours** : aucun LLM ne génère la config poussée en production. L'annulation ne porte que sur l'assistance à la rédaction. | Backlog haute priorité, après M5. L'assistant propose du texte de template ; le rendu reste Nunjucks déterministe, relu par un humain, et passe par le même plan + Management-Path Guard que n'importe quel changement. **Aucun chemin ne permet à une sortie de LLM d'atteindre un équipement sans revue.** |
| **Zero-Touch Suite Onboarding — saga cross-suite** | « Trop de dépendances externes pour la v1. » | Arbitrage : la suite est mono-éditeur, les APIs sont maîtrisées. | Un site créé une fois est propagé dans ObliWAN + Obliview + Obliguard + Oblimap. À traiter en **saga avec compensation** (création partielle → rollback des produits déjà provisionnés), jamais en appels en cascade best-effort. Jalon dédié après M7. |

> **Résolu le 2026-08-28** : la quatrième case cochée était un faux clic. **Edge Ban Fabric reste rejetée.**
> Le périmètre des rejets annulés est donc figé à ces trois entrées.

> **Identité visuelle — arbitrée le 2026-08-28** : on reste sur l'artwork d'Obliguard (bouclier) pour le moment.
> `client/public/{favicon,logo,logo-daylight}.svg` et la couleur `#4e9cff` du sélecteur d'apps dans `Header.tsx`
> sont des **placeholders assumés**, pas un oubli. À reprendre quand ObliWAN aura sa propre identité.

### 1.4 REJETÉES

| Feature | Raison |
|---|---|
| **Edge Ban Fabric** (propagation des bans Obliguard vers les CPE) | Hors périmètre : c'est une feature Obliguard qui consommerait l'API ObliWAN, pas l'inverse. Couplage inter-produit prématuré. |
| **Transpileur d'intention par LLM** | Non déterministe sur le chemin critique. Réintroduisible plus tard comme **assistant d'écriture hors exécution** (le rendu reste du code). |
| **Moteur de presets avec sandbox JS** (style GenieACS) | `vm2` déprécié, `node:vm` n'est pas une frontière de sécurité. Moteur déclaratif validé par Zod, point. |
| **Connection Request UDP/STUN (Annexe G) et XMPP (Annexe K)** | Taux de succès médiocre en production, bindings NAT qui expirent en 30-120 s, support CPE marginal. Le fallback réel est `PeriodicInformInterval` réduit — et l'UI doit l'annoncer honnêtement. |
| **Vendorer GenieACS** | AGPL-3.0 : contaminant. Lire comme référence, réécrire. (Un déploiement séparé piloté par NBI reste une option — voir décisions ouvertes.) |
| **SNMP comme source principale pour MikroTik** | L'API RouterOS donne strictement plus. SNMP reste utile en haute fréquence et comme socle commun aux 3 autres marques. |
| **TimescaleDB / BullMQ+Redis / Mongo** | Dépendances d'infra non justifiées au volume visé ; partitionnement natif + `pg-boss` + advisory locks suffisent. |
| **`/import` pour appliquer une config MikroTik** | S'arrête à la première erreur et laisse le routeur à moitié configuré sans handler. On applique via `/system/script` enveloppé `:do{}on-error={rollback}`. |
| **Zero-Touch Suite Onboarding (saga cross-suite complète)** | Trop de dépendances externes pour la v1. La partie mono-produit passe en backlog. |
| **Import/export orphelin d'Obliguard** | Repris **et monté** cette fois, ou pas repris du tout. Pas de code mort. |

---

## 2. Arborescence du monorepo `D:\Obliwan`

```
D:\Obliwan\
├─ package.json                      # workspaces: shared, server, client — name "obliwan"
├─ .env.example  .gitignore  .gitattributes(LF)  .dockerignore
├─ docker-compose.yml  .build.yml  .dev.yml  .external-db.yml
├─ install.sh  start.ps1  000-RegularUpdate.bat  001-PromoteToProd.bat
├─ README.md  LICENSE  CLAUDE.md
│
├─ shared/src/
│  ├─ index.ts  types.ts               # ApiResponse, User, UserPermissions, AppTheme
│  ├─ capabilities.ts                  # CAPABILITIES ObliWAN (vocabulaire UNIQUE)
│  ├─ tenants.ts                       # MASTER_TENANT_ID
│  ├─ socketEvents.ts                  # wan:* + notification:*
│  ├─ settings.ts                      # SETTINGS_DEFINITIONS + HARDCODED_DEFAULTS
│  ├─ ncm/                             # LE contrat
│  │   ├─ model.ts                     # NcmDocument (Zod) + ncmVersion
│  │   ├─ resources.ts                 # Interface, Vlan, Route, FirewallRule, NatRule,
│  │   │                               #   DhcpScope, IpsecPeer, LocalUser, Service, Qos
│  │   ├─ keys.ts                      # clés sémantiques stables (hash de prédicat)
│  │   └─ plan.ts                       # PlanOp, ApplyPlan, RiskLevel
│  ├─ intent/                           # IntentDocument (K4) + variables typées
│  ├─ device.ts                         # DeviceBrand, DeviceFamily, TransportKind,
│  │                                    #   DeviceCapabilities, NO_CAPABILITIES
│  └─ telemetry.ts                      # InterfaceSample, ReachabilityVerdict
│
├─ server/
│  ├─ Dockerfile  docker-entrypoint.sh  knexfile.ts  tsconfig.json  package.json
│  ├─ src/
│  │  ├─ env.ts  config.ts  index.ts  app.ts  socket.ts
│  │  ├─ db/index.ts
│  │  ├─ db/migrations/
│  │  │   001_obliwan_core.ts          # auth/tenants/groups/settings/notifications
│  │  │   002_inventory.ts             # sites, devices, transports, health, discoveries
│  │  │   003_snmp.ts                  # credentials, targets, interfaces, poll_state
│  │  │   004_timeseries.ts            # partitions + rollups + traps + syslog
│  │  │   005_config.ts                # snapshots, ncm_*, normalization_rules
│  │  │   006_templates.ts             # templates, revisions, partials, vars, renders
│  │  │   007_drift_change.ts          # drift, plans, jobs, rollouts, backups
│  │  │   008_cwmp.ts                  # ACS TR-069
│  │  │   009_attribution_audit.ts     # login events, attributions, audit chaîné
│  │  ├─ middleware/  auth  tenant  rbac  validate  rateLimiter  errorHandler  audit
│  │  ├─ routes/      index.ts + auth, tenant, devices, sites, snmp, templates,
│  │  │                config, drift, jobs, rollouts, query, cwmp, admin, importExport
│  │  ├─ controllers/ (miroir des routes)
│  │  ├─ validators/  *.schema.ts (Zod)
│  │  ├─ services/
│  │  │  ├─ auth/ (auth, twoFactor, passwordReset, obligate, appConfig, permission)
│  │  │  ├─ tenant.service.ts  group.service.ts  settings.service.ts
│  │  │  ├─ notification.service.ts  liveAlert.service.ts  smtpServer.service.ts
│  │  │  ├─ transport/
│  │  │  │   routeros/{protocol.ts, connection.ts, pool.ts, capabilities.ts}
│  │  │  │   ssh.transport.ts  snmp.transport.ts  rest.transport.ts  cwmp.transport.ts
│  │  │  │   arbiter.service.ts        # choix du canal + file d'intentions
│  │  │  ├─ drivers/
│  │  │  │   types.ts  base.ts  registry.ts
│  │  │  │   mikrotik/{driver.ts, parse.ts, render.ts, quirks.ts}
│  │  │  │   draytek/  zyxel/  sonicwall/    (même triptyque)
│  │  │  ├─ fleet/
│  │  │  │   chrDiscovery.service.ts  pppPresence.service.ts
│  │  │  │   deviceBinding.service.ts  reachability.service.ts   # K7
│  │  │  ├─ snmp/
│  │  │  │   session.ts  discovery.ts  poller.ts  rateCalculator.ts  scheduler.ts
│  │  │  │   trapReceiver.ts  syslogReceiver.ts  parsers/<brand>.ts
│  │  │  │   rollup.service.ts  partition.service.ts  threshold.service.ts
│  │  │  ├─ config/
│  │  │  │   collect.service.ts  normalize.service.ts  snapshot.service.ts
│  │  │  │   ncmIndex.service.ts        # aplatissement en tables analytiques
│  │  │  ├─ template/
│  │  │  │   engine.ts  loader.ts  renderWorker.ts  variableResolver.service.ts
│  │  │  │   version.service.ts  assignment.service.ts  render.service.ts
│  │  │  ├─ intent/  compiler.service.ts  capabilityCheck.ts   # K4
│  │  │  ├─ plan/
│  │  │  │   planner.service.ts  mgmtPathGuard.ts               # K2
│  │  │  │   riskScoring.ts  blastRadius.service.ts
│  │  │  ├─ change/
│  │  │  │   jobQueue.service.ts  apply.service.ts
│  │  │  │   safeApply.service.ts  rollback.service.ts          # K1
│  │  │  │   rollout.service.ts  healthGate.ts                  # K3
│  │  │  │   backup.service.ts  transfer.service.ts
│  │  │  ├─ drift/  drift.service.ts  semanticDiff.ts  attribution.service.ts  # K6
│  │  │  ├─ query/  dsl.ts  compiler.ts  savedQuery.service.ts  # K5
│  │  │  ├─ baseline/ miner.service.ts  cluster.ts              # K8
│  │  │  ├─ cwmp/   (voir ci-dessous)
│  │  │  ├─ audit.service.ts  leaderElection.ts  secretVault.service.ts
│  │  ├─ cwmp/                          # app Express SÉPARÉE, port 7547
│  │  │   index.ts  cwmpApp.ts  httpListener.ts  fileServer.ts
│  │  │   soap/{parse.ts, serialize.ts, xsd.ts, faults.ts}
│  │  │   auth/{digestServer.ts, digestClient.ts}
│  │  │   session/{sessionStore.ts, sessionMachine.ts}
│  │  │   handlers/{inform.ts, transferComplete.ts, cpeRequests.ts}
│  │  │   rpc/builders.ts
│  │  ├─ notifications/ registry.ts types.ts plugins/*.ts   (copie Obliguard)
│  │  └─ utils/ logger.ts crypto.ts slug.ts topoSort.ts
│  └─ test/ fakeCpe.ts  fixtures/configs/<brand>/*.txt  golden/
│
└─ client/
   ├─ Dockerfile  nginx.conf  vite.config.ts  tailwind.config.ts  index.html
   ├─ public/ favicon.svg logo.svg logo-daylight.svg
   └─ src/
      ├─ main.tsx App.tsx index.css
      ├─ api/ client.ts + auth|devices|sites|snmp|templates|config|drift|jobs|
      │        rollouts|query|cwmp|admin.api.ts
      ├─ store/ authStore tenantStore uiStore socketStore liveAlertsStore
      │         groupStore deviceStore jobStore
      ├─ socket/socketClient.ts   hooks/useSocket.ts  hooks/usePersisted.ts
      ├─ i18n/index.ts  locales/<18 langues>/translation.json
      ├─ components/
      │   layout/  AppLayout Header Sidebar TenantSwitcher LiveAlerts
      │            NotificationCenter ProtectedRoute GlobalAddDeviceModal
      │   common/  Button Input Modal Drawer DataTable Badge StatusDot
      │            LoadingSpinner Logo UserAvatar ThemePicker PeriodSelector
      │            GroupPicker TargetTreePicker CodeBlock DiffViewer
      │   settings/ SettingsPanel SettingField InheritanceBadge
      │   device/  DeviceStatusBadge InterfaceTable ThroughputChart PppTimeline
      │   config/  NcmTree ConfigDiff PlanViewer RiskBadge
      │   change/  JobTimeline WaveProgress ApprovalPanel
      └─ pages/ (voir §4)
```

---

## 3. Schéma de base de données consolidé

Convention : `tenant_id integer NOT NULL DEFAULT 1 REFERENCES tenants(id) ON DELETE CASCADE` sur toute table métier ; `uuid` unique sur toute entité exportable ; secrets en colonne `*_enc` (AES-256-GCM) ; `timestamptz`.

### 3.1 Hérité d'Obliguard — copie quasi conforme (migration `001`)

| Table | Modification pour ObliWAN |
|---|---|
| `users` | `password_hash` nullable, `foreign_source/_id/_source_url`, `enrollment_version` — inchangé |
| `session` | créée par la migration (`createTableIfMissing:false`) — inchangé |
| `password_reset_tokens`, `sso_foreign_users` | inchangé (ignorer `switch_tokens`/`sso_link_tokens`, vestiges) |
| `tenants`, `user_tenants` | inchangé |
| **`device_groups`** (ex `monitor_groups`), `group_closure` | **renommé** — arbre de sites/équipements |
| `user_teams`, `team_memberships`, `team_permissions` | `scope` ∈ `group|device` (au lieu de `monitor`) |
| `permission_sets` | `AVAILABLE_CAPABILITIES` réécrit, **aligné sur `shared/capabilities.ts`** (un seul vocabulaire) |
| `settings` | `scope` ∈ `global|group|device` |
| `app_config` | `obligate_config` (JSON chiffré), `obligate_enabled` |
| `smtp_servers`, `notification_channels`, `notification_bindings`, `notification_log`, `notification_channel_tenants` | `bindings.scope` ∈ `global|group|device` |
| `live_alerts` | inchangé |

Capabilities ObliWAN — **27 capacites, vocabulaire fige en M1** (`shared/src/capabilities.ts` fait foi ;
la valeur `<domaine>.<verbe>` est un format de fil persiste en base et echange avec Obligate : on AJOUTE, on ne renomme jamais) :
`DEVICE_READ`, `DEVICE_WRITE`, `DEVICE_DISCOVER`, `CONFIG_READ`, `CONFIG_WRITE`, `TEMPLATE_READ`, `TEMPLATE_WRITE`,
`PLAN_CREATE`, `CHANGE_APPLY`, `CHANGE_APPROVE`, `ROLLOUT_MANAGE`, `DRIFT_READ`, `DRIFT_MANAGE`, `QUERY_RUN`,
`SNMP_READ`, `SNMP_ADMIN`, `ACS_ADMIN`, `CREDENTIAL_MANAGE`, `SECRET_READ`, `GROUP_WRITE`, `USERS_MANAGE`,
`TENANTS_MANAGE`, `SETTINGS_MANAGE`, `NOTIFICATIONS_MANAGE`, `AUDIT_READ`, `EXPORT_RUN`, `IMPORT_RUN`.

> Correction du 2026-08-28 : la premiere redaction citait `CONFIG_PUSH` / `CONFIG_APPROVE`. Remplaces par
> `CHANGE_APPLY` / `CHANGE_APPROVE` — appliquer un changement n'est pas pousser une config (un reboot ou une
> mise a jour de firmware sont des changements sans config). `CREDENTIAL_MANAGE` (creer/tourner un secret) est
> volontairement distinct de `SECRET_READ` (afficher un secret en clair) : tourner un mot de passe est un geste
> d'exploitation banal, le lire ne l'est pas.

> **À ne PAS reprendre** : tout l'IPS (`ip_events`, `ip_bans`, `ip_reputation`, `ip_whitelist`, `service_templates`, `remote_blocklists`, `rate_limit_policies`), `remediation_*` d'Obliview, les méthodes `permission.service` référençant la table `monitors` (code mort, table inexistante), `syncCapabilitySchemas()` (endpoint inexistant côté Obligate), les deps `gamedig` + `playwright-chromium`.

### 3.2 Nouveau — Inventaire et transport (`002`)

| Table | Colonnes clés | Rôle |
|---|---|---|
| `sites` | `id, tenant_id, code UNIQUE(tenant), name, address, contact, timezone, maintenance_window jsonb` | Le site client ; porte la fenêtre de maintenance qui gate les pushs |
| `devices` | `id, uuid, tenant_id, site_id, group_id, name, brand, family, model, serial, os_version, role('cpe'|'chr'), concentrator_id→devices, ppp_username UNIQUE, tunnel_ip inet, wan_public_ip inet, system_identity, source_ip_hint inet, status('pending'|'active'|'quarantined'|'disabled'), is_managed, first_seen_at, last_seen_at` | Registre du parc. `UNIQUE(brand, serial)`. **Identité = ppp_username + system_identity + serial** |
| `device_transports` | `id, device_id, transport('routeros_api'|'ssh'|'rest'|'cwmp'|'snmp'), enabled, priority, host, port, username, secret_enc, private_key_enc, use_tls, tls_fingerprint_sha256, params jsonb, last_ok_at, last_error` `UNIQUE(device_id,transport)` | Un canal = une ligne. Empreinte TLS épinglée au premier succès |
| `device_capabilities` | `device_id UNIQUE, family, observed_overrides jsonb, working_transports jsonb, failed_transports jsonb, last_probe_at, probe_failure_count` | Écart entre ce que la famille sait faire et ce que **cette** unité a répondu |
| `device_health` | `device_id, transport, conn_state, circuit_state('closed'|'open'|'half_open'), consecutive_failures, backoff_ms, next_retry_at, last_rtt_ms, last_error` | Backoff/breaker persistés → survivent au restart |
| `discoveries` | `concentrator_id, ppp_username, remote_address, caller_ip, profile, ppp_comment, state('pending'|'bound'|'ignored'), bound_device_id, reviewed_by` | Quarantaine : **aucun rattachement automatique à un tenant** |
| `ppp_sessions` | `concentrator_id, device_id, ppp_username, tunnel_ip, caller_ip, started_at, ended_at, duration_seconds, disconnect_reason` | Présence, flaps, changement d'IP publique, SLA |
| `reachability_verdicts` | `device_id, ts, ppp_up, snmp_ok, external_ok, cwmp_recent, verdict, confidence` | **K7** |

### 3.3 Nouveau — SNMP et séries (`003`, `004`)

| Table | Points saillants |
|---|---|
| `snmp_credentials` | v2c `community_enc` / v3 `username, level, auth_proto, auth_key_enc, priv_proto, priv_key_enc, context` |
| `snmp_targets` | `device_id UNIQUE, credential_id, host, port, poll_interval_sec NULL=hérité, timeout_ms, retries, max_repetitions, supports_hc_counters, next_poll_at, consecutive_failures` — `INDEX(enabled, next_poll_at)` |
| `snmp_interfaces` | `UNIQUE(device_id, if_name)` — **`if_index` est mutable**, `state('active'|'vanished')` |
| `snmp_poll_state` | baseline de delta persistée (`sys_uptime_ticks`, compteurs) |
| `snmp_if_samples` | `PARTITION BY RANGE(ts)` journalier, BRIN(ts) + BTREE(if_id, ts DESC), rétention 48 h |
| `snmp_if_rollup_1m/5m/1h` | `avg/max/p95` par bucket, `PK(if_id,bucket)`, rétention 8 j / 90 j / 730 j |
| `snmp_device_samples` (+rollups) | cpu, mem, temp, uptime, reachable, rtt |
| `snmp_traps`, `syslog_messages` | partitionnées, `varbinds`/`structured_data` en jsonb, `parsed jsonb` |
| `snmp_thresholds`, `snmp_alert_state` | `for_seconds` + `hysteresis_pct` obligatoires ; états `ok|pending|firing` |

### 3.4 Nouveau — Config, NCM, templates (`005`, `006`)

| Table | Colonnes clés |
|---|---|
| `config_snapshots` | `device_id, source('routeros_api'|'ssh'|'rest'|'cwmp'|'pre_change'), raw_gz bytea, raw_sha256, ncm jsonb, ncm_hash, ncm_version, os_version, captured_at, last_seen_at` — `UNIQUE(device_id, ncm_hash)` (déduplication : un routeur inchangé bump `last_seen_at`). Index **GIN `jsonb_path_ops`** sur `ncm` |
| `ncm_interfaces` / `ncm_routes` / `ncm_firewall_rules` / `ncm_nat_rules` / `ncm_dhcp_scopes` / `ncm_local_users` / `ncm_services` / `ncm_ipsec_peers` | Aplatissement régénéré en transaction à chaque snapshot ; `device_id, snapshot_id, sem_key, position, props jsonb, is_managed(comment~'^obliwan:')`. Sert K5 et le diff sémantique |
| `normalization_rules` | `scope('global'|'brand'|'group'|'device'), kind('strip_line'|'strip_section'|'mask_secret'|'sort_set'|'canonicalize'), pattern, section_path, section_ordered` — **`section_ordered` par défaut à `true`** (le tri d'une chaîne de firewall détruit la sémantique) |
| `templates` | `tenant_id NULL=global, name, brand, model_pattern, os_min, os_max` |
| `template_revisions` | `revision, body, body_sha256, var_schema jsonb, section_severity jsonb, status('draft'|'published'|'quarantined'|'deprecated')` + **trigger d'immuabilité** sur `published` |
| `template_partials`, `template_partial_revisions`, `template_revision_deps` | Partiels **épinglés à la publication** (extraction de l'AST Nunjucks) |
| `template_assignments` | `scope('global'|'tenant'|'group'|'device'), scope_id, revision_id NULL=latest_published, pin_mode, priority` |
| `config_variables` | `scope, scope_id, key, value jsonb, is_secret` — `UNIQUE(scope,scope_id,key)`. Structure calquée sur `settings` |
| `config_renders` | `device_id, revision_id, body (secrets masqués), body_sha256, ncm_desired jsonb, variables_snapshot jsonb, render_error` |

### 3.5 Nouveau — Drift, plan, changement (`007`)

| Table | Colonnes clés |
|---|---|
| `drift_runs` | `device_id, render_id, snapshot_id, status('in_sync'|'drifted'|'error'|'unreachable'), findings_count, ignored_count, max_severity` — **`error` ≠ `unreachable`** |
| `drift_findings` | `run_id, path, sem_key, kind('missing'|'extra'|'changed'|'moved'), severity, intent_value jsonb, actual_value jsonb, text_patch, ignored, ignored_by_rule` |
| `drift_attributions` | `finding_id/run_id, actor_kind('obliwan'|'human'|'foreign_acs'|'unattributed'), device_local_user, source_ip, obligate_user_id, confidence, evidence jsonb` — **K6** |
| `device_login_events` | `device_id, ts, channel('winbox'|'ssh'|'api'|'web'|'cwmp'), local_user, source_ip, raw` (syslog + `/log` + audit REST) |
| `identity_map` | `device_local_user → obligate_user_id`, `is_shared` |
| `change_plans` | `device_id, source('template'|'intent'|'refactor'|'restore'), base_state_hash, ops jsonb (PlanOp[]), rendered jsonb, risk_level, mgmt_path_verdict, blast_radius jsonb, expires_at` |
| `change_jobs` | `uuid, device_id, plan_id, kind('push'|'export'|'backup'|'restore'|'reboot'|'firmware'), status('queued'|'awaiting_approval'|'running'|'awaiting_confirm'|'soaking'|'succeeded'|'failed'|'rolled_back'|'aborted'), rollout_id, wave_index, canary_rank, confirm_deadline, soak_until, preflight_backup_id, deadman_handle, requested_by, approved_by, scheduled_for` |
| `change_job_steps` | `job_id, seq, name('lint'|'preflight_backup'|'arm_deadman'|'apply'|'reconnect'|'postcheck'|'soak'|'disarm'|'cleanup'), status, output, error` |
| `rollouts` / `rollout_waves` | `template_revision_id, target_selector jsonb, abort_threshold, status` ; `wave_index, size_pct, gate_config jsonb, gate_result jsonb, state` — **K3** |
| `change_approvals` | `job_id|rollout_id, user_id, decision, comment` — contrainte four-eyes si `risk_level='high'` |
| `device_backups` | `device_id, kind('binary'|'rsc'), trigger('scheduled'|'preflight'|'manual'), storage_path, sha256, encryption_password_enc, retention_class, expires_at, restored_at` |
| `command_audit` | `device_id, user_id, job_id, transport, command, args_redacted jsonb, is_write, success, duration_ms, source_ip` — append-only |

### 3.6 Nouveau — ACS TR-069 (`008`)

`cwmp_devices` (`device_id PK`, `cwmp_id UNIQUE = OUI-ProductClass-Serial`, `root_prefix`, `data_model('tr098'|'tr181')`, `cwmp_version`, `connection_request_url`, `cr_password_enc`, `acs_auth_ha1`, `periodic_inform_interval`, `reachability`, `vendor_quirks jsonb`) · `cwmp_parameters` (`PK(device_id,path)`, `value`, `value_type`, `writable`, `notification`, index `text_pattern_ops`) · `cwmp_tasks` (file par device, `command_key UNIQUE`, `state`, `attempts`, `expires_at`) · `cwmp_sessions` · `cwmp_rpc_log` (partitionné, **désactivé par défaut**, rétention 7 j) · `cwmp_transfers` (`command_key`, `url_token`, `http_fetched_at`) · `cwmp_files` · `cwmp_param_map` (`canonical_key ↔ param_path` par `data_model/brand/model/firmware`, avec `{i}` d'instance) · `cwmp_acs_settings` (par tenant : `tenant_slug`, `digest_realm`, `trusted_cidrs`, `allow_auto_enroll`).

### 3.7 Nouveau — Requête et audit (`009`)

`saved_queries` (`dsl`, `compiled_sql_hash`, `is_policy`, `severity`) · `policy_results` (`query_id, device_id, snapshot_id, passed, evaluated_at`) · `audit_log` (`actor_type, actor_id, action, entity_type, entity_id, before jsonb, after jsonb, correlation_id uuid, prev_hash, hash`, `REVOKE UPDATE, DELETE`).

---

## 4. Client — pages et sidebar

### 4.1 Entrées de sidebar (`navItems: NavItem[]`)

| Label (`nav.*`) | Path | Icône lucide | Garde |
|---|---|---|---|
| Tableau de bord | `/` | `LayoutDashboard` | — |
| Parc | `/devices` | `Router` | `DEVICE_READ` |
| Sites | `/sites` | `MapPin` | `DEVICE_READ` |
| Interfaces | `/interfaces` | `Activity` | `DEVICE_READ` |
| Configurations | `/config` | `FileCode` | `CONFIG_READ` |
| Dérive | `/drift` | `GitCompareArrows` | `CONFIG_READ` |
| Templates | `/templates` | `Layers` | `TEMPLATE_WRITE` |
| Variables | `/variables` | `Braces` | `TEMPLATE_WRITE` |
| Changements | `/changes` | `PlayCircle` | `CHANGE_APPLY` |
| Déploiements | `/rollouts` | `Rocket` | `CHANGE_APPLY` |
| Requêtes parc | `/query` | `Search` | `CONFIG_READ` |
| Sauvegardes | `/backups` | `Archive` | `CONFIG_READ` |
| TR-069 / ACS | `/acs` | `RadioTower` | `ACS_ADMIN` |
| Alertes | `/alerts` | `BellRing` | — |
| Journaux | `/logs` | `ScrollText` | `DEVICE_READ` |
| — section admin repliable — | | | |
| Découvertes | `/admin/discoveries` | `Radar` | `adminOnly` |
| Groupes | `/admin/groups` | `FolderTree` | `adminOnly` |
| Utilisateurs & équipes | `/admin/users` | `Users` | `adminOnly` |
| Notifications | `/admin/notifications` | `Send` | `adminOnly` |
| Audit | `/admin/audit` | `ShieldCheck` | `adminOnly` |
| Paramètres | `/admin/settings` | `Settings` | `adminOnly` |

L'arbre sites/équipements (drag & drop `@dnd-kit`, `activationConstraint: {distance: 8}`) remplace l'arbre d'agents, sous la nav, avec pastille de présence PPP temps réel.

### 4.2 Pages

**Publiques** : `LoginPage` (SSO Obligate + anti-boucle `_sso_redirect_ts` 15 s + 2FA), `ForgotPasswordPage`, `ResetPasswordPage`, `SsoEnrollPage`.

**Applicatives** :
- `DashboardPage` — cartes : sites en ligne / tunnels down, drift ouverts par sévérité, jobs en cours, top interfaces saturées, verdicts d'accessibilité anormaux.
- `DevicesPage` (table filtrable marque/modèle/statut/drift) → `DeviceDetailPage` avec onglets : **Vue d'ensemble · Interfaces · Configuration (NCM + brut) · Dérive · Changements · Sauvegardes · TR-069 · Journaux · Paramètres**.
- `SitesPage` / `SiteDetailPage` (équipements, fenêtre de maintenance, chronologie PPP).
- `InterfacesPage` (vue parc, débit/erreurs, tri par saturation).
- `ConfigPage` (snapshots, comparaison N/N-1, arbre NCM, export).
- `DriftPage` (liste + `DriftDetailPage` : diff sémantique à gauche, patch textuel à droite, attribution, bouton « générer un plan »).
- `TemplatesPage` / `TemplateEditorPage` (éditeur + prévisualisation du rendu sur un device témoin) / `TemplateDiffPage` / `AssignmentsPage`.
- `VariablesPage` (héritage avec `InheritanceBadge` : Défaut / Global / Groupe X / Override).
- `PlanPage` (rayon d'impact, ops colorées, verdict Management-Path Guard, bouton Approuver).
- `ChangesPage` / `ChangeJobPage` (timeline des steps en direct, sortie de commandes, état du dead-man).
- `RolloutsPage` / `RolloutDetailPage` (vagues, portes de santé, pause/reprise/abandon).
- `QueryPage` (DSL + autocomplétion depuis le JSON Schema NCM, résultats drill-down, sauvegarde en politique).
- `BackupsPage`, `AlertsPage`, `LogsPage` (syslog + traps + `/log` unifiés).
- `AcsPage` (CPE, arbre de paramètres, file de tâches, journal RPC, firmwares).
- Admin : `DiscoveriesPage` (rattachement des PPP inconnus), `GroupsPage`, `UsersPage`, `NotificationsPage`, `AuditPage`, `SettingsPage` (SMTP, SSO Obligate, ACS, communautés SNMP, credentials CHR, rétentions, kill-switch global).
- `NotFoundPage`.

---

## 5. Plan d'implémentation

### 5.0 ÉTAT AU 2026-08-29

| Jalon | État | Preuve d'exécution (pas de déclaratif) |
|---|---|---|
| **M1** — squelette + SSO Obligate | ✅ **LIVRÉ** | Migration 001 exécutée contre PostgreSQL 16 réel : up → 22 tables, down → base nettoyée, re-up → 22 tables. Serveur démarre, migre, crée l'admin, élit son leader. `/health` → `{"status":"ok","version":"0.1.0"}`. Refus de démarrer sur `OBLIWAN_ROLE` invalide et sur `SESSION_SECRET` par défaut hors dev. |
| **M2** — inventaire, coffre, transports, CHR | ✅ **LIVRÉ, recette passée** | Contre PostgreSQL 16 réel + faux CHR parlant le protocole binaire RouterOS sur socket TCP : 3 découvertes en `pending` (aucun device créé en douce), rattachement manuel, **bascule de présence en 9 à 15 ms** (budget 2000 ms), verdict `UNREACHABLE` distinct de `SITE_DOWN`. Client RouterOS : 107 assertions (10 bornes d'encodage octet par octet, automate alimenté un octet à la fois, sentence coupée en 2 segments TCP, login moderne + legacy < 6.43, `!trap` → Error). Coffre : 30 assertions, dont non-fuite vérifiée mécaniquement. Migration 002 : 20 cas fonctionnels joués en SQL, chaque refus vérifié. |
| **DURCISSEMENT** — non planifié | 🔄 **EN COURS** | Voir 5.0.1. |
| M3 → M13 | ⬜ à faire | Études M3/M4 déjà produites (voir 5.0.2). |

#### 5.0.1 Le durcissement sécurité — un jalon qui n'était pas au plan

Un audit adversarial du code M1 a trouvé **8 findings critiques**, tous d'isolation multi-tenant ou de RBAC.
Les deux plus graves, confirmés par lecture directe du code :

- `getUserCapabilities()` accordait **les 27 capacités à quiconque possédait une ligne `user_tenants`** :
  la grille de rôles, les permission sets et les flags `sensitive` étaient purement décoratifs.
- Un repli `?? 1` à quatre endroits envoyait tout utilisateur sans tenant dans le **tenant maître**.

Puis une vérification adversariale des correctifs a rendu le verdict « partiellement corrigé » et découvert
**deux critiques que l'audit initial avait manquées**, plus **une régression introduite par le correctif** :

- la **clé API Obligate publiée dans l'URL de redirection SSO** à un visiteur anonyme — le même secret sert
  de bearer serveur-à-serveur ;
- `/auth/callback` adoptant **n'importe quel compte local** via `linkedLocalUserId` sans filtre `foreign_source` ;
- un admin plateforme créé par l'API se retrouvait **verrouillé hors de sa propre instance** (403 partout,
  y compris sur la route qui aurait permis de le réparer).

> **Leçon à budgéter pour la suite** : ce travail ne figurait dans aucun jalon et a coûté l'équivalent d'un
> jalon entier. Tout jalon touchant à l'authentification, au cloisonnement des tenants ou aux secrets doit
> désormais embarquer son propre audit adversarial — et une **vérification du parcours nominal**, puisque
> c'est le durcissement lui-même qui a produit la régression la plus bloquante.

#### 5.0.2 Acquis mobilisables immédiatement

`docs/` contient **7 283 lignes** d'études déjà produites, à consommer au moment du jalon concerné :

| Document | Sert à |
|---|---|
| `M4-NCM-contrat.md` | M4 — code Zod du modèle, clés sémantiques stables, modélisation de l'ordre du firewall |
| `M4-normalisation-routeros.md` | M4 — règles de normalisation, c'est là que se gagne le critère « < 3 findings de bruit » |
| `M3-series-temporelles.md` | M3 — DDL partitionné, rollups, calcul de débit, dimensionnement chiffré |
| `import-export-bundle.md` | §8.1 — format canonique et moteur de plan d'import |
| `audit-M1-securite.md`, `audit-M1-correction.md`, `verif-secfix*.md` | registre des défauts et de leur traitement |

#### 5.0.3 Dette ouverte, à traiter avant ou pendant M3

| Dette | Détail |
|---|---|
| **Anti-rejeu TOTP en mémoire de process** | Correct sur un serveur unique, inopérant après redémarrage ou avec deux répliques — **contredit directement l'arbitrage A5**. Forme durable connue : colonne `users.totp_last_counter`, `UPDATE` conditionnel, `rowCount === 0` = rejeu. |
| **Coutures du jalon M2** | Collision de deux écrivains sur `device_health` ; `assertVaultUsable()` sans appelant (protection R8 morte) ; `discoveries.bound_device_id` en `ON DELETE SET NULL` sous un `CHECK` qui l'interdit ; divergences de routes client/serveur ; `startFleetRuntime()` amorcé depuis `socket.ts`. |
| **Rien n'a jamais parlé à un équipement réel** | Zéro MikroTik, zéro CHR, zéro tunnel L2TP, zéro paquet SNMP émis, zéro navigateur ouvert. Tout est prouvé contre des doubles **écrits par les agents eux-mêmes** — si la compréhension du protocole est fausse, le double reproduit la même erreur et les tests passent. Le pinning TLS n'a jamais vu un certificat MikroTik. |
| **Bundle client : 674 kB** (etait 3 124 kB) | **Resolu le 2026-08-29.** Deux leviers, mesures : (1) les 18 locales etaient des imports STATIQUES dans `i18n/index.ts` — passees en `import.meta.glob` a la demande, l'anglais restant eager parce qu'il est le repli et doit exister avant le premier rendu : 3 124 -> 1 653 kB ; (2) les 34 pages etaient statiques dans `App.tsx` — 32 passees en `React.lazy` sous un `Suspense`, `LoginPage` et `NotFoundPage` gardees eager (premier rendu) : 1 653 -> **674 kB** (213 kB gzip). 108 chunks. Verifie sur le build servi : l'HTML ne precharge aucune locale, et les chunks de page comme de locale repondent 200 a la demande. Reste le plus gros chunk secondaire, `InterfacesTable` a 408 kB (Recharts) — candidat evident si le sujet revient. |


Chaque jalon est livrable et testable. Les jalons M1–M7 constituent la v1 ; M8–M12 l'extension multi-marque et les killers restants.

### M1 — Le squelette tourne et on se connecte via Obligate *(1,5 sem.)* — ✅ LIVRÉ
Monorepo `@obliwan/{shared,server,client}` ; `env.ts` → `config.ts` → `app.ts` (ordre helmet → cors → json → cookie → session PG → rateLimiter → `/auth` → `/api` → `/health`) ; migration `001` (auth/tenants/`device_groups`/settings/notifications/app_config) ; `obligate.service` + `obligateCallback.routes` (sans `syncCapabilitySchemas`) ; `LoginPage` + `AppLayout` + `Sidebar` vide + `ThemePicker` 4 thèmes (clé `ow-theme` aux **3** endroits) ; Docker (compose ×4, nginx, entrypoint, `.gatattributes` LF) ; `000/001-*.bat`.
**Test** : `docker compose up` → login SSO Obligate → dashboard vide, switch de tenant, thème persistant, `/health` renvoie la version.

### M2 — Inventaire, coffre, transports, CHR *(2,5 sem.)* — ✅ LIVRÉ
Migration `002` ; `secretVault` avec **clé dédiée** + `key_version` ; `routeros/{protocol, connection, pool}` **avec tags `.tag=`, streaming de lignes, `/cancel`, timeouts par requête, `!trap` → Error, pinning d'empreinte TLS** ; `ssh.transport` ; `arbiter.service` ; `chrDiscovery` + `pppPresence` (listen + réconciliation 60 s) ; `deviceBinding.assertTargetBinding()` ; `leaderElection` (advisory lock) ; pages Parc / Sites / Découvertes ; événement `wan:site:presence`.
**Test** : le CHR est déclaré, 3 sites de labo apparaissent en `pending`, rattachement manuel, présence qui bascule en < 2 s quand on coupe le tunnel, verdict `UNREACHABLE` distinct de `DOWN`.

### M3 — SNMP et séries temporelles *(2,5 sem.)* — ⬅️ PROCHAIN
Migrations `003`/`004` ; sessions v2c/v3 cachées (LRU + `close()`) ; découverte IF-MIB à identité `if_name` ; `rateCalculator` (reboot via `sysUpTime`, wrap 32 bits, clamp `ifHighSpeed`, `DISCARD` sans écriture) ; scheduler adaptatif + jitter ; partitions + rollups ; seuils `for`+hystérésis → notifications ; pages Interfaces + graphes Recharts.
**Test** : 20 interfaces à 30 s pendant 24 h, aucun débit négatif ni pic > vitesse de lien, reboot d'un routeur → trou dans la série et pas un pic, alerte de saturation qui ne re-notifie pas en boucle.

### M4 — NCM MikroTik, snapshots, drift lecture seule *(3 sem.)*
`shared/ncm` (Zod) ; driver MikroTik `parse` (`/export terse show-sensitive=no` en SSH, complément API) ; `normalize.service` + `normalization_rules` seedées ; `snapshot.service` (gzip + dédup par `ncm_hash`) ; `ncmIndex` (tables aplaties + GIN) ; `semanticDiff` (`missing|extra|changed|moved`) ; `drift_runs`/`findings` ; pages Configurations + Dérive.
**Test** : 30 devices snapshotés quotidiennement pendant 2 semaines → **objectif : < 3 findings de bruit par device**. C'est le critère d'acceptation du jalon ; on n'avance pas tant qu'il n'est pas atteint.

### M5 — Templates, variables, plan *(2,5 sem.)*
Migration `006` ; Nunjucks + loader DB + **worker_threads (`resourceLimits`, timeout 5 s)** ; filtres réseau et d'échappement RouterOS ; `variableResolver` (portage de `settings.service`) ; révisions immuables + deps épinglées ; assignations multi-scope ; `render.service` → `ncm_desired` ; `planner.service` → `PlanOp[]` + `base_state_hash` ; `PlanPage`.
**Test** : un template appliqué à 10 devices produit 10 plans corrects ; modifier un partiel ne change pas le rendu d'une révision publiée ; un plan devient invalide dès qu'on touche le routeur en Winbox.

### M6 — Écriture sûre : K1 + K2 *(3 sem.)*
`mgmtPathGuard` (moteur de forwarding sur le NCM cible, paquet CHR→mgmt, refus si `ACCEPT→DROP`/no-route ; motifs `TUNNEL_CRITICAL`) ; `backup.service` (binaire + `.rsc`, pull SFTP ou `/tool/fetch` à token à usage unique, suppression on-device) ; `safeApply` (script `obliwan-rollback` + scheduler `start-time=startup` ; apply via `/system/script` enveloppé `:do{}on-error={}` ; **reconnexion sur socket neuve**, post-conditions, soak 5 min, désarmement avec retry jusqu'au succès) ; `jobQueue` (`FOR UPDATE SKIP LOCKED`, un job par device, fenêtre de maintenance, kill-switch) ; `command_audit` ; `ChangeJobPage` en direct.
**Test destructif obligatoire** : pousser volontairement une règle `chain=input drop` qui coupe le tunnel → le guard la refuse ; forcer l'override → le device se restaure seul et le job passe `rolled_back` sans intervention.

### M7 — Rollouts par vagues : K3 *(2 sem.)*
`rollouts`/`rollout_waves`, écran de rayon d'impact (compilation des N plans avant lancement), portes de santé (session PPP remontée, `ifOperStatus`, absence de nouveaux `ifInErrors`, RTT vs baseline 7 j, aucun BOOT inattendu), pause/abandon, quarantaine automatique de la révision fautive, progression Socket.io par `rolloutId`.
**Test** : rollout sur 20 devices dont 2 saboteurs → arrêt à la vague 2, vagues précédentes rollbackées, révision quarantainée.
→ **Fin de la v1 : produit utilisable en production sur parc MikroTik.**

### M8 — Attribution et verdict : K6 + K7 *(2 sem.)*
Ingestion syslog UDP+TCP/514 + parsers par marque + `/log` RouterOS ; `device_login_events` ; `attribution.service` (fenêtre temporelle + score, `unattributed` explicite, comptes partagés marqués) ; `reachability.service` (table de vérité 4 signaux, suppression des alertes filles si `CONCENTRATOR_DEGRADED`) ; pages Journaux et bandeau d'attribution dans Dérive.
**Test** : modification manuelle en Winbox → drift attribué au bon compte et à la bonne IP en < 10 min ; coupure du CHR → 1 alerte concentrateur, pas 300.

### M9 — Fleet Query : K5 *(1,5 sem.)*
DSL (Chevrotain) → JSONPath/SQL avec **whitelist stricte des chemins** issue du schéma NCM ; requêtes sauvegardées promues en politiques évaluées à chaque snapshot ; export CSV/JSON ; page Requêtes avec autocomplétion.
**Test** : « qui a un `any/any` en entrée WAN », « qui est en SNMP v1 », « qui a un admin par défaut » — réponses < 200 ms sur 300 devices.

### M10 — ACS TR-069 et drivers DrayTek/Zyxel : C10 + K4 partiel *(4 sem.)*
Migration `008` ; app CWMP séparée sur 7547/7548 (`express.text`, POST vide = signal protocolaire, digest maison avec HA1 stocké, cookie `ACSsession` + fallback `(cwmp_id, IP)`) ; `sessionMachine` (l'ACS ne parle que sur POST vide) ; `fast-xml-parser` avec `isArray` obligatoire + sérialiseur maison ; GPV/SPV/Download/Reboot + `TransferComplete` corrélé par `CommandKey` ; `cwmp_param_map` + learn mode ; parsers NCM DrayTek/Zyxel (arbre CWMP aplati, CLI en complément) ; `fakeCpe.ts` **écrit avant le serveur**.
**Test** : `fakeCpe` en TR-098 et TR-181, quirks injectés (cookie absent, tableau à 1 élément, mauvais `xsi:type`) ; puis un Vigor et un Zyxel réels en labo. Sans matériel réel, le jalon n'est pas clos.

### M11 — SonicWall + compilateur multi-dialecte : K4 complet *(3 sem.)*
Driver SonicOS REST (session exclusive avec `override:true` + logout en `finally`, pending config, commit atomique, discard sur erreur de staging) ; `intent/compiler` (Intent → NCM → artefact par marque) ; `capabilityCheck` (échec de compilation **avant** tout accès réseau si le modèle ne sait pas faire) ; golden-files en CI.
**Test** : une même intention de site compile et s'applique sur les 4 marques en labo ; le golden-file casse la CI au moindre écart de rendu.

### M12 — Reprise de parc : K8 *(2,5 sem.)*
`baseline/miner` : découpage en facts atomiques, détection de variables par alignement inter-sites, clustering hiérarchique (Jaccard pondéré, en worker, **sans LLM**), brouillons de templates avec compteur « présent sur 27/30 », marquage « spécificité client » qui devient une exception documentée, score de conformité par client.
**Test** : import de 50 configs hétérogènes → ≤ 4 clusters proposés, ≥ 80 % des lignes couvertes par le template déduit, chaque écart listé et classable.

### M13 — Internationalisation *(à planifier)*
Les 18 langues du socle sont présentes et **aucune clé n'est manquante** (fr et en complets, les 16 autres
portent la valeur anglaise en repli — rien ne peut afficher un chemin brut à l'écran). Ce jalon couvre la
traduction réelle des 16 autres locales, plus la reprise de `SsoEnrollPage` qui est en français codé en dur
et n'utilise pas i18n du tout.
**Chaque jalon M2→M12 laisse donc derrière lui ses nouvelles clés en repli anglais — c'est assumé, pas un oubli.**

**Backlog immédiat post-M12** : Failover Forensics · Time Machine / plan inverse · Change Request + approbation · Rapports SLA PDF · ZTP · Rotation de credentials · Console broker.

---

## 6. Dépendances, ports, risques

### 6.1 Dépendances npm à ajouter

| Paquet | Version | Raison |
|---|---|---|
| `net-snmp` | ^3.26 | Seule lib Node mature couvrant v3 USM (SHA-2, AES-256) **et** `createReceiver` pour les traps |
| `nunjucks` + `@types/nunjucks` | ^3.2 | Héritage `{% extends %}/{% block %}` + partiels : le seul moteur qui couvre le besoin « blocs réutilisables + conditions ». Handlebars n'a pas d'héritage, EJS exécute du JS |
| `fast-xml-parser` | ^5 | Parsing CWMP entrant : synchrone, 5-10× plus rapide que xml2js. `removeNSPrefix`, `parseTagValue:false`, **`isArray` obligatoire** |
| `diff` | ^9 | Patch textuel unifié (revisions + complément lisible du drift). Auto-typé, ne PAS ajouter `@types/diff` |
| `ajv` + `ajv-formats` | ^8 / ^3 | Validation des `var_schema` (JSON Schema) des révisions |
| `ip-address` | ^10 | Filtres réseau (`cidrHost`, `netmask`) et **moteur de forwarding du Management-Path Guard** |
| `lru-cache` | ^11 | Cache des sessions SNMP avec `dispose()` → `session.close()` (sinon fuite de sockets UDP) |
| `p-limit` | **^3** | Bornage de concurrence. **v7 est ESM-only** et casserait le build CJS du serveur |
| `pg-boss` | ^10 | File de jobs sur Postgres : évite d'introduire Redis dans la suite |
| `chevrotain` | ^11 | Parseur du DSL Fleet Query, compilé en SQL avec whitelist de chemins |
| `semver` | ^7 | Contraintes `os_min`/`os_max` des templates |
| `http-auth-utils` | ^7 | Parsing/construction des en-têtes Digest (la vérification reste maison) |
| `handlebars` | — | **Non** : redondant avec Nunjucks |
| `pg-copy-streams` | ^7 | Optionnel, seulement si > 5000 lignes/cycle de poll |
| Déjà présents | `ssh2`, `undici`, `knex`, `pg`, `zod`, `socket.io`, `pino`, `express`, `bcrypt`, `otpauth`, `qrcode`, `nodemailer`, `recharts`, `@dnd-kit/*`, `i18next` | — |
| **À retirer** du socle copié | `gamedig`, `playwright-chromium` (~400 Mo), `three` | Restes Obliview/netmap 3D. Réintroduire Playwright uniquement au jalon « rapports PDF » |

### 6.2 Ports

| Port | Protocole | Exposition | Rôle |
|---|---|---|---|
| **3004** | TCP | publié (hôte) | Client nginx. 3000/3001/3002/3003/3020/3100 sont pris dans la suite |
| 3001 | TCP | interne au réseau compose | API + Socket.io. Jamais publié |
| **7547** | TCP | **publié** | ACS TR-069/CWMP — listener Express **dédié**, pas derrière nginx (Digest + sessions longues) |
| 7548 | TCP | publié (optionnel) | CWMP sur TLS permissif pour CPE anciens |
| **162/udp** | UDP | **publié** | Traps SNMP |
| **514/udp + 514/tcp** | UDP/TCP | **publié** | Syslog équipements |
| 5432 | TCP | interne (exposé en dev seulement) | PostgreSQL |
| **Sortants** | — | via bridge Docker | RouterOS API 8728/8729, SSH 22, SNMP 161, HTTPS SonicOS 443, Connection Request CPE 7547 — **tous à travers le tunnel L2TP** |

> **Publier des ports sur le service `server` est l'unique écart à la topologie de la suite Obli\*** (partout ailleurs seul le client nginx publie). À commenter explicitement dans les compose. L'hôte doit avoir une route vers le subnet du tunnel ; si le tunnel termine ailleurs que sur l'hôte Docker, documenter la route statique. Pour les traps, `network_mode: host` en compose alternatif si l'IP source réelle est nécessaire.

### 6.3 Risques majeurs

| # | Risque | Mitigation |
|---|---|---|
| R1 | **Auto-lockout** : un push coupe le tunnel qui sert à administrer → déplacement sur site | K2 (garde statique) + K1 (dead-man armé sur l'équipement, survit au crash serveur) + backup pré-change obligatoire. **Test destructif au jalon M6.** |
| R2 | **Périmètre TR-069 fantasmé** : RouterOS et SonicWall n'ont pas de client CWMP | Corriger l'attente maintenant, afficher la couverture par marque dans l'UI, `DeviceDriver` comme abstraction principale |
| R3 | **Drift bruyant tue l'outil** : 400 findings/device au premier run → plus personne ne regarde | Critère d'acceptation chiffré à M4 (< 3 findings de bruit), drift en **lecture seule pendant plusieurs semaines** avant d'exposer la remédiation, `normalization_rules` éditables en UI |
| R4 | **Identité par IP de tunnel** : un pool dynamique fait pousser la config du client A chez B | `assertTargetBinding()` sur connexion neuve avant chaque écriture ; `UNIQUE(brand, serial)` |
| R5 | **CHR = SPOF et goulot** : sa panne aveugle tout le parc ; sa reprise déclenche 300 reconnexions simultanées | Token bucket + jitter sur les reconnexions ; une seule socket vers le CHR ; supervision du CHR par un chemin **hors tunnel** ; verdict `CONCENTRATOR_DEGRADED` qui supprime les alertes filles |
| R6 | **RCE via Nunjucks** (`{{x.constructor.constructor(...)()}}`) sur le serveur qui détient les credentials du parc | worker_threads + `resourceLimits` + timeout 5 s + capability `TEMPLATE_WRITE` + contexte JSON pur. **Dès le premier commit, pas après.** |
| R7 | **Volumétrie** : 300 × 8 interfaces × 30 s = **207 M lignes/mois** (~90 lignes/s) ; `cwmp_rpc_log` explose | Partitions dès le jour 1, DROP de partition (jamais DELETE), `rpc_log` désactivé par défaut avec flag par device et rétention 7 j. **Corrigé le 2026-08-29** : cette ligne annonçait « ≈ 20 M lignes/mois », qui est le chiffre d'un poll à **300 s**, pas à 30 s — un intervalle de 5 min et un intervalle de 30 s avaient été mélangés dans la même phrase. Sans conséquence sur le disque (la rétention du brut est de 48 h, donc le volume résident est borné par la rétention et non par le mois) mais il faut concevoir l'insertion pour 90 lignes/s et non 8. Marge réelle de PostgreSQL : ~400×. Détail dans `docs/M3-series-temporelles.md`. Le vrai goulot de M3 est le **syslog**, pas le SNMP. |
| R8 | **Clé de chiffrement dérivée du `SESSION_SECRET`** : une rotation rend illisibles tous les credentials du parc, sans erreur au démarrage | `OBLIWAN_ENCRYPTION_KEY` dédiée + `key_version` + procédure de rotation testée |
| R9 | **L2TP sans IPsec + API 8728 en clair** : credentials et configs sur des réseaux de transit | Exiger L2TP/IPsec sur le CHR, préférer 8729 avec pinning d'empreinte, SSH par clé et jamais par mot de passe |
| R10 | **`/export show-sensitive`** ferait entrer PSK, secrets PPP et clés IPsec dans les snapshots, les diffs et l'UI | `show-sensitive=no` en dur + compte RouterOS de service **privé de la policy `sensitive`** (le flag ne peut pas être retourné) + `CONFIG_READ` distinct de `DEVICE_READ` |
| R11 | **Divergence RouterOS 6/7** (`/system/health` record vs lignes, `/interface/wireless` vs `/interface/wifi`) | Matrice de capacités détectée à la connexion et mise en cache ; les collecteurs interrogent la matrice, jamais un chemin en dur |
| R12 | **`ifIndex` instable** : après reboot, les octets du WAN atterrissent dans la série du LAN, silencieusement | Clé stable `(device_id, if_name)` + vérification de cohérence `ifDescr[if_index]` à chaque poll (coût : 1 varbind/interface, à ne jamais « optimiser ») |
| R13 | **Pas de simulateur CPE fiable** (`genieacs-sim` abandonné) | `fakeCpe.ts` écrit **avant** l'ACS + un Vigor et un Zyxel réels en labo comme condition de clôture de M10 |
| R14 | **Auth Socket.io par `handshake.auth {userId}` fournie par le client** (faiblesse héritée d'Obliguard) | Durcir dès M1 : parser le cookie de session dans `io.use()` |

---

## 7. Décisions — ARBITRÉES le 2026-08-28

| # | Décision retenue | Écart / conséquence |
|---|---|---|
| **A1** | **ACS maison minimal au jalon M10** (recommandation suivie) | Périmètre restreint : Inform, GPV/SPV, Download, Reboot. Aucune dépendance AGPL. |
| **A2** | **Les 4 marques en lecture + ÉCRITURE dès la v1** | ⚠️ **Écart à la recommandation** (qui proposait MikroTik seul en écriture). Conséquences actées : les chemins d'écriture DrayTek/Zyxel/SonicWall remontent de M10/M11 vers M6 ; le **matériel de labo des 4 marques devient bloquant dès M6** et non plus M10 ; la surface de test d'écriture est multipliée par 4. |
| **A3** | `OBLIWAN_ENCRYPTION_KEY` dédiée + colonne `key_version` dès la migration `002` | Recommandation suivie. |
| **A4** | **Renommage propre dans la migration `001`** : `device_groups`, `scope ∈ group\|device`, `@obliwan/shared` | Recommandation suivie. |
| **A5** | `OBLIWAN_ROLE=web\|worker\|all` + leader par advisory lock **dès M1** | Recommandation suivie. HA complète (affinité de session CWMP) hors périmètre v1. |
| **A6** | **Bridge Docker + ports publiés + route hôte vers le subnet de tunnel** | Recommandation suivie. Conséquence assumée : le NAT du bridge masque l'IP source réelle des traps SNMP → l'identification des équipements ne doit **jamais** reposer sur l'IP source d'un trap. Compose `network_mode: host` documenté en repli. |

### 7.1 Formulation initiale des questions (archive)

| # | Question | Options | **Recommandation** |
|---|---|---|---|
| **A1** | **TR-069 : quelle stratégie ?** GenieACS est la seule implémentation sérieuse et il est **AGPL-3.0** (contaminant si intégré au process). | (a) ACS maison minimal ; (b) GenieACS déployé en service séparé, piloté par son NBI REST ; (c) reporter en v2 et n'utiliser que SSH/CLI pour DrayTek/Zyxel. | **(a) au jalon M10**, périmètre volontairement restreint (Inform, GPV/SPV, Download, Reboot). L'option (b) demande une validation juridique et un composant d'exploitation supplémentaire ; l'option (c) prive DrayTek d'un chemin fiable. Décision à prendre **avant M5** car elle conditionne le budget. |
| **A2** | **Périmètre marques de la v1.** Écrire sur 4 marques dès la v1 multiplie le risque et la surface de test. | (a) 4 marques en lecture+écriture ; (b) MikroTik en écriture, les 3 autres en **lecture seule** (inventaire, NCM, drift, SNMP) puis écriture jalon par jalon. | **(b)**. Le parc est majoritairement MikroTik, le tunnel L2TP est déjà là, et un drift en lecture seule sur DrayTek/Zyxel/SonicWall a déjà de la valeur commerciale. L'écriture arrive en M10/M11. |
| **A3** | **Clé de chiffrement des credentials.** Obliguard dérive la clé de `SESSION_SECRET` (sha256, sans sel). Ici la base contient les accès d'administration d'un parc WAN multi-clients. | (a) reprendre le comportement Obliguard ; (b) `OBLIWAN_ENCRYPTION_KEY` dédiée + `key_version` + rotation ; (c) KMS externe. | **(b)**, avec la colonne `key_version` prévue dès la migration `002` pour rendre (c) possible sans migration destructrice. Le coût est nul maintenant, prohibitif après 300 devices provisionnés. |
| **A4** | **Renommage du schéma hérité.** Obliguard traîne `monitor_groups`, `@obliview/shared`, `notification_bindings.scope='monitor'`. | (a) copier tel quel pour minimiser le diff ; (b) renommer proprement dans la migration `001`. | **(b)**. La migration `001` est neuve : c'est le seul moment gratuit. `device_groups`, `scope ∈ group|device`, `@obliwan/shared`. Assumer 2-3 jours de renommage mécanique. |
| **A5** | **Modèle d'exécution : mono-process ou HA ?** L'état de session CWMP vit en mémoire et le poller/leader est unique. | (a) mono-process assumé, documenté ; (b) plusieurs répliques web + un seul « poller » via `OBLIWAN_ROLE` ; (c) HA complète (affinité de session CWMP, état externalisé). | **(b) dès M1** : le flag `OBLIWAN_ROLE=web|worker|all` et le leader par advisory lock coûtent une demi-journée maintenant et évitent une réécriture. **(c) hors périmètre v1** — l'affinité de session CWMP est un chantier à part. |
| **A6** | **Topologie réseau de production.** Le serveur doit à la fois recevoir du CPE (7547, 162/udp, 514/udp) et joindre le parc via le tunnel L2TP. | (a) bridge Docker + ports publiés + route hôte vers le subnet de tunnel ; (b) `network_mode: host` ; (c) tunnel terminé sur l'hôte Docker lui-même. | **(a) par défaut**, avec un compose alternatif `host` documenté **si et seulement si** l'IP source réelle des traps est nécessaire (le NAT du bridge la remplace par la passerelle, et `agent-addr` dans le trap n'est pas fiable). À valider avec l'exploitant **avant M2**, car cela conditionne la joignabilité de tout le parc. |

---

## 8. Décisions du 2026-08-28 (suite) — Import/export, secrets, validation sans labo

### 8.1 Import/export : l'import EST un plan, le bundle est versionné et diffable

Fusion demandée des modèles A et B. Un seul concept d'écriture dans tout le produit : **rien ne modifie
l'instance sans un plan revu**. Un import de bundle et un changement de config d'équipement passent par
le même écran, le même RBAC et le même audit.

**Format du bundle** — archive `.tar.gz` d'une arborescence YAML, un fichier par entité :

```
meta.yaml                    schema_version, instance_id, exported_at, sections[], content_hash
sites/<uuid>.yaml
device-groups/<uuid>.yaml
templates/<uuid>.yaml
templates/<uuid>/revisions/<n>.yaml
variables/<uuid>.yaml
teams/<uuid>.yaml
notification-channels/<uuid>.yaml
settings/<scope>-<id>.yaml
```

Contraintes de format, toutes au service du diff :
- **Clés triées, sérialisation canonique, LF.** Deux exports du même état produisent deux archives
  identiques octet pour octet. Sans ça, le diff est inexploitable.
- **UUID stable par entité**, jamais l'id Postgres. Un bundle survit à la réindexation et voyage entre
  instances.
- **Aucun timestamp volatil** dans les fichiers d'entité (`updated_at` exclu de la sérialisation) —
  sinon tout diffère à chaque export, exactement le problème du drift textuel (D1).
- `meta.yaml` porte un `content_hash` de l'arborescence : altérer un bundle se voit.

Le format est un objectif secondaire assumé : il rend l'export **versionnable dans git** et donc
compatible avec le « réseau comme du code » du backlog, sans que Postgres cesse d'être l'autorité.

**Versionning côté instance** — table `export_bundles` : uuid, tenant, auteur, sections, nombre d'entités,
`content_hash`, taille, date, rétention. Chaque import enregistre le bundle d'origine. On peut donc
répondre à « qu'est-ce qui a changé depuis l'export de mardi ».

**Trois diffs, un seul moteur, un seul composant `DiffViewer`** :

| Diff | Usage |
|---|---|
| bundle ↔ instance courante | **c'est le plan d'import** |
| bundle ↔ bundle | comparer deux dates, ou deux instances |
| instance ↔ instance | comparer prod et préprod via l'API |

**Workflow** :

```
POST /api/import/plan   (bundle)
  -> { planId, baseHash, ops: [
       { create,   site,   "Lyon-Nord" },
       { update,   group,  "Clients", diff: [...] },
       { skip,     team,   "NOC", reason: "identique" },
       { conflict, team,   "Support", reason: "nom déjà pris" },
       { blocked,  device, "CPE-42",  missing: "site Lyon-Sud" } ] }

POST /api/import/plan/:id/apply
  -> 409 si baseHash a bougé depuis le calcul (plan périmé, comme les plans de config)
  -> UNE transaction, rollback complet à la moindre erreur
```

Règles : le dry-run n'est pas une option mais **l'étape 1 obligatoire** ; ordre topologique déduit du
manifeste ; un import référençant une entité absente est `blocked`, jamais appliqué à moitié ;
un `schema_version` supérieur à ce que l'instance comprend est refusé, un inférieur est migré.

### 8.2 Les secrets : la plateforme est le coffre, et elle rend les configs complètes

Exigence utilisateur : **ObliWAN détient les secrets et génère les configurations complètes.** Les secrets
ne sont donc jamais une variable à renseigner dans un template par l'opérateur — ils vivent dans le coffre
(`secretVault`, AES-256-GCM, `OBLIWAN_ENCRYPTION_KEY` + `key_version`, arbitrage A3) et le moteur de rendu
les injecte au moment de produire l'artefact envoyé à l'équipement.

**Conséquence non négociable — la config rendue existe en deux versions :**

| Version | Contient les secrets | Où elle a le droit d'exister |
|---|---|---|
| **complète** | oui | **en mémoire uniquement**, sur le chemin coffre → équipement |
| **caviardée** | non | partout ailleurs : snapshot, diff, plan, UI, export, audit, logs |

Le plan affiché à l'opérateur, le diff, le snapshot stocké et le `command_audit` ne voient **que** la version
caviardée. C'est le prolongement direct du risque R10 : il ne sert à rien d'interdire
`/export show-sensitive` côté MikroTik si notre propre moteur de rendu écrit les mêmes secrets en base.
Corollaire : le rendu ne doit jamais être mis en cache sur disque, et un secret ne doit jamais transiter
par une valeur de `PlanOp`.

**Dans le bundle** : références de secrets seulement (uuid, label, transport concerné), jamais les valeurs.
À l'import, les équipements arrivent en état `credentials_missing` et sont **non-actionnables** — aucun plan
ne peut les cibler tant que le coffre n'est pas renseigné. Un export chiffré par phrase de passe
(capacité `SECRET_READ` + phrase saisie, chiffrement distinct de `OBLIWAN_ENCRYPTION_KEY`) reste disponible
pour une migration d'instance, mais ce n'est pas le chemin par défaut.

### 8.3 Validation sans labo : le filet remplace le matériel

Arbitrage utilisateur : **pas de matériel de labo DrayTek/Zyxel/SonicWall.** La validation est empirique —
la première poussée réelle est le test. C'est acceptable à une condition : que la reprise soit réelle.
L'effort se déplace du labo vers le filet, il ne disparaît pas.

**Le niveau de sécurité dépend de la marque, et l'UI doit l'afficher — pas le masquer :**

| Niveau | Mécanisme | Marques |
|---|---|---|
| **ARMÉ** | dead-man *sur l'équipement* : `/system/scheduler start-time=startup` + script de restauration. Le routeur se répare seul, même si le serveur ObliWAN meurt. | MikroTik |
| **ARMÉ PAR TIERS** | le dead-man est porté par un **MikroTik co-localisé sur le même site**, joint par le tunnel L2TP que le changement ne touche pas. Un équipement d'une marque répare celui d'une autre. | DrayTek / Zyxel / SonicWall **avec** MikroTik sur site |
| **DÉGRADÉ** | détection sans reprise : on sait que le CPE ne réinforme plus, on ne peut rien y faire à distance. **Confirmation explicite exigée avant tout apply.** | les mêmes, **sans** MikroTik sur site |

Le niveau est calculé par device et affiché sur l'écran de rayon d'impact **avant** le lancement, jamais
après. Un rollout par vagues (K3) qui mélange des devices ARMÉ et DÉGRADÉ traite les DÉGRADÉ en dernier.

**Mémoire empirique du risque — extension de K2.** Chaque application enregistre
`(type d'opération, marque, modèle, version de firmware) → issue` (succès / rollback / perte de contact).
Au-delà d'un seuil d'observations, le planner remonte l'historique **dans le plan, avant l'apply** :
« cette opération a provoqué un rollback 3 fois sur 11 sur Vigor 2927 en firmware 4.4.x ».
C'est le laboratoire qu'on n'a pas, construit par le parc lui-même — et ça n'a de valeur que parce que
le corpus est multi-marque et multi-client, ce qu'un éditeur constructeur ne peut pas produire.
Table `apply_outcomes` ; alimentée dès M6, exploitée dans le planner à partir d'un volume utile.

> Limite énoncée honnêtement : tant que le corpus est vide, cette mémoire ne protège de rien. Les premières
> poussées DrayTek/Zyxel/SonicWall sont, elles, réellement les premières — d'où le niveau de filet affiché
> et la confirmation explicite en mode DÉGRADÉ.

---

### 8.4 Netwatch : surveiller le service du CLIENT, pas seulement notre chemin d'administration

*Proposé par Vaintor le 2026-08-29. Ferme une limite du Management-Path Guard énoncée le même jour.*

**Le trou.** K2 fait circuler un paquet synthétique concentrateur → adresse de management sur le NCM cible.
Il protège donc **notre** chemin d'administration. Un changement qui casse la production du client sans
toucher au management — une règle NAT qui tue le flux VoIP, une route qui détourne le trafic de l'ERP —
passe le guard sans rien déclencher. Ce n'est pas un défaut du guard, c'est son périmètre.

**Le mécanisme.** `/tool/netwatch` sur l'équipement, avec des cibles définies par variable de template.
Il a la propriété qui compte, la même que le dead-man de K1 : **il tourne sur l'équipement**. Il continue
de surveiller si le serveur ObliWAN est mort, si le réseau de management est coupé, si le process qui a
lancé l'apply n'existe plus. Son `on-down` peut donc appeler le **même script `obliwan-rollback`** que
le dead-man temporisé. On ne se contente pas de détecter la casse du service client : on la répare.

**Deux familles de cibles**, toutes deux résolues par le résolveur de variables de M5 (héritage
global → tenant → groupe → device, donc un site peut surcharger avec ses propres hôtes critiques) :

| Famille | Exemples | Ce qu'elle prouve |
|---|---|---|
| **Cibles de site** | l'ERP du client, son SBC VoIP, son NAS, sa passerelle | le service pour lequel le site existe fonctionne encore |
| **Cibles d'infrastructure** | points d'ancrage globaux de la suite Obli\*, résolveurs publics | la sortie internet du site est vivante |

**Trois gardes sans lesquelles ce mécanisme fait plus de mal que de bien :**

1. **Ligne de base avant armement.** Une cible n'est retenue que si elle était **UP au moment de l'armement**.
   Sans ça, un ERP déjà en panne pour ses propres raisons fait échouer un changement sain, et on s'accuse
   d'une casse qu'on n'a pas produite. Même piège que la vérification d'armement du dead-man.
2. **Quorum et hystérésis, jamais une cible unique.** Un rollback déclenché par un faux positif annule un
   bon changement et fait perdre la confiance dans tout le dispositif. Plusieurs cibles, un seuil, et les
   compteurs d'échec de netwatch (RouterOS 7) plutôt qu'un seul paquet perdu.
3. **Attention au serpent qui se mord la queue.** Un changement qui bloque légitimement l'ICMP sortant fait
   tomber le netwatch et déclenche un rollback d'un changement correct. Les cibles doivent être joignables
   par des chemins que le changement **n'est pas censé toucher**, et un plan qui touche au filtrage ICMP
   doit être traité à part.

**Portée réelle par marque — à ne pas surestimer.** `netwatch` est MikroTik. DrayTek, Zyxel et SonicWall
ont des sondes analogues, mais **aucune ne sait exécuter un script de restauration arbitraire** : chez eux
ça reste de la détection. En revanche le mécanisme renforce nettement `ARMED_BY_PEER` — un MikroTik
co-localisé peut surveiller le côté LAN du DrayTek voisin et déclencher la reprise à sa place.

**Divergence RouterOS 6 / 7** (risque R11) : la v7 apporte les sondes `http-get`/`tcp-conn` et les
seuils ; la v6 est en ICMP simple. Le mécanisme doit passer par la **matrice de capacités détectée à la
connexion** (écrite en M2), jamais par un chemin en dur.

**Où ça atterrit.** Post-conditions et soak de K1 (M6) ; portes de santé des vagues canari de K3 (M7),
qui gagnent enfin un signal côté service et non seulement côté management.

---

### 8.5 Le concentrateur : rayon d'impact global et interlock de sous-arbre

*Arbitré avec Vaintor le 2026-08-29, après deux corrections d'analyse de ma part.*

**Correction 1 — le nom.** `role='chr'` désigne un PRODUIT MikroTik (Cloud Hosted Router), pas une
fonction : le jour où le concentrateur est un RB5009 ou une VM x86, le champ ment. Le code était déjà
incohérent avec lui-même (`concentrator_id`, `isConcentrator`, « is not a concentrator » dans les
messages d'erreur, et seule la valeur d'énum disant `chr`).
**Décision : `DEVICE_ROLES = ['cpe', 'concentrator']`**, aligné sur le terme consacré du L2TP (*LAC*,
L2TP Access Concentrator) et sur le nommage déjà présent. La contrainte `CHECK` de la migration `002`
est éditée en place — elle n'a jamais tourné hors bases jetables, c'est le dernier moment gratuit.

**Correction 2 — le multi-concentrateur était déjà géré**, contrairement à ce que j'avais affirmé :
`pppPresence.startAll()` itère sur tous les concentrateurs actifs et ouvre une surveillance par
concentrateur, et `CONCENTRATOR_DEGRADED` est évalué **par device via son parent**, pas globalement.

**Topologie arbitrée :**

| Question | Réponse |
|---|---|
| Un site peut-il joindre ObliWAN par plusieurs concentrateurs ? | **Non.** Un concentrateur par site, pas de bascule. `devices.concentrator_id` reste une FK simple. |
| Comment récupère-t-on un concentrateur rendu injoignable ? | **Console de l'hyperviseur / snapshot de VM.** Reprise en minutes, sans déplacement. |

**Ce que ça implique, et qui n'est pas dans la table 8.3 :**

1. **Le concentrateur est `ARMED`, pas `DEGRADED`.** C'est du RouterOS : il porte son propre dead-man.
   Ce n'est donc pas le filet qui lui manque.
2. **Il ne peut JAMAIS être `ARMED_BY_PEER`** — ce niveau repose sur un MikroTik co-localisé joint *par
   le tunnel*, et le concentrateur est précisément ce qui porte les tunnels. Il est le pair de tout le
   monde, personne n'est le sien. Un calcul de niveau de sûreté qui lui attribuerait `ARMED_BY_PEER`
   est un bug, pas une approximation.
3. **Son rayon d'impact est le sous-arbre entier**, pas un site. C'est le seul équipement du parc dont
   une erreur se compte en clients et non en client.
4. **La panne d'un concentrateur emporte aussi le filet de ses enfants non-MikroTik** : leur dead-man
   `ARMED_BY_PEER` se déclenche par le tunnel, donc par lui.

**L'INTERLOCK DE SOUS-ARBRE — la garde que cette conversation a fait apparaître.**

Si un apply sur le concentrateur le rend injoignable pendant que N devices enfants sont **en soak avec
leur dead-man armé**, ObliWAN ne peut désarmer aucun d'eux. Au bout du délai, N équipements annulent
seuls des changements qui étaient bons. Un incident sur un équipement en produit N+1.

Règle : **un job visant un concentrateur exige qu'aucun job ne soit en vol sur ses enfants, et bloque la
mise en file de nouveaux jobs enfants pendant toute sa durée** (armement, apply, soak, désarmement).
Réciproquement, un job enfant ne démarre pas si un job concentrateur est actif sur son parent.
C'est l'analogue à l'échelle du sous-arbre de l'index unique « un job en vol par device » de la
migration `009` — et il doit être aussi structurel que lui, pas laissé à une vérification applicative.

**Décision d'exploitation :** écrire sur un concentrateur reste **autorisé**, parce que la reprise par
console d'hyperviseur borne le risque à quelques minutes sans déplacement. Mais la confirmation doit être
d'une autre nature que celle d'un CPE : l'écran annonce le nombre de sites qui perdront le management,
exige l'interlock vérifié, et rappelle que la reprise passera par la console de la VM.

---

## 9. Hors périmètre implémentation — pris en charge par Vaintor

Ces points sont **connus, tracés, et volontairement non traités** par l'implémentation. Ils n'ont pas à
remonter comme dette à chaque jalon.

| Sujet | État |
|---|---|
| **Dépôt git** | **Créé le 2026-08-29 : `github.com/MeeJay/Obliwan`, public, branche par défaut `main`** (casse exacte confirmée via l'API GitHub — les scripts la respectent). Le dépôt est encore VIDE : `install.sh` et le README pointent sur `raw.githubusercontent.com/MeeJay/Obliwan/main/…`, qui renverra 404 tant que rien n'est poussé. `000-RegularUpdate.bat` et `001-PromoteToProd.bat` n'utilisent que des commandes git relatives (`origin`, `dev`, `main`) : ils fonctionneront dès que le dépôt local sera initialisé et le remote configuré. **Le `git init` local et le premier push restent à la main de Vaintor.** |
| **Identité visuelle** (favicon, wordmark clair/sombre, couleur de marque) | À la charge de Vaintor. En attendant, `client/public/{favicon,logo,logo-daylight}.svg` gardent l'artwork Obliguard et `Header.tsx` porte `#4e9cff` — **placeholders assumés**, ne pas les signaler comme bug. |
| **`.gitignore` : `*.bat` et `CLAUDE.md` exclus** | **Arbitré : on garde tel quel.** Les deux `.bat` codent en dur l'hôte de build interne `10.0.0.152`. Question close, ne plus la rouvrir. |
| **Traduction des 16 locales** | Devient le **jalon M13**, pas de la dette courante. |
| **Terminaison TLS** | Assurée par **Oblihub** (`github.com/MeeJay/Oblihub`), le reverse proxy de la suite. Arbitré le 2026-08-29. Conséquence à connaître et à ne pas « corriger » : depuis le durcissement du cookie de session, une instance en `NODE_ENV=production` **sans TLS devant** répond 200 au login mais ne stocke aucun cookie, donc 401 à la requête suivante. Ce n'est pas un bug, c'est la protection qui fonctionne — le déploiement passe obligatoirement par Oblihub. |
| **Index unique sur `users.email`** | Arbitré le 2026-08-29 : **on garde le comportement fail-closed.** Monter une instance qui porte déjà deux comptes partageant une adresse fait ÉCHOUER la migration 004, en nommant les lignes fautives et en imprimant le SQL de correction. Préféré à un index créé en silence ou à un compte écrasé. |

---

## 10. Features arbitrées le 2026-08-30 — après livraison de M1-M12

Cinq features demandées par Vaintor après que le produit complet a été construit et audité trois fois.
Elles ne viennent pas d'un brainstorm : quatre sortent de ce que le code a appris pendant sa
construction, la cinquième est une reprise du backlog que l'usage a rendue prioritaire.

### F1 — La justification d'une dérive acceptée

K6 répond « **qui** a changé ça ». La question suivante est toujours « **est-ce que c'était voulu ?** »
et le produit n'a nulle part où ranger la réponse : un finding marqué ignoré disparaît, et trois mois
plus tard personne ne sait pourquoi.

Ajouter au marquage d'exception une **justification obligatoire** et une **date de revue**. La liste de
dérives cesse d'être une corvée et devient la base de connaissance du parc : « cette règle NAT existe
pour l'ERP legacy du client, revue le 12/03 ».

Coût quasi nul : les findings ignorés sont **déjà conservés** en base (décision M4), il manque deux
colonnes, une garde et un écran. Meilleur rapport valeur/effort du lot.

### F2 — L'attestation de conformité signée

Tout existe : snapshots horodatés, `ncm_hash`, `audit_log` chaîné par hash, `apply_outcomes`.
Ce qui manque est l'**assemblage en preuve opposable** : « l'équipement D était en configuration C du
12/01 au 03/04, voici la chaîne de hash qui l'établit ».

C'est ce qu'un MSP doit fournir à l'assureur cyber de son client. Ce n'est pas un moteur, c'est un
rapport — et c'est un argument commercial qu'aucun concurrent du segment ne peut sortir, faute d'avoir
la chaîne de hash en dessous.

### F3 — Le mode intervention

Aujourd'hui le produit découvre le travail d'un technicien **après coup**, par la dérive. La mécanique
est forensique, jamais coopérative.

Un mode qui **encadre** un geste humain : snapshot avant, netwatch armé (§8.4), fenêtre déclarée,
snapshot après, diff proposé à la promotion en template ou en exception. Le travail légitime devient une
contribution au modèle au lieu de bruit à trier — et c'est la principale source de faux positifs de M4
qui disparaît. Toutes les briques existent.

### F4 — La corrélation changement → télémétrie, une semaine après

Les portes de santé de K3 mesurent **pendant** la vague, sur une fenêtre de soak de cinq minutes.
**Rien ne regarde huit jours plus tard**, alors que les séries SNMP sont juste à côté.

« Depuis ce changement, les erreurs WAN de ce site ont été multipliées par 40 » est une question que le
produit peut répondre et qu'il ne pose jamais. C'est la moitié manquante des portes de santé : une
dégradation lente est invisible dans une fenêtre de cinq minutes.

### F5 — Météo Opérateurs *(sortie du backlog, priorisée par Vaintor)*

**Objectif** : détecter un incident opérateur **très tôt**, par corrélation à l'échelle du parc, avant
que les clients n'appellent.

Direction technique donnée par Vaintor :
1. savoir si un routeur **sort en LTE ou par le port désigné comme WAN** ;
2. récupérer l'**IP publique** du routeur, **qui peut être derrière un NAT**.

**Fondations déjà présentes, à ne pas réécrire :**

| Brique | Où elle est | Ce qu'elle donne |
|---|---|---|
| `devices.wan_public_ip` | écrit par `applySessionUp` depuis le `caller-id` PPP | l'IP publique **vue par le concentrateur**, donc valide même derrière NAT — c'est une observation depuis l'extérieur, pas une déclaration du routeur |
| `publicPathChanged` | calculé dans `applySessionUp` | une session qui revient d'une **autre adresse publique** = bascule WAN silencieuse, déjà détectée et non exploitée |
| `snmp_interfaces.if_type` | M3 | identification d'une interface LTE |
| `ppp_sessions` | M2 | historique des flaps, par site et par horodatage |
| `reachability_verdicts` | K7 | `WAN_FAILOVER` existe déjà comme verdict |

**Ce qui manque** : le chemin de sortie actif (route par défaut RouterOS, `/interface/lte`), l'enrichissement
ASN/région de l'IP publique, et surtout **l'agrégation** — « 12 sites sur l'ASN X ont basculé en LTE en
10 minutes » est un incident opérateur, alors que chaque site pris isolément n'est qu'un flap.

**Le piège à éviter** : ne jamais conclure « incident opérateur » sur un seul site. C'est une feature de
CORRÉLATION, et son seuil de déclenchement doit être un quorum, pas un événement. Un faux positif ici
envoie un MSP appeler un opérateur pour rien, et le deuxième suffit à ce que plus personne n'y croie.

---

## 11. Features F6-F8 — arbitrées le 2026-08-30, après les quatre audits

### F6 — Détection d'équipement remplacé

`assertTargetBinding()` vérifie déjà l'identité **avant chaque écriture** — `ppp_username` +
`system_identity` + `serial` (risque R4). Mais rien ne surveillait ce triplet **dans le temps**, et
la donnée était collectée à chaque connexion puis jetée.

Un `serial` qui change, c'est un boîtier remplacé : RMA, panne, vol, ou un technicien qui a swappé du
matériel sans le dire. Sans cette feature, le jour où un site revient avec un boîtier vierge, la dérive
explose et personne ne sait pourquoi — alors que le produit avait l'information une seconde avant.

**Deux règles qui font la différence entre un signal et du bruit :**
- un `serial` **vide ou placeholder n'est pas un changement de serial**. Un CHR virtuel n'en a pas, et
  un équipement qui répond mal une fois ne doit pas déclencher un faux remplacement. L'attribut non
  répondu est reporté depuis la référence, jamais comparé.
- un remplacement **invalide** ce qui reposait sur l'ancien boîtier — le dernier snapshot cesse d'être
  une référence de confiance. C'est **signalé**, jamais corrigé tout seul : rien n'est supprimé, retiré
  ni clos automatiquement.

### F7 — SLA calculé

Un MSP vend « 99,5 % » et le prouve avec un tableur. Les données sont déjà là : `ppp_sessions` avec
`disconnect_reason`, les verdicts K7, les séries SNMP.

**Ce qu'aucun concurrent ne peut faire** : K7 distingue « le site était mort » de « **nous** avions perdu
le tunnel ». Une indisponibilité de notre plan de management n'est pas une indisponibilité du client, et
ne doit jamais lui être comptée. `CONCENTRATOR_DEGRADED` et `TUNNEL_DOWN_SITE_UP` sont exclus, et le
rapport **dit combien de temps a été exclu et pourquoi** — un SLA dont on ne peut pas auditer les
exclusions ne vaut pas mieux qu'un tableur.

Règle héritée du défaut trouvé sur l'attestation F2 : **une période sans aucune donnée n'est pas 100 %
de disponibilité**, c'est « pas de mesure ».

### F8 — Inventaire de fin de vie

Croise `devices.model` et `devices.os_version` (collectés depuis M2) avec les dates de fin de support
constructeur. Seule feature du produit qui **génère du chiffre d'affaires** au lieu d'éviter des coûts :
c'est la liste de renouvellement d'un MSP, sortie automatiquement.

Le catalogue est de la **donnée, pas du code** : une table importable, avec une **source et une date par
entrée**. Un commercial qui annonce à un client que son matériel est obsolète doit pouvoir citer le
constructeur. Et « fin de support inconnue » est une réponse honnête — « supporté » pour un modèle absent
du catalogue ne l'est pas.

Ne couvre PAS le volet CVE du backlog : il demande un catalogue d'avis à maintenir.

### 11.1 Le contrôle avant rendu — ce qui a changé dans la méthode

Quatre audits ont trouvé **24 findings critiques**, toutes sur du code qui compilait, passait ses tests
et avait l'air fini. Elles ne sont pas variées : elles se répartissent sur **dix motifs récurrents**.

À partir de F6, ces dix motifs sont un **contrôle obligatoire avant rendu**, et le rapport d'agent doit
les traiter un par un **avec leur preuve** — un grep et sa sortie, une requête SQL et son résultat, un
test et son verdict. Un point sans preuve est un point non fait.

| # | Motif | Où il a mordu |
|---|---|---|
| 1 | Une garde ne couvre pas toutes ses branches | `session.authenticated` sur 1 branche CWMP sur 4 |
| 2 | Une fonction énonce une règle et n'a **aucun appelant** | 7 cas, dont `auditedCommand` et `assertVaultUsable` |
| 3 | Identification par IP source | fuite d'un secret du coffre par POST à corps vide |
| 4 | Lecture non scopée par tenant | doctrine de normalisation vide hors tenant maître |
| 5 | Paramètre piloté par l'appelant qui change un verdict | `maxGapDays` → 365 jours sans observation = « continuous » |
| 6 | Valeur non échappée envoyée à un équipement | injection de `/user add name=bd group=full` |
| 7 | `varchar` plus étroit que son `CHECK` | `role` en `varchar(8)` contre `concentrator` |
| 8 | Index unique non partiel sur colonne nullable | settings globaux en doublons sous `NULLS DISTINCT` |
| 9 | Secret dans un log, un jsonb, une API, un export | mots de passe L2TP servis à l'écran de quarantaine |
| 10 | Écriture vers un équipement hors `change_jobs` | décision D3 |

**Effet observé dès la première application** (F6) : l'agent a inspecté la pile de middlewares Express
*à l'exécution* pour prouver que les gardes sont en amont du branchement, listé chaque requête avec son
scope, et **trouvé deux vocabulaires à zéro appelant qu'il a câblés au lieu de les laisser** — le motif
n° 2, attrapé avant l'audit au lieu de l'être après.
