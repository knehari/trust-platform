> Recovery execution update: see [EXECUTION_STATUS.md](EXECUTION_STATUS.md). The original PR #42 snapshot below is preserved as historical evidence; it is not the current delivery status.

## Current stacked Draft increments (20 October 2026)

The table below records selected unmerged laboratory increments through Draft
#70; the dated continuation notes cover later Drafts through #106. The
historical PR #42 matrix remains the reference for what was observed on PR
#41. None of these increments has landed on `main`.

**19 October 2026 continuation:** Drafts #71–#93 extend the read-only management application with CA selection/error handling, no-store responses, scoped certificate and audit detail routes, metadata modals, independent list loading/retry and filters over already loaded rows. Draft #93 adds a local preflight that detects an older API binary missing the detail routes. All seven checks passed on its exact head `bb6c6b569bad5ec3134aa54f967fbefd2a4872c2`, including [Compose smoke](https://github.com/knehari/trust-platform/actions/runs/39173002831) and [Rust/schema](https://github.com/knehari/trust-platform/actions/runs/39173002823). The filters do not search unseen pages; the modals display database metadata, not certificate validity or independent audit integrity. The stack is still Draft-only, read-only and G0 blocked, with no human IAM or HTTP issuance.

**20 October 2026 continuation:** Stacked Drafts #95–#106 add exact ID lookups through CA-scoped detail routes, guard returned identities, deduplicate overlapping pages, separate and cancel history pagination, display validated diagnostic request IDs, and check all three detail routes before local testing. Exact request/event lookups were exercised against records beyond the first 100 in a disposable browser fixture. [Draft #106](https://github.com/knehari/trust-platform/pull/106) passed all seven GitHub checks at `64d6bce4de728cfd792507e97b7fdf25f0e9b531` after the account-side runner scheduling block lifted. The one-CA browser fixture did not exercise a CA beyond the first page or an initially failed inventory with a successful direct CA lookup. Older billing-blocked PR checks remain historical failures until individually rerun. No human IAM, policy-controlled HTTP issuance, production deployment or G0 clearance is implied.

**20 October 2026 console continuation:** Stacked Drafts [#115](https://github.com/knehari/trust-platform/pull/115)–[#119](https://github.com/knehari/trust-platform/pull/119) normalize pasted UUID forms for exact lookups, sort only the certificate and audit rows loaded in the browser, copy explicitly allowlisted metadata JSON from detail dialogs, and preserve a section/CA link through laboratory OIDC login. A linked off-page CA is fetched by exact ID and remains subject to the API's reader grants; an unavailable CA falls back to an authorized one with a visible notice. The local frontend build and 24 tests passed, and the link, denied-CA fallback, sorting, exact lookup and modal were exercised against the disposable browser fixture. These are read-only usability increments; local sorting does not search or order unseen pages, clipboard JSON is not an auditor export, and the URL does not grant access. Drafts are unmerged and remain subject to independent review and G0.

| Capability | Current demonstrated scope | Remaining boundary |
|---|---|---|
| C-01 policy gate serialization | #46: deterministic two-transaction regression and migration 0011; exact-head race and Rust/schema CI passed | General populated upgrades and independent review remain |
| Crypto capability registry | #48: explicit laboratory capability routing and RSA-PSS discovery correction; exact-head CI passed | No HSM or PQC implementation/qualification |
| Read-only management API | #50–#52: OIDC token validation, CA-scoped PostgreSQL views, bounded query concurrency; exact-head CI passed | Test IdP, `NoTls` laboratory DB, no issuance or Core invocation |
| React console and Compose lab | #51–#53: real read-only API/DB views, PKCE test login and container smoke; exact-head CI passed | No human IAM, certificate issuance or deployment assurance |
| Request diagnostics | #54: request correlation ID and secret-safe JSON completion log; exact-head CI passed | Not a durable signed security audit |
| Locked source dependency inventory | #55: 318 Cargo/npm package records in SPDX 2.3 JSON; local official-schema validation, negative drift test and exact-head SBOM CI passed | Lockfile inventory only; image SBOM, license review, provenance and other CI checks remain |
| Server-owned CA reader grants | Draft #56: migration 0013 intersects signed token scope with issuer/subject/CA grants; old-behavior regression failed and exact-head API/SQL/Compose CI passed | Codex Security diff scan found no reportable issue; independent human review, issuance authorization, human IAM and tenant-wide ABAC remain open |
| OIDC signing-key rotation | Draft #57: unknown key ID triggers rate-limited JWKS refresh; stale cache must refresh before accepting a token; removed keys are replaced; seven exact-head CI checks passed | Laboratory test issuer only; no production IAM or deployment assurance |
| Management SQL deadline | Draft #58: PostgreSQL cancels a read running longer than three seconds and releases its bounded request permit; six exact-head CI checks passed | Local/disposable database only; no production connection pool or capacity qualification |
| Management readiness | Draft #59: anonymous status-only endpoint checks restricted PostgreSQL role, four read views and request slot; Compose waits for it; six exact-head CI checks passed | Lab health signal only; no human IAM, production deployment or CA signing readiness |
| Management HTTP data capacity | Draft #60: 16 in-flight data requests maximum, acquired before token validation and held through DB completion; six exact-head CI checks passed | Process-local concurrency only; no per-client rate limit, production capacity benchmark or pool |
| Populated management migration | Draft #61: 0012–0013 applied after seeded 0011 database; CA, request, certificate metadata and audit rows preserved; local and exact-head schema CI passed | Disposable fixture only; no online migration/rollback |
| Management logical restore | Drafts #62–#65: disposable `pg_dump`/`pg_restore` preserves fixture rows and reader restrictions, refuses a missing reader role in a fresh cluster, rolls back a failed restore, and verifies a real restricted login; exact-head CI passed | Cluster-global roles are provisioned separately; no CA keys, PITR, RTO/RPO or production backup |
| Interrupted management migration | Draft #66: injected 0013 DDL failure rolls back that migration while 0012 and populated data survive; manual retry passes in exact-head CI | Direct SQL rehearsal only; no automatic deployed-data recovery |
| Ledgered management migration | Draft #67: 0012–0013 runner serializes operators, records source checksums transactionally, skips repeat runs and refuses drift or untracked schema; six exact-head CI checks passed | Laboratory `NoTls` operator only; no production migration service or automatic adoption |
| Ledgered restore continuity | Draft #68: a disposable restore compares full ledger rows and the runner skips both migrations afterward; local PostgreSQL 16.15 and [code-commit CI](https://github.com/knehari/trust-platform/actions/runs/39137372438) passed | Independent review remains; no tamper-evident audit, protected backup or production recovery |
| Management history paging | Draft #69: the read-only API and console page CA-scoped certificate and audit metadata past 100 rows; a restricted PostgreSQL 16.15 login returned 100+2 rows for each route without duplicates; six exact-head CI workflows passed | No snapshot across concurrent writes, production query benchmark or issuance path |
| Management CA inventory paging | Draft #70: CA list and console page beyond 100 scoped authorities, ordered by display name and CA ID; a restricted login reads 100+2 rows and excludes a token-listed CA without a server grant | CI tracked on the Draft PR; no snapshot across concurrent writes or production query benchmark |

# Matrice des fonctionnalités

> Audit du 17 octobre 2026. `main`: `20e977a695481c54c1775a97ae0f1fc427159e43`. État de développement de référence: PR #41, `6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd`. Aucun changement fonctionnel ni fusion.

## Convention de preuve

- **Implémenté** : comportement limité et nommé, confirmé par source et exécution CI inspectée. Ne signifie ni fonctionnalité produit terminée, ni production.
- **Partiel** : chemin réel existant, mais critères produit ou intégration manquants.
- **Prototype** : contrat, prédicat, mock, démonstrateur ou composition sur entrées prévalidées.
- **Non implémenté** : aucun chemin opérationnel trouvé dans les arbres examinés; des enums/docs peuvent exister.
- **Non vérifié** : preuve absente ou environnement indisponible; ne vaut pas échec.

Toutes les capacités applicatives sont absentes de `main`, qui contient seulement la baseline documentaire. Le tableau décrit #41 sauf mention contraire. **Aucune ligne ne déclare une fonctionnalité produit « terminée ».**

Preuves: **S** source inspectée; **C41** logs CI du run [39017432908](https://github.com/knehari/trust-platform/actions/runs/39017432908) inspectés, arbre testé identique à #41; **L** exécution locale de cet audit. Aucun test Rust/PostgreSQL local n’a pu être exécuté. Les tests présents seuls ne suffisent pas à C41.

## Noyau, données et gouvernance

| Fonctionnalité / portée précise | Statut | Code / preuve | Limite et acceptation restante |
|---|---|---|---|
| Workspace 3 crates; build all-features, fmt, Clippy | **Implémenté** | [Cargo.toml](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/Cargo.toml) et workflow Rust CI; C41 | CI Linux; MSRV 1.82, matrice sans features, Windows/macOS non vérifiés |
| Politique default-deny, identité/zone DNS/SAN/validité | **Implémenté** | [crates/pki-policy/src/lib.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-policy/src/lib.rs); C41 | Identité de confiance injectée, pas authentification |
| CSR P256 SHA256: DER canonique, PoP, sujet, 16 KiB | **Implémenté** | [crates/pki-core/src/csr.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/csr.rs); C41 | Profil limité; fuzzing et corpus indépendant à étendre |
| CSR RSA PKCS1 SHA256/384/512 et taille observée | **Implémenté** | [crates/pki-core/src/csr.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/csr.rs); C41 | Interop CI 2048/256, 3072/384, 4096/512; pas couverture cartésienne exhaustive |
| Binding autorisation typée ↔ CSR exact | **Implémenté** | [crates/pki-core/src/native_typed_csr_binding.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/native_typed_csr_binding.rs); C41 | P256/RSA seulement; autorisation en mémoire |
| CA/leaf X.509 P256, SKI/AKI, policies, SAN/EKU | **Partiel** | [crates/pki-core/src/lab_ca.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/lab_ca.rs); C41 | Clés éphémères, OID de fixture; pas CA exploitable |
| RSA-PSS root/leaf et vérification indépendante | **Partiel** | [crates/pki-core/src/rsa_pss_x509_lab.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/rsa_pss_x509_lab.rs); C41 | SHA384/512 via grant typé; pas pipeline durable pour toutes suites |
| RSA PKCS1 root X.509 | **Partiel** | [crates/pki-core/src/rsa_pkcs1_x509_lab.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/rsa_pkcs1_x509_lab.rs); C41 | Pas de leaf native PKCS1 opérationnelle démontrée |
| P384/P521/Ed25519/Ed448 roots et leaf TLS | **Partiel** | [crates/pki-core/src/openssl_classical_server_lab.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/openssl_classical_server_lab.rs); C41 | Vrai OpenSSL Unix, pas provider Rust natif ni HSM; CSR correspondants non implémentés |
| Journal PostgreSQL, serial issuer-scoped, idempotence | **Implémenté** | [migrations/0002_transactional_issuance.sql](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/migrations/0002_transactional_issuance.sql); C41 schema | Portée lab; rôles runtime, upgrades et HA non validés |
| Intent durable, TBS hash, at-most-once local et résultat vérifié | **Partiel** | [crates/pki-core/src/orchestrator.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/orchestrator.rs); C41 | Plans et interfaces de confiance; pas transaction atomique avec signer |
| Adaptateur PostgreSQL P256 et RSA-PSS SHA256 lab | **Implémenté** | [crates/pki-core/src/postgres_store.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/postgres_store.rs); C41 schema | NoTls lab; pas service exposé |
| Crash SIGKILL après signature → quarantaine sans re-sign | **Implémenté** | [tests/crash_recovery_sigkill.sh](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/tests/crash_recovery_sigkill.sh); C41 schema | Un point de crash démontré; pas tous scénarios HA/pannes matérielles |
| Réconciliation et revue séparée | **Partiel** | [crates/pki-core/src/reconciliation.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/reconciliation.rs); C41 | Collecteur/provider de test, pas lecture audit HSM réelle |
| Collector evidence signé + receipt durable anti-rejeu | **Partiel** | [crates/pki-core/src/provider_evidence.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/provider_evidence.rs); C41 | Signature réelle ne prouve pas l’origine matérielle |
| Génération distincte CP et CPS DRAFT, drift pur | **Partiel** | [crates/pki-core/src/cp_cps.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/cp_cps.rs); C41 | Pas watcher, workflow complet, publication ni validation organisationnelle |
| Observation CA publique épinglée et trace draft immuable | **Partiel** | [crates/pki-core/src/policy_trace.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/policy_trace.rs); C41 schema | DRAFT_REFERENCE_ONLY, pas approbation opérationnelle |
| Gate pré-signature CP/CPS par issuer | **Partiel** | [migrations/0008_policy_approval_presign_gate.sql](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/migrations/0008_policy_approval_presign_gate.sql); C41 schema | Opt-in; concurrence activation/intents à vérifier |
| Double décision P256 et receipts anti-rejeu | **Partiel** | [crates/pki-core/src/policy_decisions.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/policy_decisions.rs); C41 | Défaut de comparaison identité des clés S-01; IdP/custody externes |
| Adaptateur identité, reviewer et challenge | **Prototype** | [crates/pki-core/src/authentication.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/authentication.rs); C41 + S | Vérifie des claims fournis; ne vérifie pas OIDC/SAML/mTLS |
| Challenge SQL consommation atomique | **Partiel** | [migrations/0010_policy_approval_challenge_lab.sql](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/migrations/0010_policy_approval_challenge_lab.sql); C41 schema | Pas transaction applicative intégrée authentification→receipt→consommation |
| Engagement SHA256 émission, chaîne et manifest | **Prototype** | [crates/pki-core/src/audit_chain.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/audit_chain.rs); C41 | Pas chaîne persistée signée/horodatée/ancrée; assertions latérales à restaurer |
| Garde capacité, signer, release et production | **Prototype** | [crates/pki-core/src/production_gates.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/production_gates.rs); C41 | Booléens/déclarations; aucun contrôle externe attesté |
| Quorum cérémonie et migration crypto | **Prototype** | [crates/pki-core/src/key_ceremony.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/key_ceremony.rs); C41 | Pas cérémonie HSM ou migration des certificats |
| Révocation reason/serial/autorisation | **Prototype** | [crates/pki-core/src/revocation_policy.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/revocation_policy.rs); C41 | Pas changement d’état métier durable ni CRL signée |
| Contrôles identité/tenant/attestation/profil | **Prototype** | [crates/pki-core/src/tenant_isolation.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/tenant_isolation.rs); C41 | Prédicats isolés; pas isolation DB/RLS ni IAM |
| Rétention, budgets, rate limiting, résilience | **Prototype** | [crates/pki-core/src/request_rate.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/request_rate.rs); C41 | Pas horloge/fenêtre/compteur partagé ou worker de suppression |
| PQC rollout, audit integrity, platform readiness | **Prototype** | [crates/pki-core/src/platform_readiness.rs](https://github.com/knehari/trust-platform/blob/6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd/crates/pki-core/src/platform_readiness.rs); C41 | Prédicats booléens, pas vérification d’attestation |
| Provider HSM PKCS#11 / KMS réel | **Non implémenté** | Inventaire S / architecture | Enums et contrats seulement; select_lab_provider refuse hardware/cloud |
| ML-DSA, ML-KEM, hybrides opérationnels | **Non implémenté** | Inventaire S / architecture | Enums/gates seulement; ML-KEM n’est pas une signature |
| CSR P384/P521/Ed25519/Ed448 et RSA-PSS | **Non implémenté** | Inventaire S / architecture | Aucun vérificateur PKCS#10 correspondant trouvé |
| CRL, OCSP, publication/validation complète de chemins | **Non implémenté** | Inventaire S / architecture | revocation_policy est un prédicat, pas CRL/OCSP |
| API Rust réseau authentifiée | **Non implémenté** | Inventaire S / architecture | Pas serveur/binaire applicatif de service |
| Control plane Go, API RBAC, CLM, ACME/EST/SCEP | **Non implémenté** | Inventaire S / architecture | Pas go.mod ni implémentation Go |
| Console React/TypeScript et parcours opérateur | **Non implémenté** | Inventaire S / architecture | Pas package.json ni application frontend |
| Inventaire CLM, discovery, renouvellement, alertes/connecteurs | **Non implémenté** | Inventaire S / architecture | Roadmap et architecture uniquement |
| Publication CP/CPS, contrôles conformité, export auditeur complet | **Non implémenté** | Inventaire S / architecture | Drafts et hashes ne satisfont pas ces workflows |
| HA/DR, backup/restauration, RTO/RPO et charge | **Non vérifié** | Inventaire S / architecture | Aucun scénario opérationnel ni résultat fourni |
| Reproductibilité locale Rust/PostgreSQL | **Non vérifié** | Inventaire S / architecture | Cargo/psql absents, Docker timeout 15 s |
| Audit dépendances à jour, fuzzing, pentest, qualification | **Non vérifié** | Inventaire S / architecture | Pas de résultat vérifié dans cette mission; ne pas inférer absence de vulnérabilité |

## Matrice cryptographique par couche

| Suite | Catalogue/politique | Primitive lab | X.509 | CSR PoP | Durable PostgreSQL | Verdict |
|---|---|---|---|---|---|---|
| ECDSA P256/SHA256 | Legacy LabOnly + typed Planned | Rust p256 réel | Root/leaf réel | Oui | Démo vérifiée | Partiel produit |
| RSA-PSS SHA256 | Legacy NotImplemented malgré signer; typed Planned | Rust rsa réel | Root/leaf réel | CSR RSA-PSS absent; subject P256/RSA distinct | Démo SHA256 vérifiée | Incohérence catalogue |
| RSA-PSS SHA384/512 | Grant typé explicite requis | Réel, MGF1/salt contrôlés | Roots/leaf vérifiés OpenSSL | Pas de CSR PSS | Non démontré pour ces suites | Partiel |
| RSA PKCS1 SHA256/384/512 | Typed Planned | Réel | Roots natifs vérifiés | RSA 2048/3072/4096 vérifiés CI | Non démontré | Partiel |
| RSA 8192 | Enum/validation, branches génériques | Accepté par code générique | Pas preuve CI 8192 | Pas fixture réussie 8192; test falsification négatif seulement | Non démontré | Non vérifié pour 8192 |
| P384/SHA384, P521/SHA512 | Typed Planned | OpenSSL Unix réel | Roots + TLS leaf réels | Absents | Non démontré | Partiel |
| Ed25519, Ed448 | Typed Planned / digest intrinsèque | OpenSSL Unix réel | Roots + TLS leaf réels | Absents | Non démontré | Partiel |
| ML-DSA 44/65/87 | Enum, politique/gate | Aucune | Aucun | Aucun | Aucun | Non implémenté |
| ML-KEM/X25519 | Ne pas assimiler à signature X.509 | Pas de service KEM établi | Sans objet pour signature | Sans objet | Aucun | Non implémenté |

Un test de rejection d’une classe RSA8192 falsifiée n’est pas une preuve positive de génération/signature RSA8192. Les certificats leaf des exemples OpenSSL emploient un subject P256 : signer Ed448 ne prouve pas prise en charge d’une CSR Ed448.

## Traçabilité PRD

Source primaire consultée : [PRD v0.2](https://app.notion.com/p/3f6e759bb68e81cc8892f0154b928d6c), dernière édition annoncée 12 octobre 2026; [Product & Roadmap](https://app.notion.com/p/3f6e759bb68e8116b39fda72ce07d1e0), et index versionné `docs/product/prd-v0.2-traceability.md` sur #41. Le texte intégral FR-001…012 / NFR-01…06 n’a pas été retrouvé dans ces sources : **Non vérifié**, aucun intitulé inventé.

| Exigence | État produit | Ce qui existe / ce qui manque |
|---|---|---|
| FR-013 CP draft | Partiel | Génération déterministe, neuf chapitres; sous-clauses et faits approuvés incomplets |
| FR-014 CPS draft | Partiel | Squelette et labels de provenance; attestations opérationnelles absentes |
| FR-015 drift | Partiel | Fonction diff/hash; pas watcher, alertes ni proposition durable |
| FR-016 quatre yeux | Partiel | Receipts/signatures/gates lab; IdP, autorité, publication/effective workflow incomplets; S-01 |
| FR-017 version/OID/CA | Partiel | Trace et gate optionnelle; ownership OID, toutes émissions et périodes à intégrer |
| FR-018 publication | Non implémenté | Draft-only; pas endpoint, monitoring, archives/redaction |
| FR-019 multi-policies/langues/disclosure | Non implémenté | IDs CA existants insuffisants pour héritage, langues et niveaux de publication |
| FR-020 catalogue contrôles | Non implémenté | Références documentaires, pas moteur versionné d’applicabilité |
| FR-021 evidence | Partiel | Audit DB/receipts réels + hashes en mémoire; pas couverture cérémonies/révocation/provenance complète |
| FR-022 owners/gaps/exceptions | Non implémenté | Pas modèle de workflow et UI opérationnels |
| FR-023 package offline | Prototype | Manifest hash; pas packaging signé, sélection, redaction, accès auditeur |
| FR-024 séparation des tâches | Partiel | Signatures et contrôles lab; rôles réels/backup/HSM non intégrés |
| FR-025 qualified profiles | Non implémenté | Intention seulement, aucune qualification déduite |
| FR-026 réévaluation continue | Non implémenté | Pas moteur événementiel de réévaluation/remédiation |
| NFR-07 intégrité/rétention/DR | Partiel | Triggers et contrats; secure clock, WORM, DR non vérifiés |
| NFR-08 publication approuvée | Non implémenté | Export draft volontairement non publiable |
| NFR-09 éditions des normes | Non implémenté | Références ne constituent pas catalogue applicatif versionné |
| NFR-10 offline evidence | Partiel | Exemples locaux, pas bundle complet ni preuve installation air-gapped |
| NFR-11 accès auditeur | Non implémenté | Pas API ni contrôle read-only/audit des téléchargements |

## Inventaire des modules déclaratifs et doubles

Les modules `identity_boundary`, `tenant_isolation`, `key_attestation`, `certificate_profile`, `audit_retention`, `recovery_budget`, `request_rate`, `pqc_rollout`, `audit_integrity`, `platform_readiness`, `release_gate`, `production_gates`, `key_ceremony`, `crypto_migration`, `revocation_policy`, `resilience_policy`, `capacity_policy` et `signer_capabilities` contiennent des fonctions réelles testées, mais **leur fonction système reste un prototype**. Une entrée `true` ne prouve pas une identité, une attestation, une sauvegarde ou une signature.

`UnconfiguredProvider` refuse de signer; `InMemorySerialStore` est un double; les faux journal/signer/verifier et providers des tests ne constituent pas des adaptateurs de production. À l’inverse, `EphemeralP256Signer`, les modules RSA lab et le provider OpenSSL effectuent de vraies opérations cryptographiques, bien qu’ils restent des logiciels de laboratoire. Conserver les deux catégories et les nommer explicitement.
