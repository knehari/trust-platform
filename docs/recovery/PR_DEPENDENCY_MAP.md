> Recovery execution update: see [EXECUTION_STATUS.md](EXECUTION_STATUS.md). The original PR #42 snapshot below is preserved as historical evidence; it is not the current delivery status.

# Carte des dépendances des PR

> Audit du 17 octobre 2026. `main`: `20e977a695481c54c1775a97ae0f1fc427159e43`. État de développement de référence: PR #41, `6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd`. Aucun changement fonctionnel ni fusion.

## Méthode et conclusions

Instantané de **41 PR ouvertes, toutes Draft**, #1 à #41, collecté avant création de la PR de ce rapport. Métadonnées GitHub, refs `refs/pull/N/head`, merge-base, différences depuis l’ancêtre commun et comparaison des corrections latérales avec #41 ont été examinés. Les intitulés de PR ne sont pas des preuves de fonctionnalités.

La dépendance déclarée est `main → #1 → #2 → … → #41`. Chaque PR cible la branche de la précédente. **Cette chaîne de noms ne représente pas une ascendance stricte des heads actuels.** Des correctifs de style et de tests ont été ajoutés aux parents après création des enfants. Retargeter toutes les PR vers `main` produirait des diffs cumulatifs et rendrait les omissions difficiles à contrôler.

#41 est le snapshot cumulatif le plus récent, mais pas une union intégrale des 41 heads. `main` a aussi un commit propre, `20e977a`, qui ajoute `ROADMAP.md` et n’est pas dans #41. Aucun cherry-pick, rebase ou merge n’a été exécuté pour cet audit.

`Ancêtre base` signifie que le head actuel de la branche cible est ancêtre du head de la PR. `Dans #41` signifie ascendance Git exacte, pas équivalence sémantique. `CI` est le statusCheckRollup observé sur la PR; absence ≠ succès. Seuls les logs #41 et les échecs #37/#38 ont été détaillés, les autres verts sont des statuts distants.

## Inventaire des 41 heads

| PR / incrément | Branche source | Base | SHA exact | Ancêtre base | Dans #41 | CI observée |
|---|---|---|---|---|---|---|
| [#1](https://github.com/knehari/trust-platform/pull/1) — Sprint 0: Rust CA foundation, fail-closed interfaces and CI | `sprint-0/engineering-foundation` | `main` | `b9acfe16f87c591fc0cc998766ff7648c949418d` | Non | Oui | rust: SUCCESS, schema: SUCCESS |
| [#2](https://github.com/knehari/trust-platform/pull/2) — PRD v0.2 + audit-by-design foundations + PKCS#10 verification (lab) | `feature/prd-compliance-lab-ca` | `sprint-0/engineering-foundation` | `a22646b5399831aa8e45b81c4c90fa964033cb2f` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#3](https://github.com/knehari/trust-platform/pull/3) — X.509 lab: SKI/AKI and controlled certificatePolicies | `feature/x509-policy-evidence` | `feature/prd-compliance-lab-ca` | `1c041bfde1f0fd09ada51d77bb0aa52b77d8c5bf` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#4](https://github.com/knehari/trust-platform/pull/4) — Transactional issuance: durable idempotency, serials and state transitions | `feature/transactional-issuance-foundation` | `feature/x509-policy-evidence` | `96e5c042321ca2ec052e50dabc39cd274d18db48` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#5](https://github.com/knehari/trust-platform/pull/5) — Durable signing intent and ambiguity-safe recovery foundation | `feature/signing-intent-rust-postgres` | `feature/transactional-issuance-foundation` | `f214f45d2235d0c92fd4ffadcc549885435efb8d` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#6](https://github.com/knehari/trust-platform/pull/6) — Laboratory issuance orchestrator: persist intent before signing, fail-closed retries | `feature/issuance-orchestrator-faults` | `feature/signing-intent-rust-postgres` | `d576be5b820755c533fb31ef8d152035356dfe12` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#7](https://github.com/knehari/trust-platform/pull/7) — v0.7 — Verify real X.509 signatures before durable PostgreSQL persistence | `feature/lab-x509-verified-persistence` | `feature/issuance-orchestrator-faults` | `90d34aea9154f861050a94bd654408a5d65642e3` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#8](https://github.com/knehari/trust-platform/pull/8) — v0.8 — Quarantine ambiguous signing after SIGKILL; no automatic re-sign | `feature/v0-8-crash-recovery` | `feature/lab-x509-verified-persistence` | `dcacde72c1b98f9eac3dda361210bbd8d3e5fefc` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#9](https://github.com/knehari/trust-platform/pull/9) — v0.9 — Read-only signer reconciliation and dual-controlled evidence review | `feature/v0-9-provider-reconciliation-review` | `feature/v0-8-crash-recovery` | `0016065567452247bdf09a3769b3e12bce5b646b` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#10](https://github.com/knehari/trust-platform/pull/10) — v1.0 lab — Signed collector evidence, HSM capability matrix and fail-closed retrieval | `feature/v1-0-signed-evidence-capabilities` | `feature/v0-9-provider-reconciliation-review` | `ba79fb8033aa7f624af9a2c0a042d83219e3e53e` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#11](https://github.com/knehari/trust-platform/pull/11) — v1.1 — Durable signed-audit evidence receipts and replay protection | `feature/v1-1-durable-audit-evidence-replay` | `feature/v1-0-signed-evidence-capabilities` | `92fa1d3c03e2580ed2a2acb3a43be2939a77d253` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#12](https://github.com/knehari/trust-platform/pull/12) — v1.2 — CP/CPS as Code: deterministic RFC 3647 drafts and policy drift detection | `feature/v1-2-cp-cps-as-code` | `feature/v1-1-durable-audit-evidence-replay` | `5f3848a502c921fffeccdd5b042a3a300b4be70f` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#13](https://github.com/knehari/trust-platform/pull/13) — v1.3 — Pinned CA public X.509 observation and immutable CP/CPS draft trace | `feature/v1-3-ca-observation-policy-trace` | `feature/v1-2-cp-cps-as-code` | `4830d2509d66d7ebbbca72d86abd3d171b9beaa7` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#14](https://github.com/knehari/trust-platform/pull/14) — v1.4 lab — CP/CPS separate-actor approval and opt-in pre-sign issuer policy gate | `feature/v1-4-policy-approval-presign-gate` | `feature/v1-3-ca-observation-policy-trace` | `e083f520ee7aa1d595c5092fd9cf174184241a29` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#15](https://github.com/knehari/trust-platform/pull/15) — v1.5 lab — Cryptographically signed dual CP/CPS decisions and gated receipts | `feature/v1-5-signed-policy-decisions` | `feature/v1-4-policy-approval-presign-gate` | `cad008854f90dcb822641ad3d125818f055982a7` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#16](https://github.com/knehari/trust-platform/pull/16) — V1.6: identity-bound dual-policy approvals (trusted adapter contract, lab) | `feature/v1-6-identity-bound-policy-approval` | `feature/v1-5-signed-policy-decisions` | `27dc0257ccb6969e6bd11fd705bee6f85c0ffebf` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#17](https://github.com/knehari/trust-platform/pull/17) — V1.7: crypto-agility foundation and RSA-PSS X.509 lab interoperability | `feature/v1-7-crypto-agility-foundation` | `feature/v1-6-identity-bound-policy-approval` | `8d89d362f056784c6eb7afe4b209ab4c481c839b` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#18](https://github.com/knehari/trust-platform/pull/18) — V1.8: validated PostgreSQL-backed RSA-PSS X.509 issuance (laboratory) | `feature/v1-8-durable-x509-issuance` | `feature/v1-7-crypto-agility-foundation` | `88fab3ab98793f86d3d58d3a46237f3c4c13a53f` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |
| [#19](https://github.com/knehari/trust-platform/pull/19) — V1.9: validated fail-closed issuance boundary (laboratory) | `feature/v1-9-issuance-boundary-hardening` | `feature/v1-8-durable-x509-issuance` | `870f2e92f411c8de5bbe69e5670ca8fbb1df9338` | Oui | Non | rust: SUCCESS, schema: SUCCESS |
| [#20](https://github.com/knehari/trust-platform/pull/20) — V2.0: validated deterministic issuance evidence commitment (laboratory) | `feature/v2-0-audit-ready-issuance-contract` | `feature/v1-9-issuance-boundary-hardening` | `ad2fd2566a02e147f140a7cfac04fe39067ab20c` | Non | Oui | rust: SUCCESS, schema: SUCCESS |
| [#21](https://github.com/knehari/trust-platform/pull/21) — V2.1: hash-chained audit commitments (laboratory) | `feature/v2-1-audit-chain` | `feature/v2-0-audit-ready-issuance-contract` | `f4e1417581265511539f19ed0e219940d64e8743` | Oui | Non | rust: SUCCESS, schema: SUCCESS |
| [#22](https://github.com/knehari/trust-platform/pull/22) — V2.2: fail-closed signer capability selection (laboratory) | `feature/v2-2-signer-policy` | `feature/v2-1-audit-chain` | `6bad3b1c7e117f9b918d7f9da54197f50a4ee64d` | Non | Non | rust: SUCCESS, schema: SUCCESS |
| [#23](https://github.com/knehari/trust-platform/pull/23) — V2.3: issuance admission and overload limits (laboratory) | `feature/v2-3-capacity-policy` | `feature/v2-2-signer-policy` | `4ab1e7c531663d2e80a0bc13b62f9771fcbd5ece` | Non | Non | Non vérifiée (aucun check remonté) |
| [#24](https://github.com/knehari/trust-platform/pull/24) — V2.4: deterministic audit manifest commitments (laboratory) | `feature/v2-4-audit-export` | `feature/v2-3-capacity-policy` | `fab9b8c3c0ccc529683d494d258e10d7c168577c` | Non | Non | Non vérifiée (aucun check remonté) |
| [#25](https://github.com/knehari/trust-platform/pull/25) — V2.5: release gate and cross-module evidence composition (laboratory) | `feature/v2-5-release-readiness` | `feature/v2-4-audit-export` | `23c7cd0fe7405910de036b04e8d190e0cc65c628` | Non | Oui | Non vérifiée (aucun check remonté) |
| [#26](https://github.com/knehari/trust-platform/pull/26) — V2.6: Key ceremony witness quorum (laboratory contract) | `feature/v2-6-key-ceremony` | `feature/v2-5-release-readiness` | `e83ce2b03054eb7313b0f381e66ab02c55846de5` | Oui | Non | rust: SUCCESS, schema: SUCCESS |
| [#27](https://github.com/knehari/trust-platform/pull/27) — V2.7: Cryptographic migration decision policy (laboratory contract) | `feature/v2-7-crypto-migration` | `feature/v2-6-key-ceremony` | `3418f98d6012c2a6982fce2cc1d1062daa2df328` | Non | Non | rust: SUCCESS, schema: SUCCESS |
| [#28](https://github.com/knehari/trust-platform/pull/28) — V2.8: Revocation approval and reason validation (laboratory contract) | `feature/v2-8-revocation-policy` | `feature/v2-7-crypto-migration` | `eda11808837cf6a1e97bf765b8a4418f2098c10f` | Non | Non | rust: SUCCESS, schema: SUCCESS |
| [#29](https://github.com/knehari/trust-platform/pull/29) — V2.9: Recovery and signer uncertainty controls (laboratory contract) | `feature/v2-9-resilience-policy` | `feature/v2-8-revocation-policy` | `f9798995af9e9b48f84d32adee0dcc9d2e2536a8` | Non | Non | rust: SUCCESS, schema: SUCCESS |
| [#30](https://github.com/knehari/trust-platform/pull/30) — V3.0: production enablement evidence gates (laboratory contract) | `feature/v3-0-production-gates` | `feature/v2-9-resilience-policy` | `8a1691a836381fac868b63906735f2f7e0b5b5a4` | Non | Oui | rust: SUCCESS, schema: SUCCESS |
| [#31](https://github.com/knehari/trust-platform/pull/31) — V3.1: Identity claims validation (laboratory) | `feature/v3-1-identity-boundary` | `feature/v3-0-production-gates` | `5c65116da39b1d4d1b15fac335a21cdfd470a816` | Oui | Non | rust: SUCCESS, schema: SUCCESS |
| [#32](https://github.com/knehari/trust-platform/pull/32) — V3.2: Tenant scope authorization (laboratory) | `feature/v3-2-tenant-isolation` | `feature/v3-1-identity-boundary` | `114b6fe8ace37dab1cab8cdc167301f6e12ee671` | Non | Non | rust: SUCCESS, schema: SUCCESS |
| [#33](https://github.com/knehari/trust-platform/pull/33) — V3.3: Key attestation evidence preflight (laboratory) | `feature/v3-3-key-attestation` | `feature/v3-2-tenant-isolation` | `b10cc3faa630c4c01082a99ef6f17062a3e4dff5` | Non | Non | rust: SUCCESS, schema: SUCCESS |
| [#34](https://github.com/knehari/trust-platform/pull/34) — V3.4: Certificate profile preflight (laboratory) | `feature/v3-4-certificate-profile` | `feature/v3-3-key-attestation` | `ca159b874e1c5968635fbe72d7f24b61e2f3f8ff` | Non | Non | rust: SUCCESS, schema: SUCCESS |
| [#35](https://github.com/knehari/trust-platform/pull/35) — V3.5: audit retention guard (laboratory) | `feature/v3-5-audit-retention` | `feature/v3-4-certificate-profile` | `973a7e195cfc5442496f3cd4a5f08e1928591eff` | Non | Non | rust: SUCCESS, schema: SUCCESS |
| [#36](https://github.com/knehari/trust-platform/pull/36) — V3.6: Recovery attempt budget (laboratory contract) | `feature/v3-6-recovery-budget` | `feature/v3-5-audit-retention` | `07383fc53fe9e68ec45e69ecef4d95b6d6d11aed` | Non | Non | rust: SUCCESS, schema: SUCCESS |
| [#37](https://github.com/knehari/trust-platform/pull/37) — V3.7: Request rate-limit policy (laboratory contract) | `feature/v3-7-request-rate` | `feature/v3-6-recovery-budget` | `da794dc5e1c4c3a360f4d1f0e00645c40b16cac3` | Non | Non | rust: FAILURE, schema: SUCCESS |
| [#38](https://github.com/knehari/trust-platform/pull/38) — V3.8: Post-quantum rollout gate (laboratory contract) | `feature/v3-8-pqc-rollout` | `feature/v3-7-request-rate` | `ac12bfadaed5368a645674a9f2d48b5d49c7df50` | Non | Non | rust: FAILURE, schema: SUCCESS |
| [#39](https://github.com/knehari/trust-platform/pull/39) — V3.9: External audit checkpoint policy (laboratory contract) | `feature/v3-9-audit-integrity` | `feature/v3-8-pqc-rollout` | `a107468b5207bc8098e24c397d2ed6c7a2255f0e` | Non | Non | Non vérifiée (aucun check remonté) |
| [#40](https://github.com/knehari/trust-platform/pull/40) — V4.0: Platform integration readiness gate (laboratory) | `feature/v4-0-platform-readiness` | `feature/v3-9-audit-integrity` | `e07817da737bad2162325c3bd337eb5cf5a34f13` | Non | Oui | Non vérifiée (aucun check remonté) |
| [#41](https://github.com/knehari/trust-platform/pull/41) — Crypto-agility by design: typed classical signing, lab dispatch and X.509 identifier gates | `feature/classical-crypto-agility-foundation` | `feature/v4-0-platform-readiness` | `6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd` | Oui | Oui | rust: SUCCESS, schema: SUCCESS |

## Divergences à préserver

| Origine | Différence observée dans #41 | Conséquence / traitement futur |
|---|---|---|
| main `20e977a` | `ROADMAP.md` absent | Conserver le document et réconcilier ses versions avec le code. |
| #19, #21, #22 | Heads non ancêtres; corrections latérales hors `lib.rs` équivalentes après `git diff -w` | Ne pas confondre non-ascendance et perte fonctionnelle; préserver provenance. |
| #23 `4ab1e7c` | Assertion `admit(l, {in_flight:0,pending:0}) == Ok(())` absente de `capacity_policy.rs` dans #41 | Perte réelle de couverture de test; réintroduire sur branche de consolidation puis exécuter. |
| #24 `fab9b8c` | Assertion de déterminisme `manifest_digest(&[a,b]) == manifest_digest(&[a,b])` absente de #41 | Préserver l’intention du test, idéalement avec valeur attendue indépendante; aucune preuve de perte de l’algorithme lui-même. |
| #26–#29, #31–#35 | Corrections latérales principalement de formatage et d’ordre des modules | Comparer le contenu, éviter les cherry-picks aveugles. |
| #36 `07383fc` | Test `UnknownOperation` corrigé sur parent mais non hérité immédiatement par #37–#39 | #41 contient la correction et ajoute `Exhausted` / `InvalidBudget`; préserver les trois assertions. |
| #37/#38 | CI Rust en échec: attendu `UnknownOperation`, obtenu `Exhausted` pour `check(1,1,true)` | Fixture erronée; code #41 corrigé. Les anciens heads restent rouges. |
| #39/#40 | Aucun check remonté dans l’instantané | Ne pas les annoncer verts individuellement; #40 est ancêtre de #41, pas #39. |

Les autres écarts de `lib.rs` comprennent de nouveaux modules et des réordonnancements; tous les modules déclarés sur les heads antérieurs doivent figurer dans l’inventaire de conservation, même si leur code est encore un prototype.

## Répartition des incréments et dépendances techniques

| PR | Apport propre / domaine à conserver | Dépendances réelles |
|---|---|---|
| #1–#3 | Workspace, politique, CSR, X.509 P256, SKI/AKI/OID | Crypto/policy avant CA; identité fournie par appelant de confiance |
| #4–#5 | Transactions, idempotence, serial, intent et adaptateur PostgreSQL | Migrations 0001→0003, contraintes issuer/request |
| #6–#8 | Orchestration, vérification réelle, crash/quarantaine | Journal durable avant signer, vérificateur avant stockage |
| #9–#11 | Réconciliation en lecture, double revue, collector signé et anti-rejeu | 0004→0006, clés de confiance, aucun re-sign automatique |
| #12–#16 | CP/CPS drafts, observation CA, gate opt-in, double signature, identité/challenge | 0007→0010, validation Rust + appelant de confiance |
| #17–#19 | RSA-PSS, binding serial/TBS/certificat, orchestration et bornes | Extensions de crypto/policy; tests PostgreSQL/OpenSSL |
| #20–#25 | Engagement d’émission, chaîne/manifest, garde signer/capacité/release | Fonctions en mémoire, composition de contrats, pas pipeline durable |
| #26–#30 | Quorum cérémonie, migration crypto, révocation, résilience, production gate | Prédicats sur entrées prévalidées, pas services opérationnels |
| #31–#40 | Identité/tenant/attestation/profil/rétention/budget/rate/PQC/audit/readiness | Contrats indépendants, pas d’IAM, de scheduler ou de HSM |
| #41 | Suites typées, dispatch réel lab, RSA/ECDSA/EdDSA X.509 et CSR RSA | Politique typée, providers lab, OpenSSL Unix; orchestration durable typée encore à intégrer |

## Reproduction de la carte

```sh
gh pr list --repo knehari/trust-platform --state open --limit 100 \
  --json number,title,headRefName,headRefOid,baseRefName,isDraft,statusCheckRollup
git fetch origin '+refs/pull/*/head:refs/remotes/pull/*'
git merge-base --is-ancestor origin/<base> refs/remotes/pull/<N>
git log --oneline origin/<base> --not refs/remotes/pull/<N>
git diff origin/<base>...refs/remotes/pull/<N>
git diff -w refs/remotes/pull/23 refs/remotes/pull/41 -- crates/pki-core/src/capacity_policy.rs
git diff -w refs/remotes/pull/24 refs/remotes/pull/41 -- crates/pki-core/src/audit_manifest.rs
```

Les refs évoluent : utiliser les SHA du tableau pour reproduire cet audit. Après toute consolidation autorisée, vérifier l’ensemble des fonctions publiques, migrations, exemples, fixtures et assertions, pas seulement un build vert.
