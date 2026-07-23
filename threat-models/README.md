# CycloneDX 2.0 threat models

This directory contains structured translations of the security/threat model
documents referenced from `scripts/project-coordinates.json`
(`security_model_link` / `security_model_source`) into the draft CycloneDX 2.0
Threat Model format.

These files are an experiment and are not published on security.apache.org.

## Format and schema revision

The CycloneDX 2.0 Threat Model format is an unreleased draft developed by
Ecma TC54 on the `2.0-dev-threatmodeling` branch of
<https://github.com/CycloneDX/specification> (review guide:
<https://github.com/Ecma-TC54/meetings/issues/9>). The format may still change
in incompatible ways before release.

All files validate against the bundled schema at revision
`cf0bc55711517c20c0ccb10f55d822eccb521e03` of that branch. To validate:

```sh
nix-shell -p "python3.withPackages (ps: [ ps.jsonschema ])" \
    --run "python3 scripts/validate-threat-models.py"
```

## Provenance and generation method

Each file was produced on 2026-07-23 by an LLM (Claude) reading the project's
published security model document and mapping its content into the CycloneDX
structure. The translation is interpretive: prose was regrouped into threats,
controls, and boundaries, but no content was invented beyond the source
document. A thin security page yields a thin file. The source document is
always authoritative; see the `threat-model` external reference in each file's
metadata.

## File naming

- `<pmc>.cdx.json` for a PMC-level security model (e.g. `kafka.cdx.json`).
- `<pmc>-<subproject>.cdx.json` for sub-project models listed under the PMC's
  `projects` array (e.g. `ws-wss4j.cdx.json`, `commons-configuration.cdx.json`).

## Mapping conventions

- Root: `specFormat: "CycloneDX"`, `specVersion: "2.0"`.
- `metadata.component` describes the project (type `application`, `library`,
  `framework`, or `platform` as appropriate) and carries an external reference
  of type `threat-model` pointing at the source document, plus one of type
  `website` when obvious. `metadata.supplier` is The Apache Software
  Foundation. `metadata.properties` records `asf:pmc`,
  `asf:security-model-link`, and (when present in the coordinates)
  `asf:security-model-source`.
- Each distinct "what can go wrong" item becomes an entry in
  `threats.threats[]` with a readable `bom-ref` (`threat-<slug>`), an `origin`
  from the NIST SP 800-30 enum (`adversarial`, `accidental`, `structural`,
  `environmental`), and STRIDE `categories` where the classification is clear
  from the text.
- Documented mitigations and hardening recommendations become entries in the
  root `controls` array (`control-<slug>`), referenced from the threats'
  `mitigations` and, where meaningful, given `appliesTo` targets. `status` is
  `recommended` for operator guidance, `implemented` for safeguards built into
  the project, `planned` for documented future work.
- Threats that the source document explicitly declares out of scope, by
  design, or the deployer's responsibility are kept (not dropped) and marked
  with `"properties": [{"name": "asf:in-scope", "value": "false"}]`.
- Pages that document no threats at all carry a metadata property
  `asf:security-model-scope` with value
  `reporting-and-supported-versions-only` (reporting policy pages) or
  `published-vulnerabilities-only` (pure CVE archive pages, e.g. Sentry),
  and an empty `threats` object.
- When the document describes architecture, roles, or trust boundaries, a
  single entry in `blueprints` captures them: `assets` (with `zone`
  references), `zones` (type `trust`), `boundaries` (type `trust`, joining two
  or more zones), `actors` (a `party` with a custom role name and a `persona`
  description), and `assumptions` (objects with a `description`). The
  boundaries are then annotated in `threats.trustBoundaries[]` with
  `trustLevel`, `threatsAtBoundary`, and `controlsAtBoundary`. Documents that
  do not describe architecture omit `blueprints` and `trustBoundaries`
  entirely.
- `affectedAssets` and `appliesTo` are bom-ref references, so they are only
  used when the referenced blueprint assets or boundaries exist.

`activemq.cdx.json` (rich Markdown threat model) and `airflow.cdx.json`
(HTML security model page) are the reference examples of the convention.

## Known gaps

- `geronimo`: the `security_model_link` in `project-coordinates.json`
  (https://geronimo.apache.org/security-reports.html) returns HTTP 404, so no
  file could be generated.
- `singa`: the linked page (https://singa.apache.org/security.html) also
  returns 404; the document was translated from its current location,
  https://singa.apache.org/docs/security.html, noted in the file's external
  reference comment.
