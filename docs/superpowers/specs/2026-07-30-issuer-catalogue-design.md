# Issuer Catalogue Design

## Goal

Help operators understand and inspect every configured credential issuer from the
launcher without changing any OpenID4VCI behavior or public endpoint.

## Placement and presentation

Add an “Available issuers” section immediately below the credential picker and its
session buttons. Render one compact card per issuer in the order already supplied to
the launcher.

Each card shows:

- the configured display name;
- a short description of how its proof policy differs;
- links labelled “Issuer,” “Credential issuer well-known,” and “Authorization server
  well-known.”

Do not render conformance status tags or the configured warning block.

For the conforming issuer, replace the configured description in this UI with:

> Conformant to Commission Implementing Regulation (EU) 2026/1731, in particular
> TR_KA-4: both `jwt` and `attestation` proof types are present and both include
> `key_attestations_required`.

Link “Commission Implementing Regulation (EU) 2026/1731” to
`https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=OJ%3AL_202601731`. The JWT-only
issuer continues to show its configured ordinary description, without its warning.

The chained auto-approving authorization server is an internal test-flow detail and is
not included.

## Data and rendering

Generate the cards from the existing `IssuerCredentialGroup` values passed to
`indexPage`. Use each resolved issuer’s `display.name`, `display.description`,
`compliance`, `issuerIdentifier`, `issuerMetadataUrl`, and
`authorizationServerMetadataUrl` fields. The compliance value selects the static,
linked TR_KA-4 explanation for the conforming card. Keep this UI-specific explanation
out of the shared issuer configuration so the public `/issuers` catalogue is
unchanged.

All configured values remain HTML-escaped. The static regulation and endpoint links
open in a new tab with `rel="noreferrer"`.

## Styling

Follow the existing Credimi/Atlas tokens already used by the inline launcher
stylesheet. Preserve the previewed colors. Use a responsive card grid with restrained
borders and backgrounds. The list must remain readable as a single column on narrow
screens.

## Empty state and protocol impact

If no issuer groups are supplied, render the section heading with a short “No issuers
available” message rather than invalid links.

This is a server-rendered presentation change only. It does not alter issuer
configuration, metadata, credential offers, authorization flows, captured evidence,
or API response shapes.

## Validation

Extend the existing launcher HTTP test first. Assert that the homepage contains both
configured issuers, the linked TR_KA-4 explanation, the JWT-only description, and the
three correct links for each issuer. Assert that status tags, the warning copy, and the
chained authorization-server URL are absent. Add an adversarial unit fixture proving
configured issuer text and URLs are escaped. Then run the focused server test, the
complete test suite, TypeScript build, formatter, and lint checks.
