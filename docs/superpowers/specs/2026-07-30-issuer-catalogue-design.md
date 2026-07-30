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
- a conforming or deliberately non-conforming status label;
- the configured description;
- the configured warning when present, so the important difference between proof
  policies is explicit;
- links labelled “Issuer,” “Credential issuer well-known,” and “Authorization server
  well-known.”

The chained auto-approving authorization server is an internal test-flow detail and is
not included.

## Data and rendering

Generate the cards from the existing `IssuerCredentialGroup` values passed to
`indexPage`. Use each resolved issuer’s `display`, `compliance`, `issuerIdentifier`,
`issuerMetadataUrl`, and `authorizationServerMetadataUrl` fields. This keeps the UI
aligned with the issuer registry and avoids duplicating protocol URLs or conformance
descriptions.

All rendered values remain HTML-escaped. Endpoint links open in a new tab with
`rel="noreferrer"`.

## Styling

Follow the existing Credimi/Atlas tokens already used by the inline launcher
stylesheet. Use a responsive card grid, restrained borders and backgrounds, and
distinct success and warning treatments for conformance status. The list must remain
readable as a single column on narrow screens.

## Empty state and protocol impact

If no issuer groups are supplied, render the section heading with a short “No issuers
available” message rather than invalid links.

This is a server-rendered presentation change only. It does not alter issuer
configuration, metadata, credential offers, authorization flows, captured evidence,
or API response shapes.

## Validation

Extend the existing launcher HTTP test first. Assert that the homepage contains both
configured issuers, their conformance explanations, and the three correct links for
each issuer. Then run the focused server test, the complete test suite, TypeScript
build, formatter, and lint checks.
