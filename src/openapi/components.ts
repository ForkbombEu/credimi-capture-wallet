import type { JsonRecord } from "../types.js";

export function components(issuerIds: readonly string[]): JsonRecord {
  return {
    schemas: {
      Health: {
        type: "object",
        required: ["status"],
        properties: { status: { type: "string", const: "ok" } },
      },
      Error: {
        type: "object",
        required: ["error"],
        properties: {
          error: { type: "string" },
          error_description: { type: "string" },
          message: { type: "string" },
        },
        additionalProperties: true,
      },
      Jwks: {
        type: "object",
        required: ["keys"],
        properties: {
          keys: { type: "array", items: { type: "object", additionalProperties: true } },
        },
      },
      Event: {
        type: "object",
        required: ["at", "type", "detail"],
        properties: {
          at: { type: "string", format: "date-time" },
          type: { type: "string" },
          detail: { type: "object", additionalProperties: true },
        },
      },
      Oid4vciHttpRequestCapture: {
        type: "object",
        required: [
          "id",
          "at",
          "method",
          "path",
          "session_id",
          "issuer_configuration_id",
          "headers",
          "header_counts",
          "query",
          "body",
          "response",
        ],
        properties: {
          id: { type: "string", format: "uuid" },
          at: { type: "string", format: "date-time" },
          method: { type: "string" },
          path: { type: "string" },
          session_id: { type: ["string", "null"] },
          issuer_configuration_id: { type: ["string", "null"] },
          unmatched: {
            type: "boolean",
            const: true,
            description:
              "Present when no configured issuer resource or other route matched, and the response was 404.",
          },
          headers: { type: "object", additionalProperties: true },
          header_counts: {
            type: "object",
            additionalProperties: { type: "integer", minimum: 1 },
            description:
              "Occurrences of each header field, keyed by lower-case name and counted from the raw header list. Node joins repeated fields into one value, so headers cannot show a field was sent more than once.",
          },
          raw_headers: {
            type: "array",
            description:
              "Only in a session created with evidence_mode full: every header field in received order with its original name casing. Authorization, DPoP, Cookie, and Proxy-Authorization values are presence and length metadata.",
            items: {
              type: "object",
              required: ["name", "value"],
              properties: {
                name: { type: "string" },
                value: { oneOf: [{ type: "string" }, { type: "object" }] },
              },
            },
          },
          raw_body: {
            type: "object",
            required: ["content_type"],
            description:
              "Only in a session created with evidence_mode full, for PAR, token, and Credential Requests: the declared Content-Type and the exact received bytes as base64, or the text of an application/jwt body. A token request body is described with redacted true and its length, because it carries codes that stay redacted. Present even when the media type matched no parser or the body failed to parse.",
            properties: {
              content_type: { type: ["string", "null"] },
              base64: { type: "string", contentEncoding: "base64" },
              text: { type: "string" },
              redacted: { type: "boolean", const: true },
              length: { type: "integer", minimum: 0 },
            },
          },
          query: {},
          body: {},
          response: {
            type: "object",
            properties: {
              status: { type: ["integer", "null"] },
              content_type: { type: ["string", "null"] },
              body: {
                description:
                  "The delivered body, after any response encryption. JSON is redacted by the same rules as the request in that evidence mode (tokens and issued credentials are always presence and length metadata; c_nonce is always kept); any other body is presence and length metadata. Absent when the response had no body.",
              },
            },
          },
        },
      },
      IssuanceSessionRequests: {
        type: "object",
        required: ["session_id", "window", "requests", "unattributed_requests"],
        properties: {
          session_id: { type: "string", format: "uuid" },
          window: {
            type: "object",
            required: ["from", "to"],
            properties: {
              from: { type: "string", format: "date-time" },
              to: { type: "string", format: "date-time" },
            },
          },
          requests: {
            type: "array",
            description: "Requests attributed to this session in chronological order.",
            items: { $ref: "#/components/schemas/Oid4vciHttpRequestCapture" },
          },
          unattributed_requests: {
            type: "array",
            description:
              "Ledger entries with no session ID recorded within window; always redacted, including for a full-evidence session.",
            items: { $ref: "#/components/schemas/Oid4vciHttpRequestCapture" },
          },
        },
      },
      IssuanceSessionRequest: {
        type: "object",
        properties: {
          issuer_configuration_id: {
            type: "string",
            enum: issuerIds,
            default: "eu-pid-device-bound",
            description: "Selects one of the served, isolated issuer configurations.",
          },
          flow: {
            type: "string",
            enum: ["pre_authorized_code", "authorization_code"],
            default: "authorization_code",
            description: "Issuance flow preset.",
          },
          credential_offer_mode: {
            type: "string",
            enum: ["credential_offer", "credential_offer_uri"],
            default: "credential_offer",
            description:
              "Encode the offer directly in the deeplink or provide its hosted URI by reference.",
          },
          status_reference: {
            type: "string",
            enum: [
              "valid",
              "status_without_status_list",
              "negative_index",
              "missing_index",
              "malformed_uri",
              "missing_uri",
              "uri_missing_scheme",
              "uri_space_in_host",
              "uri_invalid_percent_encoding",
              "uri_illegal_characters",
              "uri_empty",
            ],
            default: "valid",
            description:
              "Shape of the status structure in the issued SD-JWT VC or mdoc. Anything other than valid is test-only, refused unless the deployment sets FCAF_SCENARIOS_ENABLED, and requires status_list_enabled so the malformed structure reshapes a genuinely allocated reference. The uri_* values keep idx and derive uri from the allocated URI: scheme: component removed, a space inserted in the middle of the host, %GG appended, <token>|1 appended, or the empty string. For mdoc, only the Mobile Security Object status structure is reconstructed and Credo's KMS signs it.",
          },
          digest_algorithm: {
            type: "string",
            enum: ["sha-256", "sha-384", "sha-512"],
            default: "sha-256",
            description:
              "Hash function the issued SD-JWT VC digests its disclosures with, placed in the _sd_alg claim. Credential Issuer Metadata keeps advertising SHA-256 only, so a value other than sha-256 produces a credential a Wallet can present only if it supports that hash function. Not available for mdoc configurations, where the digests belong to the Mobile Security Object.",
          },
          fixture_id: {
            type: "string",
            default: "pid_default",
            description:
              "Predefined PID claim set the issued credential carries. Fixtures differ from the baseline along one value axis each, so a DCQL value constraint matches one and withholds the others. Refused for a credential imported from Attestbook, whose values are generated per session.",
          },
          document_number: {
            type: "string",
            minLength: 1,
            description:
              "Caller-selected document number for the issued PID. It overrides the selected fixture's document number without changing its other claims. Refused for imported Attestbook credentials, as are status_list_enabled and status_reference.",
          },
          credential_configuration_id: {
            type: "string",
            description: "One of the IDs advertised by credential issuer metadata.",
          },
          status_list_enabled: {
            type: "boolean",
            default: false,
            description:
              "When true, allocate and embed a Token Status List reference in each issued credential.",
          },
          evidence_mode: {
            type: "string",
            enum: ["redacted", "full"],
            default: "redacted",
            description:
              "Test-only full is refused with evidence_mode_not_enabled unless the deployment sets FCAF_SCENARIOS_ENABLED. full keeps this session's own OpenID4VCI evidence unredacted except for access and refresh tokens, authorization and pre-authorized codes, tx_code, code_verifier, issued credentials, and the Authorization, DPoP, and cookie headers. The global /oid4vci/requests ledger stays redacted.",
          },
          issuance_response_scenario: {
            $ref: "#/components/schemas/IssuanceResponseScenario",
          },
          offer_scheme: {
            type: "string",
            enum: ["openid-credential-offer://", "eu-eaa-offer://", "haip-vci://"],
            default: "openid-credential-offer://",
            description:
              "URL scheme of the offer deeplink, passed to Credo-TS as the offer baseUri. A by-value offer keeps it.",
          },
          offer_mutation: {
            $ref: "#/components/schemas/CredentialOfferMutation",
          },
        },
      },
      IssuanceResponseScenario: {
        type: "object",
        minProperties: 1,
        additionalProperties: false,
        description:
          'Test-only, refused with issuance_response_scenario_not_enabled unless the deployment sets FCAF_SCENARIOS_ENABLED, and with invalid_issuance_response_scenario when malformed. Replaces what the Wallet receives from the session\'s PAR or Credential endpoint at the HTTP boundary; Credo-TS still handles the request, and each application is logged as an issuance_response_scenario_applied event with the original and delivered responses. When the Wallet requested an encrypted Credential Response, a delivered 2xx response is encrypted after the scenario is applied, and a delivered error status is sent unencrypted (OpenID4VCI 1.0 Section 8.3.1). Example: {"par":{"omit_parameters":["/request_uri"]}} or {"credential":{"status":400,"content_type":"application/json","body":"{\\"error\\":\\"credential_request_denied\\"}"}}.',
        properties: {
          par: { $ref: "#/components/schemas/IssuanceEndpointResponseScenario" },
          credential: { $ref: "#/components/schemas/IssuanceEndpointResponseScenario" },
        },
      },
      CredentialOfferMutation: {
        type: "object",
        minProperties: 1,
        additionalProperties: false,
        description:
          "Test-only, refused with offer_mutation_not_enabled unless the deployment sets FCAF_SCENARIOS_ENABLED, with invalid_offer_mutation when malformed, and with offer_mutation_requires_by_value_offer for credential_offer_uri mode. RFC 6901 JSON Pointer edits to the Credential Offer carried by value in the deeplink; writes first, then removals. Credo-TS keeps serving the generated offer, recorded in raw.credential_offer, with the delivered one in raw.credential_offer_delivered.",
        properties: {
          set: {
            type: "object",
            additionalProperties: true,
            description: "JSON Pointer to the value written there, including null.",
          },
          unset: {
            type: "array",
            items: { type: "string", pattern: "^/" },
            description: "JSON Pointers whose member is removed.",
          },
        },
      },
      IssuanceEndpointResponseScenario: {
        type: "object",
        minProperties: 1,
        additionalProperties: false,
        properties: {
          status: { type: "integer", minimum: 100, maximum: 599 },
          content_type: { type: "string" },
          body: { type: "string", description: "Exact delivered body." },
          extra_parameters: {
            type: "object",
            additionalProperties: true,
            description: "Members merged into the produced JSON body.",
          },
          omit_parameters: {
            type: "array",
            items: { type: "string", pattern: "^/" },
            description:
              "RFC 6901 JSON Pointers removed from the produced JSON body after extra_parameters are merged.",
          },
        },
      },
      IssuanceSessionCreated: {
        type: "object",
        required: [
          "session_id",
          "issuer_configuration_id",
          "issuer_identifier",
          "authorization_server_identifier",
          "flow",
          "credential_offer_mode",
          "credential_configuration_id",
          "status_list_enabled",
          "offer_url",
          "deeplink",
          "status",
        ],
        properties: {
          session_id: { type: "string", format: "uuid" },
          issuer_configuration_id: { type: "string" },
          issuer_identifier: { type: "string", format: "uri" },
          authorization_server_identifier: { type: "string", format: "uri" },
          flow: {
            type: "string",
            enum: ["pre_authorized_code", "authorization_code"],
          },
          credential_offer_mode: {
            type: "string",
            enum: ["credential_offer", "credential_offer_uri"],
          },
          credential_configuration_id: { type: "string" },
          status_list_enabled: { type: "boolean" },
          fixture_id: { type: "string" },
          credential_definition: { $ref: "#/components/schemas/SessionCredentialDefinition" },
          generated_claims: { $ref: "#/components/schemas/SessionGeneratedClaims" },
          document_number: { type: "string", minLength: 1 },
          status_reference: { type: "string" },
          digest_algorithm: { type: "string" },
          evidence_mode: { type: "string", const: "full" },
          offer_scheme: {
            type: "string",
            description:
              "Present only when a scheme other than openid-credential-offer:// was selected.",
          },
          offer_url: { type: "string", format: "uri" },
          deeplink: { type: "string" },
          status: { type: "string", const: "created" },
        },
      },
      IssuanceSession: {
        type: "object",
        required: [
          "session_id",
          "issuer_configuration_id",
          "issuer_identifier",
          "authorization_server_identifier",
          "status",
          "flow",
          "credential_offer_mode",
          "credential_configuration_id",
          "observed",
          "checks",
          "events",
        ],
        properties: {
          evidence_mode: {
            type: "string",
            const: "full",
            description: "Present only for a session created with evidence_mode full.",
          },
          document_number: {
            type: "string",
            minLength: 1,
            description: "Caller-selected document number used in the issued PID.",
          },
          credential_definition: {
            $ref: "#/components/schemas/SessionCredentialDefinition",
          },
          generated_claims: {
            $ref: "#/components/schemas/SessionGeneratedClaims",
          },
          issuance_response_scenario: {
            $ref: "#/components/schemas/IssuanceResponseScenario",
          },
          offer_scheme: {
            type: "string",
            description:
              "Present only when a scheme other than openid-credential-offer:// was selected.",
          },
          offer_mutation: { $ref: "#/components/schemas/CredentialOfferMutation" },
          initiated_by: {
            type: "string",
            const: "wallet",
            description:
              "Present only for a session the Wallet started itself with a Pushed Authorization Request naming a scope and no issuer_state. No Credential Offer exists for it, so its offer and deeplink endpoints answer credential_offer_not_ready, and credential_offer_mode carries the default.",
          },
          notifications: {
            type: "array",
            description:
              "Each notification_id delivered in a Credential Response, with the Wallet's Notification Requests for it. Present once one was delivered. A report is what the Wallet said, not proof a Credential is stored.",
            items: {
              type: "object",
              required: [
                "notification_id",
                "issued_at",
                "credential_configuration_id",
                "credential_count",
                "received",
              ],
              properties: {
                notification_id: { type: "string" },
                issued_at: { type: "string", format: "date-time" },
                credential_configuration_id: { type: "string" },
                credential_count: { type: "integer", minimum: 1 },
                received: {
                  type: "array",
                  description:
                    "Distinct reports in arrival order; an identical repeat only updates last_received_at and received_count.",
                  items: {
                    type: "object",
                    required: ["event", "first_received_at", "last_received_at", "received_count"],
                    properties: {
                      event: {
                        type: "string",
                        enum: ["credential_accepted", "credential_failure", "credential_deleted"],
                      },
                      event_description: { type: "string" },
                      first_received_at: { type: "string", format: "date-time" },
                      last_received_at: { type: "string", format: "date-time" },
                      received_count: { type: "integer", minimum: 1 },
                    },
                  },
                },
              },
            },
          },
          observed: {
            type: "object",
            additionalProperties: true,
            properties: {
              client_authentication: {
                type: "object",
                additionalProperties: true,
                description:
                  "The first request carrying OAuth-Client-Attestation or OAuth-Client-Attestation-PoP, decoded and not verified: method wallet_attestation, and for wallet_attestation and wallet_attestation_pop their presence, source, JOSE header, claims, and decode error. wallet_attestation adds cnf_jwk and client_id_matches (sub against the request client_id, null when the request states none); wallet_attestation_pop adds audience_matches (aud against the authorization server identifier) and challenge.",
              },
            },
          },
          raw: {
            type: "object",
            additionalProperties: true,
            properties: {
              oid4vci_requests: {
                type: "array",
                description:
                  "The session's OpenID4VCI requests, attributed when each arrives. For evidence_mode full, the unredacted form of each ledger entry.",
                items: { $ref: "#/components/schemas/Oid4vciHttpRequestCapture" },
              },
              credential_request_proofs: {
                $ref: "#/components/schemas/CredentialRequestProofs",
              },
            },
          },
          status_list_references: {
            type: "array",
            description:
              "Reference allocated for each issued credential, at the credential's index. The real allocation, even when status_reference reshaped what the credential carries.",
            items: {
              type: "object",
              required: ["allocation_id", "uri", "idx"],
              properties: {
                allocation_id: { type: "string" },
                uri: { type: "string" },
                idx: { type: "integer", minimum: 0 },
              },
            },
          },
          status_list_updates: {
            type: "array",
            description: "Every POST /sessions/{sessionId}/status call, in order.",
            items: { $ref: "#/components/schemas/StatusListUpdate" },
          },
        },
        additionalProperties: true,
      },
      JwtEvidence: {
        type: "object",
        required: ["compact", "header", "payload", "error"],
        description: "A compact JWT exactly as received, decoded and never verified.",
        properties: {
          compact: { type: "string" },
          header: { type: ["object", "null"], additionalProperties: true },
          payload: { type: ["object", "null"], additionalProperties: true },
          error: { type: ["string", "null"] },
        },
      },
      CredentialRequestProofs: {
        type: "object",
        required: ["request_id", "at", "jwt", "attestation"],
        description:
          "Only for evidence_mode full: the latest Credential Request's proofs, recorded when it arrives and before Credo-TS verifies them, so a rejected proof is kept too.",
        properties: {
          request_id: {
            type: "string",
            format: "uuid",
            description: "id of the request's raw.oid4vci_requests entry.",
          },
          at: { type: "string", format: "date-time" },
          proofs: {
            description: "The proofs member exactly as received, with its JSON types.",
          },
          jwt: {
            type: "array",
            description:
              "Each string in proofs.jwt, or proofs.jwt itself when it is a string. key_attestation is the decoded key_attestation JOSE header parameter.",
            items: {
              allOf: [
                { $ref: "#/components/schemas/JwtEvidence" },
                {
                  type: "object",
                  required: ["source"],
                  properties: {
                    source: { type: "string" },
                    key_attestation: { $ref: "#/components/schemas/JwtEvidence" },
                  },
                },
              ],
            },
          },
          attestation: {
            type: "array",
            description: "Each Key Attestation string in proofs.attestation.",
            items: {
              allOf: [
                { $ref: "#/components/schemas/JwtEvidence" },
                {
                  type: "object",
                  required: ["source"],
                  properties: { source: { type: "string" } },
                },
              ],
            },
          },
        },
      },
      StatusListUpdate: {
        type: "object",
        required: ["at", "requested_status", "results"],
        properties: {
          error: { type: "string", const: "status_list_update_failed" },
          session_id: { type: "string" },
          at: { type: "string", format: "date-time" },
          requested_status: { type: "string", const: "revoked" },
          results: {
            type: "array",
            items: {
              type: "object",
              required: ["uri", "idx", "status", "ok", "http_status"],
              properties: {
                uri: { type: "string" },
                idx: { type: "integer" },
                status: { type: "integer", const: 1 },
                ok: { type: "boolean" },
                http_status: { type: ["integer", "null"] },
                response_body: {
                  type: "string",
                  description: "The Status List service's response body, as received.",
                },
                error: { type: "string", description: "Transport failure, such as a timeout." },
              },
            },
          },
        },
        additionalProperties: false,
      },
      IssuerCatalogueEntry: {
        type: "object",
        required: [
          "id",
          "compliance",
          "credential_issuer",
          "credential_issuer_metadata",
          "authorization_server_metadata",
          "upstream_authorization_server",
          "name",
          "description",
          "credential_configuration_ids",
        ],
        properties: {
          id: { type: "string" },
          compliance: {
            type: "string",
            enum: ["eudi-pid-device-bound", "deliberately-nonconforming", "experimental"],
          },
          credential_issuer: { type: "string", format: "uri" },
          credential_issuer_metadata: { type: "string", format: "uri" },
          authorization_server_metadata: { type: "string", format: "uri" },
          upstream_authorization_server: { type: "string", format: "uri" },
          name: { type: "string" },
          description: { type: "string" },
          warning: { type: "string" },
          credential_configuration_ids: {
            type: "array",
            items: { type: "string" },
          },
        },
      },
      SessionCredentialDefinition: {
        type: "object",
        description:
          "The exact published Attestbook rulebook version an imported-credential session is pinned to; provenance only, never claim values.",
        required: [
          "source",
          "origin",
          "rulebook_id",
          "version",
          "content_digest",
          "attestation",
          "vct",
          "vct_source",
        ],
        properties: {
          source: { type: "string", const: "attestbook" },
          origin: { type: "string", format: "uri" },
          rulebook_id: { type: "string" },
          version: { type: "string" },
          content_digest: { type: "string", pattern: "^[0-9a-f]{64}$" },
          attestation: { type: "string" },
          vct: { type: "string" },
          vct_source: { type: "string", const: "attestation_name" },
        },
      },
      SessionGeneratedClaims: {
        type: "object",
        description:
          "Synthetic claim values an imported credential is issued with, generated at session creation. The same generator version, seed and reference date regenerate them exactly.",
        required: ["generator", "seed", "reference_date", "claims"],
        properties: {
          generator: { type: "string", examples: ["@faker-js/faker@10.6.0"] },
          seed: { type: "string", description: "The session id." },
          reference_date: { type: "string", format: "date-time" },
          claims: { type: "object", additionalProperties: true },
        },
      },
      AttestbookIntegrationStatus: {
        type: "object",
        required: ["enabled"],
        properties: {
          enabled: { type: "boolean" },
          issuer_configuration_id: { type: "string" },
          origin: { type: "string", format: "uri" },
          rulebook_id: { type: "string" },
          subscription: {
            type: "object",
            properties: {
              callback_url: { type: "string", format: "uri" },
              webhook_secret_configured: { type: "boolean" },
              manual_sync_enabled: { type: "boolean" },
              last_verification_challenge_at: { type: ["string", "null"] },
              last_signed_notification_at: { type: ["string", "null"] },
            },
          },
          last_observed_event: { type: ["object", "null"], additionalProperties: true },
          pending_notifications: { type: "integer", minimum: 0 },
          active: {
            type: ["object", "null"],
            properties: {
              version: { type: "string" },
              content_digest: { type: "string" },
              published_at: { type: ["string", "null"] },
              event_id: { type: ["string", "null"] },
              activated_at: { type: "string" },
              credential_configuration_ids: { type: "array", items: { type: "string" } },
            },
          },
          last_successful_sync_at: { type: ["string", "null"] },
          sync: {
            type: "object",
            properties: {
              state: {
                type: "string",
                enum: ["idle", "fetching", "validating", "activating", "failed"],
              },
              last_trigger: {
                type: ["string", "null"],
                enum: ["startup", "webhook", "manual", "retry", null],
              },
              failure: {
                type: ["object", "null"],
                properties: {
                  stage: {
                    type: "string",
                    enum: ["fetch", "verify", "compile", "issuability", "activate", "persist"],
                  },
                  code: { type: "string" },
                  message: { type: "string" },
                  at: { type: "string" },
                  version: { type: ["string", "null"] },
                  content_digest: { type: ["string", "null"] },
                },
              },
              diagnostics: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    severity: { type: "string", enum: ["error", "info"] },
                    code: { type: "string" },
                    attestation: { type: ["string", "null"] },
                    field: { type: ["string", "null"] },
                    message: { type: "string" },
                  },
                },
              },
            },
          },
        },
      },
      PresentationSessionRequest: {
        type: "object",
        properties: {
          scheme: {
            type: "string",
            pattern: "^[A-Za-z][A-Za-z0-9+.-]*://$",
            default: "openid4vp://",
            description: "Custom URL-scheme prefix for the returned deeplink.",
          },
          request_uri_method: {
            type: "string",
            default: "get",
            description:
              "HTTP method advertised for request_uri retrieval. OpenID4VP defines case-sensitive get and post; other values are preserved only for wallet negative tests.",
          },
          client_id_scheme: {
            type: "string",
            enum: [
              "x509_hash",
              "x509_san_dns",
              "redirect_uri",
              "decentralized_identifier",
              "verifier_attestation",
            ],
            default: "x509_hash",
            description:
              "Verifier client identifier prefix. redirect_uri is delivered only as a plain, unsigned Authorization Request.",
          },
          request_delivery: {
            type: "string",
            enum: ["by_reference", "by_value", "plain", "multisigned"],
            default: "by_reference",
            description:
              "Deliver a signed request object by reference or value, or a plain URL-encoded Authorization Request without request or request_uri. For the dc_api response modes this selects how the request reaches the browser instead: by_value produces a signed openid4vp-v1-signed request, multisigned an openid4vp-v1-multisigned request signed under both the x509_hash and decentralized_identifier Client Identifiers, plain an unsigned openid4vp-v1-unsigned one, by_reference is rejected, and the default becomes by_value. multisigned is rejected outside the dc_api response modes, with a client_id_scheme other than x509_hash, with verifier_info, and with signature-altering request behaviours.",
          },
          response_type: {
            type: "string",
            enum: ["vp_token", "vp_token id_token", "code"],
            default: "vp_token",
          },
          response_mode: {
            type: "string",
            enum: ["direct_post", "direct_post.jwt", "dc_api", "dc_api.jwt"],
            default: "direct_post.jwt",
            description:
              "Selects the presentation flow. direct_post and direct_post.jwt are redirect-based and return a wallet deeplink. dc_api and dc_api.jwt travel over the W3C Digital Credentials API: the response carries dc_api_request, deeplink points at the verifier's presentation page instead of a wallet, and request_uri, response_uri, and state are absent. The .jwt modes return the Authorization Response encrypted.",
          },
          presentation_request: {
            type: "object",
            additionalProperties: true,
            description:
              "Request Object claim overrides. Only response_type, dcql_query, nonce, state, scopes, transaction_data, and verifier_info are honoured here; delivery, response_mode, client_id_scheme, scheme, redirect_uri, and client_metadata are top-level fields and are ignored when nested.",
          },
          dcql_query: {
            oneOf: [{ type: "object", additionalProperties: true }, { type: "null" }],
            description:
              "DCQL query, or null to omit dcql_query from the wallet-facing Authorization Request. The verifier keeps a query for verification either way, because the Authorization Response is matched against the request object this service signs; use null together with scopes for a Section 5.1 scope-based request. Set require_cryptographic_holder_binding on individual credential entries to request unbound presentations where supported.",
          },
          state: {
            type: "null",
            description:
              "null omits state from the Authorization Request and from the request the verifier checks the response against; any other value is rejected with invalid_state. OpenID4VP Section 5.3 makes state mandatory when a credential entry sets require_cryptographic_holder_binding: false outside the DC API, so such a response is captured as presentation_invalid. DC API requests never carry state.",
          },
          scopes: { oneOf: [{ type: "string" }, { type: "array", items: { type: "string" } }] },
          verifier_attestation: {
            type: "object",
            additionalProperties: false,
            description:
              'Content of the Verifier Attestation JWT delivered in the request object\'s jwt JOSE header. Requires client_id_scheme: "verifier_attestation". The attestation is signed by a fixture issuer whose public key is published at /openid4vp/verifier-attestation-issuer/jwks.json, confirms the request signing key in cnf, and by default carries no redirect_uris claim.',
            properties: {
              subject: {
                type: "string",
                description:
                  "Attestation sub. The Client Identifier keeps the real subject, so setting this makes the two disagree.",
              },
              issuer: {
                type: "string",
                description: "Attestation iss, for an issuer outside a wallet's trusted list.",
              },
              redirect_uris: {
                type: "array",
                items: { type: "string" },
                description:
                  "redirect_uris claim. Omitted from the attestation when absent. An entry equal to the literal {{response_uri}} is replaced with the session's own response_uri at session creation; the placeholder is refused for the DC API response modes, which have no response_uri. The resolved content is recorded in the session's verifier_attestation.",
              },
              claims: { type: "object", additionalProperties: true },
              signature: {
                type: "string",
                enum: ["corrupt"],
                description:
                  "Breaks the attestation signature while leaving the request object validly signed. Gated by FCAF_SCENARIOS_ENABLED.",
              },
            },
          },
          transaction_data: {
            description:
              "Transaction data. Array entries that are JSON objects are base64url-encoded as OpenID4VP Section 5.1 requires; entries of any other type, strings included, are delivered exactly as supplied, and a value that is not an array is passed through untouched.",
          },
          verifier_info: {
            description:
              "Verifier Info array, delivered exactly as supplied. OpenID4VP Section 5.11 leaves the format and semantics to ecosystems and profiles, so this service signs no attestation of its own; bind a key-bound attestation by choosing the nonce and reading the Client Identifier from /openid4vp/client-identifiers.",
          },
          client_metadata: {
            oneOf: [{ type: "object", additionalProperties: true }, { type: "null" }],
            description:
              'Overrides individual members of the generated verifier metadata: a supplied member wins, an omitted member keeps its generated value, and a member set to null is dropped. The merge is one level deep, so supplying jwks replaces the whole key set. Use null for the whole object to omit the parameter, which is supported only with direct_post. Top-level only; a value inside presentation_request is ignored. Narrow the advertised response encryption with {"encrypted_response_enc_values_supported":["A128GCM"]} to give the Wallet a single JWE enc choice. For direct_post.jwt the merged metadata must keep the session\'s generated encryption public key, compared by RFC 7638 thumbprint so that alg, use, and kid may be altered or omitted; replacing or dropping jwks requires allow_undecryptable_response.',
          },
          allow_undecryptable_response: {
            type: "boolean",
            default: false,
            description:
              "Test-only. Publish a jwks that is not the verifier's encryption public key for direct_post.jwt, so the service cannot decrypt a response. Requires a client_metadata object. Any direct_post.jwt request sent without the verifier encryption key records a vp_undecryptable_response_allowed session event.",
          },
          redirect_uri: {
            oneOf: [
              { type: "string", format: "uri" },
              { type: "string", const: "{{base_url}}/openid4vp/redirect" },
            ],
            description:
              "Absolute URI inserted into the wallet-facing Authorization Request and returned to the Wallet after a successful presentation. The service appends a fresh response_code parameter. The capture template creates a service-hosted confirmation page and records valid visits.",
          },
          request_mutation: { $ref: "#/components/schemas/RequestMutation" },
          request_behavior: { $ref: "#/components/schemas/RequestBehavior" },
          response_scenario: { $ref: "#/components/schemas/ResponseScenario" },
        },
        additionalProperties: true,
      },
      RequestMutation: {
        type: "object",
        description:
          "Test-only, refused unless the deployment sets FCAF_SCENARIOS_ENABLED. Deliberate edits to the wallet-facing Authorization Request, addressed by RFC 6901 JSON Pointer because protocol object keys contain dots and plus signs. The verifier keeps verifying against the request it generated: a mutation changes only the copy the Wallet receives, and both are recorded in the session capture.",
        properties: {
          outer_request: { $ref: "#/components/schemas/RequestMutationEdits" },
          request_object: { $ref: "#/components/schemas/RequestMutationEdits" },
          request_object_header: { $ref: "#/components/schemas/RequestMutationEdits" },
          verification_applies: {
            type: "boolean",
            description:
              "Recorded as evidence, never enforced: whether the caller still expects normal presentation verification to succeed.",
          },
        },
        additionalProperties: false,
      },
      RequestMutationEdits: {
        type: "object",
        description:
          "Writes are applied before removals. A member set to null is sent as null, which is a different wire outcome from removing it.",
        properties: {
          set: {
            type: "object",
            description: "JSON Pointer to the value written there, of any JSON type.",
            additionalProperties: true,
          },
          unset: {
            type: "array",
            items: { type: "string" },
            description: "JSON Pointers whose member is removed entirely.",
          },
        },
        additionalProperties: false,
      },
      RequestBehavior: {
        type: "object",
        description:
          "Test-only, refused unless the deployment sets FCAF_SCENARIOS_ENABLED. Request-delivery behaviours that are not payload values, so a request_mutation pointer cannot express them.",
        properties: {
          signing_key: {
            type: "string",
            enum: ["unrelated"],
            description:
              "Sign the Request Object with a key that is not the one bound to the advertised client identifier, leaving the certificate or DID document untouched. Requires a signed request.",
          },
          certificate_chain: {
            type: "string",
            enum: [
              "unrelated_self_signed",
              "untrusted_root",
              "incomplete_chain",
              "with_trust_anchor",
            ],
            description:
              "Present a different X.509 chain in x5c. The generated chains come from the same Credo X.509 path the service uses for its own material; the request stays validly signed by that chain's leaf key and the x509_hash Client Identifier is recomputed from it, so the chain is the only defect. with_trust_anchor instead delivers [deployed verifier certificate, configured CA certificate] signed by the normal key, with the Client Identifier unchanged, so the trust anchor inside x5c is the only defect; a Wallet is expected to reject it (WS_RP_SM_RpIntegrity__025). The CA is read from verifier/verifier-ca-certificate.pem in the data directory: its absence is refused with verifier_ca_certificate_not_configured, and a CA that does not validate the deployed verifier certificate under Credo's chain validation with verifier_ca_certificate_invalid. Requires the x509_hash client identifier prefix.",
          },
          wallet_nonce: {
            type: "string",
            enum: ["echo", "mismatch", "omit"],
            default: "echo",
            description:
              "How the POST Request URI flow answers the wallet_nonce the Wallet supplied: echo it, return a different one, or omit it. The received and returned values are both recorded in the vp_request_retrieved event.",
          },
          request_uri_response: {
            type: "object",
            description:
              "Serve the Request URI with a deliberately wrong HTTP response. The signed Request Object is still generated and captured; only what the endpoint returns changes.",
            properties: {
              status: { type: "integer", minimum: 100, maximum: 599 },
              content_type: { type: "string" },
              body: { type: "string" },
            },
            additionalProperties: false,
          },
          request_object_encryption: {
            type: "string",
            enum: ["none"],
            description:
              "Serve the signed Request Object unencrypted even when the Wallet's POST Request URI wallet_metadata supplied encryption keys. Recorded as a vp_request_object_encryption_skipped event.",
          },
          signature: {
            type: "string",
            enum: ["corrupt"],
            description:
              "Deliver a Request Object whose signature does not verify. The request is signed normally first and the signature value is then invalidated, so the JWS stays well formed and the Wallet rejects it on the signature. Requires a signed request, so it is refused with the redirect_uri client identifier prefix.",
          },
        },
        additionalProperties: false,
      },
      ResponseScenario: {
        type: "object",
        description:
          "Test-only, refused unless the deployment sets FCAF_SCENARIOS_ENABLED. Controls the HTTP response returned to the Wallet after it submits an Authorization Response. It changes only what the Wallet is told: the recorded verification result, session status, and checks are unaffected, so a test-selected 400 never marks a valid presentation invalid and a test-selected 200 never marks an invalid one verified.",
        properties: {
          status: { type: "integer", minimum: 100, maximum: 599 },
          content_type: { type: "string" },
          body: {
            type: "string",
            description: "Exact response body, replacing the normal JSON body.",
          },
          extra_parameters: {
            type: "object",
            additionalProperties: true,
            description:
              "Members merged into the normal JSON body, for an unrecognised response parameter or an error member.",
          },
        },
        additionalProperties: false,
      },
      PresentationSessionCreated: {
        type: "object",
        required: [
          "session_id",
          "request_delivery",
          "response_mode",
          "deeplink",
          "authorization_request",
          "status",
        ],
        properties: {
          session_id: { type: "string", format: "uuid" },
          request_delivery: { type: "string" },
          request_uri: {
            type: "string",
            format: "uri",
            description: "Redirect flows only; absent for the dc_api response modes.",
          },
          request_uri_method: {
            type: "string",
            description: "Redirect flows only; absent for the dc_api response modes.",
          },
          response_mode: { type: "string" },
          scheme: {
            type: "string",
            description: "Redirect flows only; absent for the dc_api response modes.",
          },
          response_uri: {
            type: "string",
            format: "uri",
            description: "Redirect flows only; absent for the dc_api response modes.",
          },
          redirect_uri: { type: "string", format: "uri" },
          deeplink: {
            type: "string",
            description:
              "Wallet invocation URL for the redirect flows. For the dc_api response modes it is the HTTPS URL of this service's presentation page at /ui/openid4vp/sessions/{sessionId}/dc_api_presentation, built from the configured public base URL. Scanning it opens a webpage, it does not invoke a wallet.",
          },
          dc_api_request: {
            $ref: "#/components/schemas/DcApiRequest",
          },
          authorization_request: { type: "object", additionalProperties: true },
          status: { type: "string", const: "created" },
        },
      },
      DcApiRequest: {
        type: "object",
        required: ["protocol", "data"],
        description:
          "Present for the dc_api response modes. Pass as one entry of navigator.credentials.get({ digital: { requests: [ ... ] } }).",
        properties: {
          protocol: {
            type: "string",
            enum: ["openid4vp-v1-signed", "openid4vp-v1-multisigned", "openid4vp-v1-unsigned"],
          },
          data: {
            type: "object",
            additionalProperties: true,
            description:
              "For openid4vp-v1-signed a single request member holding the compact signed Request Object. For openid4vp-v1-multisigned a single request member holding the JWS JSON Serialization object: a payload without client_id and one signatures entry per Client Identifier, each carrying its client_id in the protected header. For openid4vp-v1-unsigned the Authorization Request parameters themselves, without client_id or expected_origins.",
          },
        },
      },
      PresentationSession: {
        type: "object",
        required: ["session_id", "status", "authorization_request", "observed", "checks", "events"],
        properties: {
          redirect_uri_visited_at: { type: "string", format: "date-time" },
          redirect_uri_visit_count: { type: "integer", minimum: 1 },
          verifier_attestation: {
            type: "object",
            additionalProperties: true,
            description:
              "Present when verifier_attestation content was supplied: the content signed into the attestation, with {{response_uri}} already replaced by the session's response_uri.",
          },
          request_object_encryption: {
            type: "object",
            required: ["alg", "enc", "kid", "alg_source", "enc_source"],
            description:
              "Present once a POST Request URI served the Request Object encrypted; the latest retrieval wins. Also the detail of the vp_request_object_encrypted event.",
            properties: {
              alg: { type: "string", const: "ECDH-ES" },
              enc: { type: "string" },
              kid: { type: ["string", "null"] },
              alg_source: {
                type: "string",
                enum: ["request_object", "authorization_encryption", "default"],
              },
              enc_source: {
                type: "string",
                enum: ["request_object", "authorization_encryption", "default"],
              },
            },
          },
          raw: {
            type: "object",
            properties: {
              authorization_request_jwt: {
                type: "string",
                description:
                  "Exact signed request object returned to the Wallet, or the signed JWT enclosed in authorization_request_jwe when the Request Object was encrypted.",
              },
              authorization_request_jwe: {
                type: "string",
                description:
                  "Exact encrypted Request Object returned from a POST Request URI whose wallet_metadata supplied an encryption key.",
              },
              request_uri_http: {
                $ref: "#/components/schemas/RequestUriHttpCapture",
              },
              presentation_response_http: {
                $ref: "#/components/schemas/PresentationResponseHttpCapture",
              },
              presentation_response_verifier_http: {
                $ref: "#/components/schemas/VerifierResponseHttpCapture",
              },
              redirect_uri_visits: {
                type: "array",
                items: { $ref: "#/components/schemas/RedirectUriVisitHttpCapture" },
              },
            },
            additionalProperties: true,
          },
        },
        additionalProperties: true,
      },
      PresentationResponseHttpCapture: {
        type: "object",
        required: ["method", "headers", "body"],
        description:
          "Machine-readable wallet presentation response evidence. Sensitive header values are redacted.",
        properties: {
          method: { type: "string" },
          headers: { type: "object", additionalProperties: true },
          body: { type: "string" },
        },
      },
      RequestUriHttpCapture: {
        type: "object",
        required: ["method", "target", "headers"],
        description:
          "Machine-readable wallet request to retrieve the request object, for both GET and POST Request URI retrieval. Sensitive header values are redacted; body is present only when received.",
        properties: {
          method: { type: "string" },
          target: {
            type: "string",
            description:
              "Request target, path plus query, exactly as received by this service. This is after any reverse proxy, so a proxy that rewrites the path or query changes what is recorded.",
          },
          headers: { type: "object", additionalProperties: true },
          body: { type: "string" },
        },
      },
      VerifierResponseHttpCapture: {
        type: "object",
        required: ["status", "headers", "body"],
        description:
          "Machine-readable verifier response to the Wallet. Sensitive header values are redacted.",
        properties: {
          status: { type: "integer" },
          headers: { type: "object", additionalProperties: true },
          body: { type: "string" },
        },
      },
      RedirectUriVisitHttpCapture: {
        type: "object",
        required: ["method", "headers"],
        description: "Redirect-page visit evidence. Sensitive header values are redacted.",
        properties: {
          method: { type: "string" },
          headers: { type: "object", additionalProperties: true },
        },
      },
      TokenResponse: {
        type: "object",
        required: ["access_token", "token_type", "expires_in"],
        properties: {
          access_token: { type: "string" },
          token_type: { type: "string", const: "DPoP" },
          expires_in: { type: "integer" },
          authorization_details: {
            type: "array",
            description:
              "Present when authorization_details was requested at PAR or the token endpoint (OpenID4VCI 1.0 Section 6.2).",
            items: {
              type: "object",
              required: ["type", "credential_configuration_id", "credential_identifiers"],
              properties: {
                type: { type: "string", const: "openid_credential" },
                credential_configuration_id: { type: "string" },
                credential_identifiers: {
                  type: "array",
                  minItems: 1,
                  items: { type: "string" },
                },
              },
            },
          },
        },
      },
    },
  };
}
