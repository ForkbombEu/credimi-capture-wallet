import type { Mdoc, MdocSignOptions } from "@credo-ts/core";
import { DataItem, cborDecode, cborEncode } from "@owf/cose";
import { CoseKey, IssuerAuth, IssuerSigned } from "@owf/mdoc";
import type { StatusReferenceFixture } from "./types.js";

export type MdocSignOptionsWithStatusReference = MdocSignOptions & {
  statusReference?: StatusReferenceFixture;
};

type MdocStatusSigner = (options: {
  algorithm: string;
  data: Uint8Array;
  keyId: string;
}) => Promise<Uint8Array>;

/**
 * Credo signs ordinary mdocs. This narrowly scoped reconstruction is only for the status-list
 * negative fixtures that @owf/token-status-list correctly refuses to construct.
 */
export async function applyMdocStatusReferenceFixture(
  mdoc: Mdoc,
  options: MdocSignOptionsWithStatusReference,
  sign: MdocStatusSigner,
): Promise<Mdoc> {
  const fixture = options.statusReference;
  if (!fixture || fixture === "valid") return mdoc;

  const issuerAuth = mdoc.issuerSigned.issuerAuth;
  if (!issuerAuth.payload) throw new Error("Signed mdoc is missing its Mobile Security Object");

  const payload = malformedStatusPayload(issuerAuth.payload, fixture);
  const issuerCertificate = Array.isArray(options.issuerCertificate)
    ? options.issuerCertificate[0]
    : options.issuerCertificate;
  const signingKey = CoseKey.fromJwk(issuerCertificate.publicJwk.toJson());
  const keyId = signingKey.keyId;
  const algorithm = issuerAuth.jwaAlgorithm;
  if (!keyId || !algorithm) {
    throw new Error("Signed mdoc is missing the issuer key identifier or signature algorithm");
  }

  const malformedIssuerAuth = await IssuerAuth.create({
    payload,
    protectedHeaders: issuerAuth.protectedHeaders,
    unprotectedHeaders: issuerAuth.unprotectedHeaders,
  }).sign(
    { signingKey, algorithm: issuerAuth.algorithm },
    {
      sign: ({ toBeSigned }) => sign({ algorithm, data: toBeSigned, keyId }),
    },
  );
  const issuerSigned = IssuerSigned.create({
    issuerAuth: malformedIssuerAuth,
    issuerNamespaces: mdoc.issuerSigned.issuerNamespaces,
  });

  return { base64Url: issuerSigned.encodedForOid4Vci } as Mdoc;
}

function malformedStatusPayload(
  payload: Uint8Array,
  fixture: Exclude<StatusReferenceFixture, "valid">,
): Uint8Array {
  const dataItem = cborDecode(payload, { unwrapTopLevelDataItem: false });
  if (!(dataItem instanceof DataItem) || !(dataItem.data instanceof Map)) {
    throw new Error("Signed mdoc Mobile Security Object is not an encoded CBOR map");
  }

  const mobileSecurityObject = new Map(dataItem.data);
  const status = mobileSecurityObject.get("status");
  if (!(status instanceof Map)) throw new Error("Signed mdoc is missing its status structure");
  const malformedStatus = new Map(status);

  if (fixture === "status_without_status_list") {
    malformedStatus.delete("status_list");
  } else {
    const statusList = malformedStatus.get("status_list");
    if (!(statusList instanceof Map))
      throw new Error("Signed mdoc is missing its status_list structure");
    const malformedStatusList = new Map(statusList);
    switch (fixture) {
      case "negative_index":
        malformedStatusList.set("idx", -1);
        break;
      case "missing_index":
        malformedStatusList.delete("idx");
        break;
      case "malformed_uri":
        malformedStatusList.set("uri", "not a uri");
        break;
      case "missing_uri":
        malformedStatusList.delete("uri");
        break;
    }
    malformedStatus.set("status_list", malformedStatusList);
  }

  mobileSecurityObject.set("status", malformedStatus);
  return cborEncode(DataItem.fromData(mobileSecurityObject));
}
