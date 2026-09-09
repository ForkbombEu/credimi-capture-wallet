import { afterEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_CONFIG } from "../src/config.js";
import { allocateStatusListReference, statusListCredentialType } from "../src/status-list.js";

const config = {
  ...DEFAULT_CONFIG,
  status_list_base_url: "http://status-list.example.test/",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("status-list allocation", () => {
  it("uses an mdoc doctype or SD-JWT vct as the allocation type", () => {
    expect(
      statusListCredentialType({
        id: "mdoc",
        scope: "mdoc",
        format: "mso_mdoc",
        proofPolicy: "jwt-proof",
        displayName: "mdoc",
        claimPaths: [],
      }),
    ).toBe("eu.europa.ec.eudi.pid.1");
    expect(
      statusListCredentialType({
        id: "degree",
        scope: "degree",
        format: "dc+sd-jwt",
        proofPolicy: "jwt-proof",
        displayName: "degree",
        vct: "urn:credimi:degree:1",
        claimPaths: [],
      }),
    ).toBe("urn:credimi:degree:1");
  });

  it("sends the management request only when called and parses its public reference", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          status_list: {
            uri: "http://status-list.example.test/token_status_list/EU/pid/123",
            idx: 123,
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      allocateStatusListReference({
        config,
        allocationId: "session-id:0",
        doctype: "urn:eudi:pid:1",
      }),
    ).resolves.toEqual({
      uri: "http://status-list.example.test/token_status_list/EU/pid/123",
      idx: 123,
    });

    expect(fetchMock).toHaveBeenCalledOnce();
    const [input, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(input)).toBe("http://status-list.example.test/token_status_list/take");
    expect(init).toMatchObject({
      method: "POST",
      headers: expect.objectContaining({
        "x-api-key": "test",
        "content-type": "application/x-www-form-urlencoded",
      }),
    });
    expect(String(init?.body)).toContain("allocation_id=session-id%3A0");
  });

  it("fails closed when the allocator returns no valid reference", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response(JSON.stringify({ status_list: { uri: "", idx: "bad" } }), {
          status: 200,
        }),
      ),
    );

    await expect(
      allocateStatusListReference({
        config,
        allocationId: "session-id:0",
        doctype: "urn:eudi:pid:1",
      }),
    ).rejects.toThrow("valid status_list reference");
  });
});
