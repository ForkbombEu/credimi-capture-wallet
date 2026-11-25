import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/server/app.js";
import { serverTestSuite } from "./support/server.js";

const { config } = serverTestSuite("brand-assets-test-");

/**
 * SHA-256 of each brand asset as the Credimi Extras template ships it (`brand/` in
 * credimi-extras-template). The logo values are the ones its DESIGN.md §1 pins; the stylesheet
 * and fonts are maintained there, so a template update means copying the files and these hashes.
 */
const CANONICAL_SHA256: Record<string, string> = {
  "src/design/style.css": "1385c61b7cbd177296057e48b4282009b3871432646e0253010e600a11e575f8",
  "src/design/fonts/InterVariable.ttf":
    "29160a80ff49ddcab2c97711247e08b1fab27a484a329ce8b813d820dc559031",
  "src/design/fonts/InterVariable.OFL.txt":
    "5b9321a4298cfeb6b34354164a1c3afc3db114569984c502b9b35d988fd58c57",
  "src/design/fonts/SourceCodeProVariable.ttf":
    "b400fc584e10aff25d0e775ce181b4fc1c5ea1b5dc37b81aeb2084375b945790",
  "src/design/fonts/SourceCodeProVariable.OFL.txt":
    "cb30d3086a8b3ce0b9e3690bf48d6620402b61160bc658076f95180ccd9e9dae",
  "src/design/logo/credimi_logo.svg":
    "031885760a9165e9d8d49eab45baca30ba5ed8dd1fbf0b4699fba2de5dc4feac",
  "src/design/logo/credimi_logo_negative.svg":
    "32df33f9f5ffa696d452e1f65f5d6738b920415c5114db4b010af1f997a8cb3a",
  "src/design/logo/credimi_logo-transp.svg":
    "8407a3ed0beddc137599f71498f1ca8e68766a2684dba80093ea25e17173eef7",
  "src/design/logo/credimi_logo-transp_white.svg":
    "196017744fca7d3836720995aca8c55c8531908e8dcdafc5ca5e7b48ef8f7e10",
};

describe("brand assets", () => {
  it("keeps every runtime copy byte-for-byte equal to the template's", () => {
    for (const [path, sha256] of Object.entries(CANONICAL_SHA256)) {
      expect(createHash("sha256").update(readFileSync(path)).digest("hex"), path).toBe(sha256);
    }
  });

  it("serves every font the stylesheet declares, and no other file from the fonts directory", async () => {
    const app = createApp(config);
    const stylesheet = await request(app).get("/assets/style.css");
    const fonts = Array.from(
      stylesheet.text.matchAll(/url\(["']fonts\/([^"']+)["']\)/g),
      ([, file]) => file,
    );
    expect(fonts.length).toBeGreaterThan(0);

    for (const file of fonts) {
      const response = await request(app).get(`/assets/fonts/${file}`);
      expect(response.status, file).toBe(200);
      expect(response.type, file).toBe("font/ttf");
      expect(response.body).toEqual(readFileSync(`src/design/fonts/${file}`));
    }
    expect((await request(app).get("/assets/fonts/InterVariable.OFL.txt")).status).toBe(404);
  });
});
