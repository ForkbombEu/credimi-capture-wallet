import { describe, expect, it } from "vitest";
import { indexPage } from "../src/ui.js";

describe("launcher issuer catalogue", () => {
  it("renders an explicit empty state when no issuers are available", () => {
    const page = indexPage([]);

    expect(page).toContain('<h2 id="issuer-catalogue-title">Available issuers</h2>');
    expect(page).toContain('<p class="issuer-empty">No issuers available</p>');
    expect(page).not.toContain('<article class="issuer-card">');
  });
});
