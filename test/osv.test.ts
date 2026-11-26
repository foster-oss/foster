import { afterEach, describe, expect, it, vi } from "vitest";
import { queryBatch } from "../src/lib/osv.js";
import type { Dependency } from "../src/lib/types.js";

const dependency = (name: string): Dependency => ({
  ecosystem: "npm", name, version: "1.0.0", direct: true, source: "test",
});

describe("queryBatch pagination", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("follows each query's page token and keeps the results with the right dependency", async () => {
    const requests: { url: string; body: Record<string, unknown> }[] = [];
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      requests.push({ url, body });

      if (url.endsWith("/querybatch")) {
        return Response.json({ results: [
          { vulns: [{ id: "OSV-1" }], next_page_token: "first-page" },
          { vulns: [{ id: "OSV-2" }] },
        ] });
      }
      if (body.page_token === "first-page") {
        return Response.json({ vulns: [{ id: "OSV-1" }, { id: "OSV-3" }], next_page_token: "second-page" });
      }
      return Response.json({ vulns: [{ id: "OSV-4" }] });
    });
    vi.stubGlobal("fetch", fetchMock);

    const results = await queryBatch([dependency("first"), dependency("second")]);

    expect(results).toEqual([["OSV-1", "OSV-3", "OSV-4"], ["OSV-2"]]);
    expect(requests).toHaveLength(3);
    expect(requests[1]).toMatchObject({
      url: "https://api.osv.dev/v1/query",
      body: { package: { name: "first", ecosystem: "npm" }, version: "1.0.0", page_token: "first-page" },
    });
    expect(requests[2]?.body.page_token).toBe("second-page");
  });
});
