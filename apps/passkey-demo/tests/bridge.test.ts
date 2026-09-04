import { describe, expect, it, vi } from "vitest";
import { createApiHandler, linkArtifactBytecode, type ContractArtifact } from "../server";

describe("passkey demo bridge API", () => {
  it("links every artifact reference for a deployed library", () => {
    const placeholder = "00".repeat(20);
    const artifact = {
      abi: [],
      bytecode: {
        object: `0x11${placeholder}22${placeholder}33`,
        linkReferences: {
          "src/Library.sol": {
            Library: [
              { start: 1, length: 20 },
              { start: 22, length: 20 },
            ],
          },
        },
      },
    } satisfies ContractArtifact;
    const address = "0x1234567890123456789012345678901234567890";

    expect(linkArtifactBytecode(artifact, new Map([["src/Library.sol:Library", address]]))).toBe(
      `0x11${address.slice(2)}22${address.slice(2)}33`,
    );
  });

  it("keeps proof verification browser-local", async () => {
    const register = vi.fn();
    const response = await createApiHandler(register)(
      new Request("http://127.0.0.1/api/verify-passkey-proof", { method: "POST" }),
    );

    expect(response.status).toBe(501);
    await expect(response.json()).resolves.toEqual({
      error: "server-side proof verification is intentionally unavailable; verify in the browser",
    });
    expect(register).not.toHaveBeenCalled();
  });

  it("rejects malformed registration before touching Anvil", async () => {
    const register = vi.fn();
    const response = await createApiHandler(register)(
      new Request("http://127.0.0.1/api/register-passkey", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ publicKeyX: "0x01", publicKeyY: "0x02", slotIndex: 1 }),
      }),
    );

    expect(response.status).toBe(400);
    expect(register).not.toHaveBeenCalled();
  });

  it("passes a valid registration request to the registry bridge", async () => {
    const registry = { leafIndex: 1, root: "123" };
    const register = vi.fn().mockResolvedValue(registry);
    const body = {
      publicKeyX: `0x${"01".repeat(32)}`,
      publicKeyY: `0x${"02".repeat(32)}`,
      slotIndex: 1,
    };
    const response = await createApiHandler(register)(
      new Request("http://127.0.0.1/api/register-passkey", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      }),
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual(registry);
    expect(register).toHaveBeenCalledWith(body);
  });
});
