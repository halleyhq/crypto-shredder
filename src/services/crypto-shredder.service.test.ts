import { randomBytes } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import { EncryptableEvent } from "../decorators/encryptable-event.decorator";
import { CryptoShredderService } from "./crypto-shredder.service";
import type { EncryptionKeyService } from "./encryption-key.service";

@EncryptableEvent({
  subjectType: "customer",
  subjectIdField: "customerId",
  piiFields: ["name", "email"],
  piiDateFields: ["dateOfBirth"],
})
class CustomerRegisteredEvent {
  constructor(
    public customerId: string,
    public name: string,
    public email: string,
    public dateOfBirth: Date,
    public plan: string,
  ) {}
}

class PlainEvent {
  constructor(public foo: string) {}
}

/** Minimal in-memory stand-in for EncryptionKeyService's public surface. */
class FakeEncryptionKeyService {
  private readonly store = new Map<string, Buffer>();
  private readonly deleted = new Set<string>();

  async getOrCreateKey(subjectType: string, subjectId: string): Promise<Buffer> {
    const id = `${subjectType}:${subjectId}`;
    if (this.deleted.has(id)) {
      throw new Error(`Encryption key for ${id} has been deleted (GDPR erasure).`);
    }
    let key = this.store.get(id);
    if (!key) {
      key = randomBytes(32);
      this.store.set(id, key);
    }
    return key;
  }

  async getKey(subjectType: string, subjectId: string): Promise<Buffer | null> {
    return this.store.get(`${subjectType}:${subjectId}`) ?? null;
  }

  async deleteKey(subjectType: string, subjectId: string): Promise<void> {
    const id = `${subjectType}:${subjectId}`;
    this.store.delete(id);
    this.deleted.add(id);
  }
}

describe("CryptoShredderService", () => {
  let keyService: FakeEncryptionKeyService;
  let shredder: CryptoShredderService;

  beforeEach(() => {
    keyService = new FakeEncryptionKeyService();
    shredder = new CryptoShredderService(keyService as unknown as EncryptionKeyService);
  });

  it("returns undecorated events unchanged", async () => {
    const event = new PlainEvent("bar");
    const result = await shredder.encryptEvent(event);
    expect(result).toBe(event);
  });

  it("returns the raw event unchanged when the subject ID field is missing", async () => {
    const event = { name: "Ada" }; // no customerId
    Object.setPrototypeOf(event, CustomerRegisteredEvent.prototype);
    const result = await shredder.encryptEvent(event as CustomerRegisteredEvent);
    expect(result).toEqual(event);
  });

  it("encrypts PII string and date fields, leaving non-PII fields untouched", async () => {
    const event = new CustomerRegisteredEvent(
      "cust-1",
      "Ada Lovelace",
      "ada@example.com",
      new Date("1990-01-01T00:00:00.000Z"),
      "pro",
    );

    const encrypted = await shredder.encryptEvent(event);

    expect(encrypted.name).not.toBe("Ada Lovelace");
    expect(encrypted.email).not.toBe("ada@example.com");
    expect(String(encrypted.name)).toMatch(/^enc:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);
    expect(String(encrypted.dateOfBirth)).toMatch(/^enc:/);
    expect(encrypted.plan).toBe("pro");
    expect(encrypted.customerId).toBe("cust-1");
  });

  it("round-trips encrypt -> decrypt back to the original values", async () => {
    const event = new CustomerRegisteredEvent(
      "cust-2",
      "Grace Hopper",
      "grace@example.com",
      new Date("1985-06-15T00:00:00.000Z"),
      "free",
    );

    const encrypted = await shredder.encryptEvent(event);
    const decrypted = await shredder.decryptEventData(CustomerRegisteredEvent, encrypted);

    expect(decrypted.name).toBe("Grace Hopper");
    expect(decrypted.email).toBe("grace@example.com");
    expect((decrypted.dateOfBirth as Date).toISOString()).toBe("1985-06-15T00:00:00.000Z");
  });

  it("resolves metadata by event type name string as well as by class", async () => {
    const event = new CustomerRegisteredEvent(
      "cust-3",
      "Alan Turing",
      "alan@example.com",
      new Date("1912-06-23T00:00:00.000Z"),
      "pro",
    );

    const encrypted = await shredder.encryptEvent(event);
    const decrypted = await shredder.decryptEventData("CustomerRegisteredEvent", encrypted);

    expect(decrypted.name).toBe("Alan Turing");
  });

  it("passes plaintext (pre-shredding) values through unchanged for backward compatibility", async () => {
    const legacyData = {
      customerId: "cust-4",
      name: "Plaintext Name",
      email: "plaintext@example.com",
      dateOfBirth: "2000-01-01T00:00:00.000Z",
      plan: "free",
    };

    const decrypted = await shredder.decryptEventData(CustomerRegisteredEvent, legacyData);

    expect(decrypted.name).toBe("Plaintext Name");
    expect(decrypted.email).toBe("plaintext@example.com");
    expect(decrypted.dateOfBirth).toBeInstanceOf(Date);
  });

  it("falls back to [DELETED] / null when the encryption key has been shredded", async () => {
    const event = new CustomerRegisteredEvent(
      "cust-5",
      "Erased Person",
      "erased@example.com",
      new Date("1970-01-01T00:00:00.000Z"),
      "pro",
    );

    const encrypted = await shredder.encryptEvent(event);
    await keyService.deleteKey("customer", "cust-5");

    const decrypted = await shredder.decryptEventData(CustomerRegisteredEvent, encrypted);

    expect(decrypted.name).toBe("[DELETED]");
    expect(decrypted.email).toBe("[DELETED]");
    expect(decrypted.dateOfBirth).toBeNull();
    // Non-PII and structural fields remain — the audit trail survives the erasure.
    expect(decrypted.customerId).toBe("cust-5");
    expect(decrypted.plan).toBe("pro");
  });

  it("falls back to [DELETED] / null when a value fails to decrypt (corrupted ciphertext)", async () => {
    const corrupted = {
      customerId: "cust-6",
      name: "enc:not:valid:hex-but-wrong-length",
      email: "enc:zz:zz:zz",
      dateOfBirth: "enc:zz:zz:zz",
      plan: "pro",
    };
    // Ensure a key exists so the code attempts decryption rather than short-circuiting.
    await keyService.getOrCreateKey("customer", "cust-6");

    const decrypted = await shredder.decryptEventData(CustomerRegisteredEvent, corrupted);

    expect(decrypted.name).toBe("[DELETED]");
    expect(decrypted.email).toBe("[DELETED]");
    expect(decrypted.dateOfBirth).toBeNull();
  });
});
