import type { Model } from "mongoose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { EncryptionKey } from "../schemas/encryption-key.schema";
import { EncryptionKeyService } from "./encryption-key.service";

interface FakeRecord {
  _id: string;
  subjectType: string;
  subjectId: string;
  keyMaterial: string;
  createdAt: Date;
  deletedAt: Date | null;
}

/** Minimal in-memory stand-in for the slice of the Mongoose Model API this service uses. */
function createFakeModel() {
  const store = new Map<string, FakeRecord>();

  const model = {
    findOne: vi.fn((query: { _id: string; deletedAt?: null }) => ({
      lean: () => ({
        exec: async () => {
          const doc = store.get(query._id);
          if (!doc) return null;
          if (query.deletedAt === null && doc.deletedAt !== null) return null;
          return doc;
        },
      }),
    })),
    create: vi.fn(async (doc: FakeRecord) => {
      const saved = { ...doc };
      store.set(doc._id, saved);
      return saved;
    }),
    updateOne: vi.fn((query: { _id: string }, update: { $set: Partial<FakeRecord> }) => ({
      exec: async () => {
        const doc = store.get(query._id);
        if (doc) Object.assign(doc, update.$set);
      },
    })),
  };

  return model;
}

describe("EncryptionKeyService", () => {
  let model: ReturnType<typeof createFakeModel>;
  let service: EncryptionKeyService;

  beforeEach(() => {
    model = createFakeModel();
    service = new EncryptionKeyService(model as unknown as Model<EncryptionKey>);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("creates a new 32-byte key on first call", async () => {
    const key = await service.getOrCreateKey("customer", "cust-1");
    expect(key).toBeInstanceOf(Buffer);
    expect(key.length).toBe(32);
    expect(model.create).toHaveBeenCalledOnce();
  });

  it("serves subsequent calls from the in-process cache without hitting the store", async () => {
    const first = await service.getOrCreateKey("customer", "cust-2");
    model.findOne.mockClear();

    const second = await service.getOrCreateKey("customer", "cust-2");

    expect(second).toEqual(first);
    expect(model.findOne).not.toHaveBeenCalled();
  });

  it("getKey returns null for a subject that has no key", async () => {
    expect(await service.getKey("customer", "unknown")).toBeNull();
  });

  it("getKey reads a key created by another instance sharing the same store", async () => {
    const created = await service.getOrCreateKey("customer", "cust-3");

    const otherInstance = new EncryptionKeyService(model as unknown as Model<EncryptionKey>);
    const fetched = await otherInstance.getKey("customer", "cust-3");

    expect(fetched).toEqual(created);
  });

  it("deleteKey soft-deletes: getKey returns null and getOrCreateKey throws afterwards", async () => {
    await service.getOrCreateKey("customer", "cust-4");

    await service.deleteKey("customer", "cust-4");

    expect(await service.getKey("customer", "cust-4")).toBeNull();
    await expect(service.getOrCreateKey("customer", "cust-4")).rejects.toThrow(/has been deleted/);
  });

  it("expires the cache after the 15-minute TTL and re-reads from the store", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));

    await service.getOrCreateKey("customer", "cust-5");
    model.findOne.mockClear();

    vi.setSystemTime(new Date("2026-01-01T00:16:00.000Z")); // +16 minutes
    await service.getKey("customer", "cust-5");

    expect(model.findOne).toHaveBeenCalledOnce();
  });
});
