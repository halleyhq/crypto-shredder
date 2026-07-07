import { randomBytes } from "node:crypto";
import { Injectable, Logger } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import type { Model } from "mongoose";
import { EncryptionKey } from "../schemas/encryption-key.schema";

/** In-process cache entry with 15-minute TTL */
interface CacheEntry {
  key: Buffer;
  cachedAt: number; // Date.now()
}

const TTL_MS = 15 * 60 * 1000; // 15 minutes

/**
 * Manages per-entity AES-256-GCM encryption keys stored in MongoDB.
 *
 * Key lifecycle:
 *  1. getOrCreateKey() – creates a new 32-byte key on first call; cached for 15 min.
 *  2. getKey()         – returns the active key, or null if deleted/missing.
 *  3. deleteKey()      – soft-deletes (sets deletedAt), evicts cache.
 *
 * After deleteKey(), getOrCreateKey() throws to prevent accidental re-keying
 * of an already-erased subject.
 */
@Injectable()
export class EncryptionKeyService {
  private readonly logger = new Logger(EncryptionKeyService.name);
  private readonly cache = new Map<string, CacheEntry>();

  constructor(
    @InjectModel(EncryptionKey.name)
    private readonly keyModel: Model<EncryptionKey>,
  ) {}

  private keyId(subjectType: string, subjectId: string): string {
    return `${subjectType}:${subjectId}`;
  }

  private fromCache(id: string): Buffer | null {
    const entry = this.cache.get(id);
    if (!entry) return null;
    if (Date.now() - entry.cachedAt > TTL_MS) {
      this.cache.delete(id);
      return null;
    }
    return entry.key;
  }

  private toCache(id: string, key: Buffer): void {
    this.cache.set(id, { key, cachedAt: Date.now() });
  }

  /**
   * Return the active encryption key for (subjectType, subjectId), creating it if it
   * does not yet exist.  Throws if the key has been previously deleted (GDPR erasure).
   */
  async getOrCreateKey(subjectType: string, subjectId: string): Promise<Buffer> {
    const id = this.keyId(subjectType, subjectId);

    const cached = this.fromCache(id);
    if (cached) return cached;

    let record = await this.keyModel.findOne({ _id: id, deletedAt: null }).lean().exec();

    if (!record) {
      // Guard against re-keying an already-erased subject
      const deleted = await this.keyModel.findOne({ _id: id }).lean().exec();
      if (deleted?.deletedAt) {
        throw new Error(
          `Encryption key for ${id} has been deleted (GDPR erasure). ` +
            "Cannot encrypt new events for an erased subject.",
        );
      }

      // Create a fresh 32-byte AES-256 key
      const keyMaterial = randomBytes(32).toString("base64");
      record = await this.keyModel.create({
        _id: id,
        subjectType,
        subjectId,
        keyMaterial,
        createdAt: new Date(),
        deletedAt: null,
      });

      this.logger.log(`Created encryption key for ${id}`);
    }

    const key = Buffer.from(record.keyMaterial, "base64");
    this.toCache(id, key);
    return key;
  }

  /**
   * Return the active encryption key, or null if it has been deleted or never existed.
   * Used on the read/decrypt path — graceful fallback to '[DELETED]' is handled by caller.
   */
  async getKey(subjectType: string, subjectId: string): Promise<Buffer | null> {
    const id = this.keyId(subjectType, subjectId);

    const cached = this.fromCache(id);
    if (cached) return cached;

    const record = await this.keyModel.findOne({ _id: id, deletedAt: null }).lean().exec();
    if (!record) return null;

    const key = Buffer.from(record.keyMaterial, "base64");
    this.toCache(id, key);
    return key;
  }

  /**
   * Soft-delete the encryption key for a subject (GDPR crypto shredding).
   * After this call, getKey() returns null and getOrCreateKey() throws.
   */
  async deleteKey(subjectType: string, subjectId: string): Promise<void> {
    const id = this.keyId(subjectType, subjectId);
    await this.keyModel
      .updateOne({ _id: id }, { $set: { deletedAt: new Date(), keyMaterial: "" } })
      .exec();
    this.cache.delete(id);
    this.logger.log(`Deleted encryption key for ${id} (GDPR erasure)`);
  }
}
