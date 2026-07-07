import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { Injectable, Logger } from "@nestjs/common";
import { getEncryptableEventMetadata } from "../decorators/metadata-registry";
import { EncryptionKeyService } from "./encryption-key.service";

/** Minimal event shape: any plain object with a constructor */
type DomainEvent = object & { constructor: Function };

/**
 * Encrypted value format stored in the event store:
 *   enc:<iv-hex>:<authtag-hex>:<ciphertext-hex>
 *
 * Any value NOT starting with 'enc:' is treated as plaintext
 * (backward-compatible with pre-existing unencrypted events).
 */
const ENC_PREFIX = "enc:";

/**
 * Provides AES-256-GCM encrypt / decrypt for domain events annotated with
 * @EncryptableEvent.
 *
 * Write path: encryptEvent()     – call before persisting an event.
 * Read path:  decryptEventData() – call after reading an event back / before
 *             replaying it into a projection or aggregate.
 *
 * If the encryption key is missing (crypto-shredded), PII string fields fall back to
 * '[DELETED]' and PII date fields fall back to null.
 */
@Injectable()
export class CryptoShredderService {
  private readonly logger = new Logger(CryptoShredderService.name);

  constructor(private readonly keyService: EncryptionKeyService) {}

  /**
   * Encrypt all PII field values in the event.
   * Returns a plain object suitable for storage in the event store.
   * If the event class has no @EncryptableEvent metadata, the original data is returned as-is.
   */
  async encryptEvent(event: DomainEvent): Promise<Record<string, unknown>> {
    const eventClass = event.constructor as Function;
    const metadata = getEncryptableEventMetadata(eventClass);

    if (!metadata) {
      return event as unknown as Record<string, unknown>;
    }

    const raw = event as unknown as Record<string, unknown>;
    const subjectId = raw[metadata.subjectIdField] as string | undefined;

    if (!subjectId) {
      this.logger.warn(
        `Cannot encrypt ${eventClass.name}: field '${metadata.subjectIdField}' is missing`,
      );
      return raw;
    }

    const key = await this.keyService.getOrCreateKey(metadata.subjectType, subjectId);

    const result: Record<string, unknown> = { ...raw };

    for (const field of metadata.piiFields) {
      const value = result[field];
      if (value === undefined || value === null) continue;
      const str = typeof value === "string" ? value : String(value);
      result[field] = this.encryptValue(str, key);
    }

    for (const field of metadata.piiDateFields) {
      const value = result[field];
      if (value === undefined || value === null) continue;
      let iso: string;
      if (value instanceof Date) {
        if (Number.isNaN(value.getTime())) {
          this.logger.warn(
            `Skipping encryption of invalid Date in field '${field}' for ${subjectId}`,
          );
          continue;
        }
        iso = value.toISOString();
      } else {
        // Value may be a string coming from JSON-deserialized aggregate state
        const parsed = new Date(String(value));
        if (Number.isNaN(parsed.getTime())) {
          this.logger.warn(
            `Skipping encryption of unparseable date '${String(value)}' in field '${field}' for ${subjectId}`,
          );
          continue;
        }
        iso = parsed.toISOString();
      }
      result[field] = this.encryptValue(iso, key);
    }

    return result;
  }

  /**
   * Decrypt PII fields in raw event data read from the event store.
   *
   * @param eventTypeOrClass - Event class constructor OR event type name string
   * @param data             - Raw data object from the event store (may contain enc: values)
   * @returns Data object with PII fields decrypted (or '[DELETED]'/null on missing key)
   */
  async decryptEventData(
    eventTypeOrClass: Function | string,
    data: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const metadata = getEncryptableEventMetadata(eventTypeOrClass);

    if (!metadata) {
      return data;
    }

    const subjectId = data[metadata.subjectIdField] as string | undefined;
    if (!subjectId) {
      return data;
    }

    const key = await this.keyService.getKey(metadata.subjectType, subjectId);
    const result: Record<string, unknown> = { ...data };

    for (const field of metadata.piiFields) {
      const value = result[field];
      if (typeof value !== "string") continue;

      if (!value.startsWith(ENC_PREFIX)) continue; // plaintext (pre-shredding event)

      if (!key) {
        result[field] = "[DELETED]";
        continue;
      }

      try {
        result[field] = this.decryptValue(value, key);
      } catch {
        this.logger.warn(
          `Failed to decrypt field '${field}' for ${subjectId} — treating as [DELETED]`,
        );
        result[field] = "[DELETED]";
      }
    }

    for (const field of metadata.piiDateFields) {
      const value = result[field];
      if (typeof value !== "string") continue;

      if (!value.startsWith(ENC_PREFIX)) {
        // Plaintext value (pre-shredding event) — normalise to a Date object so callers
        // always receive a consistent type regardless of whether the field was encrypted.
        const plainDate = new Date(value);
        if (!Number.isNaN(plainDate.getTime())) {
          result[field] = plainDate;
        }
        continue;
      }

      if (!key) {
        result[field] = null;
        continue;
      }

      try {
        const decryptedStr = this.decryptValue(value, key);
        const date = new Date(decryptedStr);
        result[field] = Number.isNaN(date.getTime()) ? null : date;
      } catch {
        this.logger.warn(
          `Failed to decrypt date field '${field}' for ${subjectId} — treating as null`,
        );
        result[field] = null;
      }
    }

    return result;
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private encryptValue(plaintext: string, key: Buffer): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return `${ENC_PREFIX}${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted.toString("hex")}`;
  }

  private decryptValue(encrypted: string, key: Buffer): string {
    const parts = encrypted.split(":");
    if (parts.length !== 4 || parts[0] !== "enc") {
      throw new Error(`Invalid encrypted value format: expected 'enc:<iv>:<tag>:<ct>'`);
    }
    const iv = Buffer.from(parts[1], "hex");
    const authTag = Buffer.from(parts[2], "hex");
    const ciphertext = Buffer.from(parts[3], "hex");

    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString("utf8");
  }
}
