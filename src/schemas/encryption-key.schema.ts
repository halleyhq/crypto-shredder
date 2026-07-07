import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import type { HydratedDocument } from "mongoose";

export type EncryptionKeyDocument = HydratedDocument<EncryptionKey>;

/**
 * Mongoose schema for per-entity AES-256-GCM encryption keys.
 *
 * Document _id: '<subjectType>:<subjectId>' e.g. 'customer:uuid-123'
 * Key material is base64-encoded 32-byte random data.
 * deletedAt null = active key; non-null = crypto shredded (GDPR erasure).
 */
@Schema({ collection: "encryption_keys", timestamps: false })
export class EncryptionKey {
  @Prop({ required: true, type: String })
  _id!: string;

  @Prop({ required: true, type: String })
  subjectType!: string;

  @Prop({ required: true, type: String })
  subjectId!: string;

  /** Base64-encoded 32-byte AES-256 key material */
  @Prop({ required: true, type: String })
  keyMaterial!: string;

  @Prop({ required: true, type: Date })
  createdAt!: Date;

  /** null = active; Date = soft-deleted (key shredded for GDPR erasure) */
  @Prop({ type: Date, default: null })
  deletedAt!: Date | null;
}

export const EncryptionKeySchema = SchemaFactory.createForClass(EncryptionKey);
