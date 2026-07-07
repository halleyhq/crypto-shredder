/**
 * Plain Map-based registry for @EncryptableEvent metadata.
 * No reflect-metadata dependency — decorators populate this at module load time.
 */

export interface EncryptableEventMetadata {
  /** Domain subject type, e.g. 'patient' | 'user' | 'customer' */
  subjectType: string;
  /** Name of the field on the event class that holds the subject ID */
  subjectIdField: string;
  /** String fields that contain PII and must be encrypted */
  piiFields: string[];
  /** Date fields that contain PII — encrypted as ISO strings, fallback to null on missing key */
  piiDateFields: string[];
}

const classRegistry = new Map<Function, EncryptableEventMetadata>();
const nameRegistry = new Map<string, EncryptableEventMetadata>();

/**
 * Register metadata for an event class.
 * Called by the @EncryptableEvent decorator at class-definition time.
 */
export function setEncryptableEventMetadata(
  target: Function,
  metadata: EncryptableEventMetadata,
): void {
  classRegistry.set(target, metadata);
  nameRegistry.set(target.name, metadata);
}

/**
 * Look up metadata by class reference or event type name string.
 * Returns undefined if the class is not annotated with @EncryptableEvent.
 */
export function getEncryptableEventMetadata(
  target: Function | string,
): EncryptableEventMetadata | undefined {
  if (typeof target === "string") {
    return nameRegistry.get(target);
  }
  return classRegistry.get(target);
}
