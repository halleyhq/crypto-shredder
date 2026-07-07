import { setEncryptableEventMetadata } from "./metadata-registry";

export interface EncryptableEventOptions {
  /** Domain subject type stored in the encryption key record, e.g. 'patient' | 'user' | 'customer' */
  subjectType: string;
  /** Name of the field on the event that holds the aggregate/subject ID */
  subjectIdField: string;
  /** String PII fields to encrypt (fallback: '[DELETED]' when key is missing) */
  piiFields?: string[];
  /** Date PII fields to encrypt — stored as ISO strings (fallback: null when key is missing) */
  piiDateFields?: string[];
}

/**
 * Class decorator that marks an event as containing PII fields to be
 * encrypted via AES-256-GCM before writing to the event store.
 *
 * Usage:
 * ```typescript
 * @EncryptableEvent({
 *   subjectType: 'customer',
 *   subjectIdField: 'aggregateId',
 *   piiFields: ['givenName', 'familyName', 'postcode'],
 *   piiDateFields: ['dateOfBirth'],
 * })
 * export class CustomerRegisteredEvent implements IEvent { ... }
 * ```
 */
export function EncryptableEvent(options: EncryptableEventOptions) {
  return (target: Function): void => {
    setEncryptableEventMetadata(target, {
      subjectType: options.subjectType,
      subjectIdField: options.subjectIdField,
      piiFields: options.piiFields ?? [],
      piiDateFields: options.piiDateFields ?? [],
    });
  };
}
