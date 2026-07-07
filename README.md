# @halleyhq/crypto-shredding

GDPR-safe erasure for event-sourced systems: encrypt PII per-subject, delete the key to erase, and keep your audit trail intact forever.

## The problem

Event sourcing and GDPR's right to erasure (Article 17) are normally in direct conflict. Events are supposed to be immutable — that's the whole point of an audit trail — but "the right to be forgotten" means you sometimes have to make specific data disappear. You can't rewrite history in an append-only store without breaking the guarantee that makes it useful in the first place.

This package resolves that conflict with **crypto-shredding**: instead of deleting or rewriting events, each subject (a customer, a patient, a user — anything erasure requests apply to) gets its own encryption key. PII fields on events are encrypted with that key before they're ever written to your event store. To "erase" a subject, you throw away their key — not their events. The events stay exactly where they were, in full, forever. Their PII fields just become permanently unreadable.

## How it works

- Mark PII fields on a domain event with `@EncryptableEvent`
- Each subject gets its own AES-256-GCM key, stored separately from the event store
- Events are encrypted field-by-field before being persisted — your event store never sees plaintext PII
- An erasure request deletes only the key. The event is untouched, forever
- On replay, PII fields gracefully degrade to `'[DELETED]'` (strings) or `null` (dates) once the key is gone — every other field, timestamp, and event in the stream stays fully intact

This pattern is already running in production inside a healthcare platform, handling real erasure requests against a live event store.

## Install

```bash
npm install @halleyhq/crypto-shredding
```

Peer dependencies: `@nestjs/common` and `@nestjs/mongoose` (encryption keys are currently stored in MongoDB via Mongoose — see [Roadmap](#roadmap)).

## Usage

Mark PII fields on your event:

```typescript
import { EncryptableEvent } from "@halleyhq/crypto-shredding/decorators/encryptable-event.decorator";

@EncryptableEvent({
  subjectType: "customer",
  subjectIdField: "customerId",
  piiFields: ["givenName", "familyName", "email"],
  piiDateFields: ["dateOfBirth"],
})
export class CustomerRegisteredEvent {
  constructor(
    public customerId: string,
    public givenName: string,
    public familyName: string,
    public email: string,
    public dateOfBirth: Date
  ) {}
}
```

Register the module:

```typescript
import { CryptoShreddingModule } from "@halleyhq/crypto-shredding/crypto-shredding.module";

@Module({
  imports: [CryptoShreddingModule],
})
export class AppModule {}
```

Encrypt before writing, decrypt after reading:

```typescript
import { CryptoShredderService } from "@halleyhq/crypto-shredding/services/crypto-shredder.service";

// write path — call before persisting the event
const encrypted = await cryptoShredder.encryptEvent(event);

// read path — call after reading the event back, or before replaying it
const decrypted = await cryptoShredder.decryptEventData(CustomerRegisteredEvent, rawData);
```

Erase a subject on request:

```typescript
import { EncryptionKeyService } from "@halleyhq/crypto-shredding/services/encryption-key.service";

// Immediately and irreversibly destroys the key. Every historical event
// for this subject becomes cryptographically unreadable, even though the
// events themselves are never touched.
await encryptionKeyService.deleteKey("customer", customerId);
```

## What this doesn't do

This library gives you the technical mechanism for field-level erasure in an immutable event store. It does **not**, on its own, make your system "GDPR compliant" — that depends on your hosting, your data processing agreements, your retention policies, and your organizational processes. Treat it as: *built-in Article 17 erasure for immutable event logs*, not a compliance guarantee.

## Roadmap

- Pluggable key storage (currently MongoDB-only via Mongoose; a storage-agnostic interface is under consideration)
- Framework-agnostic core (currently assumes NestJS DI conventions)

## License

MIT
