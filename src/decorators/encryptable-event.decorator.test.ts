import { describe, expect, it } from "vitest";
import { EncryptableEvent } from "./encryptable-event.decorator";
import { getEncryptableEventMetadata } from "./metadata-registry";

@EncryptableEvent({
  subjectType: "customer",
  subjectIdField: "customerId",
  piiFields: ["name", "email"],
  piiDateFields: ["dateOfBirth"],
})
class DecoratedEvent {
  constructor(
    public customerId: string,
    public name: string,
  ) {}
}

@EncryptableEvent({
  subjectType: "customer",
  subjectIdField: "customerId",
})
class BareDecoratedEvent {}

class UndecoratedEvent {}

describe("EncryptableEvent decorator", () => {
  it("registers metadata retrievable by class reference", () => {
    const metadata = getEncryptableEventMetadata(DecoratedEvent);
    expect(metadata).toEqual({
      subjectType: "customer",
      subjectIdField: "customerId",
      piiFields: ["name", "email"],
      piiDateFields: ["dateOfBirth"],
    });
  });

  it("registers metadata retrievable by class name string", () => {
    const metadata = getEncryptableEventMetadata("DecoratedEvent");
    expect(metadata?.subjectType).toBe("customer");
  });

  it("defaults piiFields and piiDateFields to empty arrays when omitted", () => {
    const metadata = getEncryptableEventMetadata(BareDecoratedEvent);
    expect(metadata?.piiFields).toEqual([]);
    expect(metadata?.piiDateFields).toEqual([]);
  });

  it("returns undefined for a class without the decorator", () => {
    expect(getEncryptableEventMetadata(UndecoratedEvent)).toBeUndefined();
    expect(getEncryptableEventMetadata("UndecoratedEvent")).toBeUndefined();
  });
});
