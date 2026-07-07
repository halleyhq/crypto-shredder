import { defineConfig } from "tsup";

export default defineConfig({
  entry: [
    "src/index.ts",
    "src/crypto-shredding.module.ts",
    "src/decorators/encryptable-event.decorator.ts",
    "src/decorators/metadata-registry.ts",
    "src/schemas/encryption-key.schema.ts",
    "src/services/crypto-shredder.service.ts",
    "src/services/encryption-key.service.ts",
  ],
  format: ["cjs", "esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  external: ["@nestjs/common", "@nestjs/mongoose", "mongoose"],
});
