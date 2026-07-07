import { Module } from "@nestjs/common";
import { MongooseModule } from "@nestjs/mongoose";
import { EncryptionKey, EncryptionKeySchema } from "./schemas/encryption-key.schema";
import { CryptoShredderService } from "./services/crypto-shredder.service";
import { EncryptionKeyService } from "./services/encryption-key.service";

@Module({
  imports: [MongooseModule.forFeature([{ name: EncryptionKey.name, schema: EncryptionKeySchema }])],
  providers: [EncryptionKeyService, CryptoShredderService],
  exports: [CryptoShredderService, EncryptionKeyService],
})
export class CryptoShreddingModule {}
