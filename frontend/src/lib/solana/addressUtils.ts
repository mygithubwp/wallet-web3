import { Keypair } from "@solana/web3.js";
import bs58 from "bs58";

// genearte private key(base58 encoding) and address from seed
function generateKeysFromSeed(rootSeed: string): {
  addresses: { privateKey: string; address: string };
} {
  const solanaKeyPair = Keypair.fromSeed(
    Buffer.from(rootSeed, "hex").slice(0, 32)
  );

  const solanaPrivateKey = bs58.encode(solanaKeyPair.secretKey);
  const solanaAddress = solanaKeyPair.publicKey.toBase58();

  return {
    addresses: {
      privateKey: solanaPrivateKey,
      address: solanaAddress,
    },
  };
}

export { generateKeysFromSeed };
