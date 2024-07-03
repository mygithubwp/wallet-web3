import { Buffer } from "buffer";
import { privateToAddress } from "ethereumjs-util";
import HDKey from "hdkey";

function generateKeysFromSeed(rootSeed: string): {
  addresses: { privateKey: string; address: string };
} {
  const masterHdKey = HDKey.fromMasterSeed(Buffer.from(rootSeed, "hex"));
  const ETH_ACCOUNT_PATH = `m/44'/60'/0'`;
  const ethAccountKey = masterHdKey.derive(ETH_ACCOUNT_PATH + "/0/0");
  const ethPrivateKey: string = ethAccountKey.privateKey.toString("hex");
  const ethAddress: string =
    "0x" + privateToAddress(Buffer.from(ethPrivateKey, "hex")).toString("hex");

  return {
    addresses: {
      privateKey: ethPrivateKey,
      address: ethAddress,
    },
  };
}

export { generateKeysFromSeed };
