import { KMS } from "@aws-sdk/client-kms";
import { arrayify, hexlify } from '@ethersproject/bytes';
import { convertPublicKeyToX25519, convertSecretKeyToX25519 } from '@stablelib/ed25519';
import { sharedKey } from '@stablelib/x25519';
import { IKey, TKeyType } from '@veramo/core';
import { AbstractKeyManagementSystem } from '@veramo/key-manager';
import * as asn1 from 'asn1.js';
import { toJose } from "./util";

export interface KeyManagementSystemOptions {
  region: string,
  apiVersion: string,
  accessKeyId?: string,
  secretAccessKey?: string
}

/**
 * @alpha
 */
export class KeyManagementSystem extends AbstractKeyManagementSystem {
  private kms: KMS;

  constructor(options: KeyManagementSystemOptions) {
    super();
    this.kms = new KMS(options)
  }

  private EcdsaSigAsnParse = asn1.define('EcdsaSig', function (this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3 
    this.seq().obj(
      this.key('r').int(),
      this.key('s').int(),
    );
  });

  private EcdsaPubKey = asn1.define('EcdsaPubKey', function (this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
    this.seq().obj(
      this.key('algo').seq().obj(
        this.key('algorithm').objid(),
        this.key('parameters').objid(),
      ),
      this.key('pubKey').bitstr()
    );
  });

  leftpad(data: string, size = 64): string {
    if (data.length === size) return data
    return '0'.repeat(size - data.length) + data
  }

  async createKey({ type, meta }: { type: TKeyType, meta: any }): Promise<Omit<IKey, 'kms'>> {
    try {
      let alias: string = meta ? meta.alias : undefined;
      let key: Omit<IKey, 'kms'>
      switch (type) {
        case 'Ed25519':
          throw Error('KeyManagementSystem createKey Ed25519 not implemented')
          break
        case 'Secp256k1':
          const result = await this.kms.createKey({ KeyUsage: "SIGN_VERIFY", CustomerMasterKeySpec: "ECC_SECG_P256K1", })
          if (alias) await this.kms.createAlias({ AliasName: alias, TargetKeyId: result.KeyMetadata?.KeyId });
          const publicKeyDER = await this.kms.getPublicKey({ KeyId: result.KeyMetadata?.KeyId })
          const publicKey = this.EcdsaPubKey.decode(Buffer.from(publicKeyDER.PublicKey!))
          key = { "kid": result.KeyMetadata?.KeyId || "kid", "type": type, "publicKeyHex": publicKey.pubKey.data.toString('hex') || "publicKeyHex" };
          break
        default:
          throw Error('Key type not supported: ' + type)
      }
      return key
    } catch (error) {
      console.log(`Error Caught ${error}`)
      return Promise.reject(error);
    }
  }

  async deleteKey(args: { kid: string }) {
    //throw Error('KeyManagementSystem deleteKey not implemented')
    try {
      await this.kms.scheduleKeyDeletion({ KeyId: args.kid })
    } catch (error) {
      console.log(`Error Caught ${error}`)
      return Promise.reject(error);
    }
    return true
  }

  async encryptJWE({ key, to, data }: { key: IKey; to: IKey; data: string }): Promise<string> {
    throw Error('KeyManagementSystem encryptJWE not implemented')
  }

  async decryptJWE({ key, data }: { key: IKey; data: string }): Promise<string> {
    throw Error('KeyManagementSystem decryptJWE not implemented')
  }

  async signEthTX({ key, transaction }: { key: IKey; transaction: object }): Promise<string> {
    throw Error('KeyManagementSystem signEthTX not implemented')
  }

  async signJWT({ key, data }: { key: IKey; data: string }): Promise<string> {
    const enc = new TextEncoder()
    const result = await this.kms.sign({ KeyId: key.kid, Message: enc.encode(data), SigningAlgorithm: "ECDSA_SHA_256" })
    if (!result.Signature) throw Error("sig undefined")
    const sig = result.Signature
    const sigDecoded = this.EcdsaSigAsnParse.decode(Buffer.from(sig));
    console.log(sigDecoded)
    return toJose({
      r: this.leftpad(sigDecoded.r.toString('hex')),
      s: this.leftpad(sigDecoded.s.toString('hex')),
      recoveryParam: 1
    })
  }

  async sign({ key, algorithm, data }: { key: IKey; algorithm?: string; data: Uint8Array }): Promise<string> {
    if (algorithm && !awsEccSupportedSigningAlgorithms.includes(algorithm)) {
      throw new Error(`AWS KMS plugin only supports the algorithms ${awsEccSupportedSigningAlgorithms.join(",")} for signing.`);
    }

    const enc = new TextEncoder()
    const result = await this.kms.sign({ KeyId: key.kid, Message: data, SigningAlgorithm: "ECDSA_SHA_256" })
    if (!result.Signature) throw Error("sig undefined")
    const sig = result.Signature
    const sigDecoded = this.EcdsaSigAsnParse.decode(Buffer.from(sig));
    return sigDecoded;
  };

  async sharedSecret(args: { myKey: IKey; theirKey: Pick<IKey, 'type' | 'publicKeyHex'> }): Promise<string> {
    const { myKey, theirKey } = args
    let myKeyBytes = arrayify('0x' + myKey.privateKeyHex)
    if (myKey.type === 'Ed25519') {
      myKeyBytes = convertSecretKeyToX25519(myKeyBytes)
    } else if (myKey.type !== 'X25519') {
      throw new Error(`not_supported: can't compute shared secret for type=${myKey.type}`)
    }
    let theirKeyBytes = arrayify('0x' + theirKey.publicKeyHex)
    if (theirKey.type === 'Ed25519') {
      theirKeyBytes = convertPublicKeyToX25519(theirKeyBytes)
    } else if (theirKey.type !== 'X25519') {
      throw new Error(`not_supported: can't compute shared secret for type=${theirKey.type}`)
    }
    const shared = sharedKey(myKeyBytes, theirKeyBytes)
    return hexlify(shared).substring(2)
  }

}

const awsEccSupportedSigningAlgorithms = [
  'ECDSA_SHA_256', 'ECDSA_SHA_384', 'ECDSA_SHA_512'
];