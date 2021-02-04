import { TKeyType, IKey, EcdsaSignature } from '@veramo/core'
import { AbstractKeyManagementSystem } from '@veramo/key-manager'
import { KMS } from "@aws-sdk/client-kms"
import { Credentials } from "@aws-sdk/types"
import { hash } from '@stablelib/sha256'
import * as asn1 from 'asn1.js';

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

  private EcdsaSigAsnParse = asn1.define('EcdsaSig', function(this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3 
    this.seq().obj( 
        this.key('r').int(), 
        this.key('s').int(),
    );
  });

  private EcdsaPubKey = asn1.define('EcdsaPubKey', function(this: any) {
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

  async createKey({ type }: { type: TKeyType }): Promise<Omit<IKey, 'kms'>> {
    try {
      let key: Omit<IKey, 'kms'>
      switch (type) {
        case 'Ed25519':
          throw Error('KeyManagementSystem createKey Ed25519 not implemented')
          break
        case 'Secp256k1':
          const result = await this.kms.createKey({KeyUsage: "SIGN_VERIFY", CustomerMasterKeySpec: "ECC_SECG_P256K1"})
          const publicKeyDER = await this.kms.getPublicKey({ KeyId: result.KeyMetadata?.KeyId})
          const publicKey = this.EcdsaPubKey.decode(Buffer.from(publicKeyDER.PublicKey!))
          key = {"kid": result.KeyMetadata?.KeyId || "kid", "type": type, "publicKeyHex": publicKey.pubKey.data.toString('hex') || "publicKeyHex"};
          break
        default:
          throw Error('Key type not supported: ' + type)
      }
      return key
    } catch(error) {
      console.log(`Error Caught ${error}`)
      return Promise.reject(error);
    }
  }

  async deleteKey(args: { kid: string }) {
    //throw Error('KeyManagementSystem deleteKey not implemented')
    try{
      await this.kms.scheduleKeyDeletion({ KeyId: args.kid })
    } catch(error) {
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

  async signJWT({ key, data }: { key: IKey; data: string }): Promise<EcdsaSignature> {
    const enc = new TextEncoder()
    const result = await this.kms.sign({ KeyId: key.kid, Message: enc.encode(data), SigningAlgorithm: "ECDSA_SHA_256"})
    if(!result.Signature) throw Error("sig undefined")
    const sig = result.Signature
    const sigDecoded = this.EcdsaSigAsnParse.decode(Buffer.from(sig));
    console.log(sigDecoded)
    return {
      r: this.leftpad(sigDecoded.r.toString('hex')),
      s: this.leftpad(sigDecoded.s.toString('hex')),
      recoveryParam: 1
    }
  }

}
