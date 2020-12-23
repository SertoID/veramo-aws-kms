import { IIdentifier } from '@veramo/core'
import { AbstractDIDStore } from '@veramo/did-manager'

/**
 * @alpha
 */
export class DIDStore extends AbstractDIDStore {
  async get({ did, alias, provider }: { did: string; alias: string; provider: string }): Promise<IIdentifier> {
    throw Error('IdentityStore get not implemented')
  }

  async delete({ did }: { did: string }) {
    throw Error('IdentityStore delete not implemented')
    return true
  }

  async import(args: IIdentifier) {
    throw Error('IdentityStore import not implemented')
    return true
  }

  async list(args: { alias?: string; provider?: string }): Promise<IIdentifier[]> {
    throw Error('IdentityStore list not implemented')
  }
}
