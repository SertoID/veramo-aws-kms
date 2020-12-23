import { IIdentifier, IKey, IService, IAgentContext, IKeyManager } from '@veramo/core'
import { AbstractIdentifierProvider } from '@veramo/did-manager'

type IContext = IAgentContext<IKeyManager>

/**
 * @alpha
 */
export class IdentifierProvider extends AbstractIdentifierProvider {
  private defaultKms: string

  constructor(options: { defaultKms: string }) {
    super()
    this.defaultKms = options.defaultKms
  }

  async createIdentifier(
    { kms, alias }: { kms?: string; alias?: string },
    context: IContext,
  ): Promise<Omit<IIdentifier, 'provider'>> {
    throw Error('IdentityProvider createIdentity not implemented')
  }

  async deleteIdentifier(identity: IIdentifier, context: IContext): Promise<boolean> {
    throw Error('IdentityProvider deleteIdentity not implemented')
    return true
  }

  async addKey(
    { identifier, key, options }: { identifier: IIdentifier; key: IKey; options?: any },
    context: IContext,
  ): Promise<any> {
    throw Error('IdentityProvider addKey not implemented')
    return { success: true }
  }

  async addService(
    { identifier, service, options }: { identifier: IIdentifier; service: IService; options?: any },
    context: IContext,
  ): Promise<any> {
    throw Error('IdentityProvider addService not implemented')
    return { success: true }
  }

  async removeKey(
    args: { identifier: IIdentifier; kid: string; options?: any },
    context: IContext,
  ): Promise<any> {
    throw Error('IdentityProvider removeKey not implemented')
    return { success: true }
  }

  async removeService(
    args: { identifier: IIdentifier; id: string; options?: any },
    context: IContext,
  ): Promise<any> {
    throw Error('IdentityProvider removeService not implemented')
    return { success: true }
  }
}
