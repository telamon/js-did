import type {
  AuthParams,
  CreateJWSParams,
  DIDMethodName,
  DIDProvider,
  DIDProviderMethods
} from 'dids'
import type {
  RPCRequest,
  RPCResponse,
  HandlerMethods,
  SendRequestFunc
} from 'rpc-utils'
import { createHandler, RPCError } from 'rpc-utils'
import {
  populateCreateOpts,
  selectPublicKey,
  storePublicKey
} from './utils'
import type { SimpleCreateCredentialOpts } from './utils'

// import * as u8a from 'uint8arrays'

export interface KeySelector {
  seen: (credentialID: string, pk: Uint8Array) => void
  select: (credentialID: string, pk0: Uint8Array, pk1: Uint8Array) => Uint8Array|null
}

interface Context {
  credentialID?: string
}

const didMethods: HandlerMethods<Context, DIDProviderMethods> = {
  async did_authenticate ({ credentialID }: Context, params: AuthParams)  {
    const discoverable = !!credentialID
  },

  async did_createJWS (ctx: Context, params: CreateJWSParams) {
    
  },

  async did_decryptJWE () {
    throw new RPCError(4100, 'Decryption not supported')
  }
}



export class PasskeyProvider implements DIDProvider {
  _handle: SendRequestFunc<DIDProviderMethods>
  _selector?: KeySelector
  /**
   * UX-yikes
   */
  constructor (noMemory = false) {
    const handler = createHandler<Context, DIDProviderMethods>(didMethods)
    if (!noMemory) this._selector = new LocalStorageKeySelector()
    const selectors = []
    const ctx: Context =  {
      credentialID: undefined
    }

    this._handle = msg => handler(ctx, msg)
  }

  async send<Name extends DIDMethodName> (
    msg: RPCRequest<DIDProviderMethods, Name>
  ): Promise<RPCResponse<DIDProviderMethods, Name> | null> {
    return this._handle(msg)
  }

  async createCredential (opts: SimpleCreateCredentialOpts) {
    const credential = await globalThis.navigator.credentials.create(populateCreateOpts(opts)) as any
    if (!credential) throw new Error('Empty Credential Response')
      const authenticatorData = getAuthenticatorData(credential.response)
    const { publicKey } = decodeAuthenticatorData(authenticatorData)
    if (this._selector) this._selector.seen(credentialId, publicKey)
      return encodeDIDFromPub(publicKey)
  }
}

class LocalStorageKeySelector implements KeySelector {
  seen (_: string, pk: Uint8Array) { storePublicKey(pk) }

  select (_: string, pk0: Uint8Array, pk1: Uint8Array): Uint8Array|null {
    return selectPublicKey(pk0, pk1)
  }
}
