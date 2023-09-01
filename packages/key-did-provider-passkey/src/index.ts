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
  storePublicKey,
  getAuthenticatorData,
  decodeAuthenticatorData,
  jsonToBase64Url,
  authenticatorSign
} from './utils'
import type { SimpleCreateCredentialOpts } from './utils'
import { encodeDIDFromPub } from '@didtools/key-webcrypto'
import * as u8a from 'uint8arrays'
import { p256 } from '@noble/curves/p256'

export interface KeySelector {
  seen: (credentialId: string, pk: Uint8Array) => void
  select: (credentialId: string, pk0: Uint8Array, pk1: Uint8Array) => Uint8Array|null
}

interface Context {
  credentialId?: string // Set if PasskeyProvider was initialized in non-discoverable mode
  pk?: Uint8Array // source for did
  selectors?: KeySelector[] // TODO: think this through / discoverable-mode
}

const sign = async (
  payload: Record<string, any> | string,
  // did: string,
  ctx: Context,
  protectedHeader: Record<string, any> = {}
) => {
  const kid = '' //  `${did}#${did.split(':')[2]}`
  const toStableObject = (o:any) => o // TODO: code duplication feel bad
  const header = toStableObject(Object.assign(protectedHeader, { kid, alg: 'ES256' })) // TODO: alg needs custom verifier..
  const encodedHeader = jsonToBase64Url(header)

  const actualPayload = typeof payload === 'string'
    ? payload
    : jsonToBase64Url(toStableObject(payload))

  const data = `${encodedHeader}.${actualPayload}`

  // challenge is part of `clientDataJSON` which must stored
  // alongside signature; prehashing challenge avoids storing partial message within message.
  // TODO: remember to verify clientDataJSON.challenge === hash(message)
  const challenge = p256.CURVE.hash(u8a.fromString(data))
  const { signature, recovered, credential } = await authenticatorSign(challenge, ctx.credentialId)
  
  debugger
  const encodedSignature = u8a.toString(new Uint8Array(signature), 'base64url')
  return `${data}.${encodedSignature}`
}

const didMethods: HandlerMethods<Context, DIDProviderMethods> = {
  async did_authenticate (ctx: Context, params: AuthParams)  {
    const did = ''// N/A encodeDIDFromPub(await getPublicKey(keyPair))
    const response = await sign(
      {
        did,
        aud: params.aud,
        nonce: params.nonce,
        paths: params.paths,
        exp: Math.floor(Date.now() / 1000) + 600, // expires 10 min from now
      },
      ctx
    )
    return toGeneralJWS(response) 
  },

  async did_createJWS (ctx: Context, params: CreateJWSParams) {
    
  },

  async did_decryptJWE () {
    throw new RPCError(4100, 'Decryption not supported')
  }
}

export interface CreateCredentialResult {
  publicKey: Uint8Array,
  credential: PublicKeyCredential,
  did: string
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
      credentialId: undefined
    }

    this._handle = msg => handler(ctx, msg)
  }

  async send<Name extends DIDMethodName> (
    msg: RPCRequest<DIDProviderMethods, Name>
  ): Promise<RPCResponse<DIDProviderMethods, Name> | null> {
    return this._handle(msg)
  }

  async createCredential (opts: SimpleCreateCredentialOpts): Promise<CreateCredentialResult> {
    const credential = await globalThis.navigator.credentials.create(populateCreateOpts(opts)) as any
    if (!credential) throw new Error('Empty Credential Response')

    const authenticatorData = getAuthenticatorData(credential.response)
    const { publicKey } = decodeAuthenticatorData(authenticatorData)
    if (this._selector) this._selector.seen(credential.id, publicKey)
    return {
      publicKey,
      did: encodeDIDFromPub(publicKey),
      credential
    }
  }
}

class LocalStorageKeySelector implements KeySelector {
  seen (_: string, pk: Uint8Array) { storePublicKey(pk) }

  select (_: string, pk0: Uint8Array, pk1: Uint8Array): Uint8Array|null {
    return selectPublicKey(pk0, pk1)
  }
}
