import { Cacao, CacaoBlock } from '@didtools/cacao'
import { decode } from 'cborg'
import { p256 } from '@noble/curves/p256'
import * as u8a from 'uint8arrays'
import { ecPointCompress, encodeDIDFromPub } from '@didtools/key-webcrypto'
// Hashing workaround
import * as dagCbor from '@ipld/dag-cbor'
import * as Block from 'multiformats/block'
import { sha256 as hasher } from 'multiformats/hashes/sha2'

const RelayingPartyID = globalThis.location.hostname
const RelayingPartyName = 'CeramicNetwork' // ???

// Webauthn requires a browser.
const { credentials } = globalThis.navigator
const { crypto } = globalThis

type WebauthnCreateOpts = { // TODO: remove this interface
  // TODO: readup on use
  rpname?: PublicKeyCredentialCreationOptions['rp']['name'],

  // User facing identifiers (Shown on device/selection screens)
  // This seems to be the string displayed on windows/chrome (windows-hello credential store)
  name?: PublicKeyCredentialCreationOptions['user']['name'],
  displayName?: PublicKeyCredentialCreationOptions['user']['displayName'] // shown in system popups
}

export async function createAccount (opts: WebauthnCreateOpts = {}) {
  const config: CredentialCreationOptions = {
    publicKey: {
      challenge: randomBytes(32), // Otherwise issued by server
      rp: {
        id: RelayingPartyID, // Must be set to current hostname
        name: RelayingPartyName
      },
      user: {
        id: randomBytes(32), // Otherwise issued by server
        name: opts.name || 'ceramicuser',
        displayName: opts.displayName || 'Ceramic user',
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ECDSA with SHA-256
      ],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
        requireResidentKey: true,
      }
    }
  }
  const cred = await credentials.create(config) as any
  if (!cred) throw new Error('AbortedByUser')

  // cred.response.getPublicKey() // Returns binary DER-PK; Only available on Chrome
  const { publicKey } = decodeAuthenticatorData(cred.response.attestationObject)
  return encodeDIDFromPub(publicKey)
}

export async function createCacaoChallenge () {
    const now = Date.now()
    // Workaround for unknown AAD and discoverable PK;
    // we create a "challenge" CacaoBlock without Issuer attribute
    const challenge: Cacao = Object.freeze({
      h: {
        t: 'caip122'
      },
      p: {
        domain: globalThis.location.hostname,
        iat: new Date(now).toISOString(),
        aud: '' + globalThis.location,
        version: 1,
        nonce: globalThis.crypto.randomUUID(),
        exp: new Date(now + 7 * 86400000).toISOString(), // 1 week
        nbf: new Date(now).toISOString(),
        resources: ['uri', 'uri'] // <-- resources we wish to grant permission to.
      }
    })

    // Workaround for https://github.com/multiformats/js-multiformats/issues/259
    const fromCacao = (cacao: Cacao): Promise<CacaoBlock> => {
      return Block.encode<Cacao, number, number>({
        value: cacao,
        codec: dagCbor,
        hasher: {
          ...hasher,
          digest (bytes: any) {
            if (!(bytes instanceof Uint8Array) && bytes?.buffer) bytes = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)
            return hasher.digest(bytes)
          }
        }
      })
    }
    const block = await fromCacao(challenge) // await CacaoBlock.fromCacao(challenge)

    // Webauthn Sign
    // const signResponse = await webauthnSign(block.cid.bytes)

    // Extend CacaoMessage with Authenticator values
    const toCacao = (did: string, sig: Uint8Array, authenticatorData: Uint8Array):Cacao => ({
      p: {
        ...challenge.p,
        iss: did
      },
      s: {
        t: 'webauthn:es256',
        s: sig,
        aad: authenticatorData
      }
    })
    return [block.cid.bytes, toCacao]
}

async function webauthnSign (hash: Uint8Array, requiredIdentity?: BufferSource) {
  const allowCredentials = []
  if (requiredIdentity) { // non-discoverable mode
    allowCredentials.push({ type: "public-key", id: requiredIdentity })
  }
  const res = await globalThis.navigator.credentials.get({
    publicKey: {
      rpId: RelayingPartyID,
      challenge: hash,
      allowCredentials,
      timeout: 240000,
    },
  })

  res.response.authenticatorData
  res.response.signature
  debugger
  return res
}
export type AdditionalAuthenticatorData = {
  authData: Uint8Array,
  clientDataJSON: Uint8Array
}

export function webauthnVerify (sig: Uint8Array, publicKey: Uint8Array, aad: AdditionalAuthenticatorData) {
  const { authData, clientDataJSON } = aad
  const clientDataHash = p256.CURVE.hash(clientDataJSON)
  const msg = u8a.concat([authData, clientDataHash])
  const hashBase = p256.CURVE.hash(msg)
  return p256.verify(sig, hashBase, publicKey)
}

// --- Helpers
function randomBytes (n: number) {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return b
}

export function decodeAttestationObject (attestationObject: Uint8Array|ArrayBuffer) {
  // TODO: AttestationObject is not same as authData; AObject is a CBOR containing a copy of AuthData
  if (attestationObject instanceof ArrayBuffer) attestationObject = new Uint8Array(attestationObject)
  if (!(attestationObject instanceof Uint8Array)) throw new Error('Uint8ArrayExpected')
  return decode(attestationObject)
}

/**
 * Extracts PublicKey from AuthenticatorData as received from hardware key.
 *
 * See box `CREDENTIAL PUBLIC KEY` in picture:
 * https://w3c.github.io/webauthn/images/fido-attestation-structures.svg
 * @param {Uint8Array|ArrayBuffer} attestationObject As given by credentials.create().response.attestationObject
 */
export function decodeAuthenticatorData (authData: Uint8Array) {
  if (!(authData instanceof Uint8Array)) throw new Error('Uint8ArrayExpected')
  // https://w3c.github.io/webauthn/#sctn-authenticator-data
  if (authData.length < 37) throw new Error('AuthenticatorDataTooShort')
  let o = 0
  const rpidHash = authData.slice(o, o += 32) // SHA-256 hash of rp.id

  const flags = authData[o++]
  // console.debug(`Flags: 0b` + flags.toString(2).padStart(8, '0'))
  if (!(flags & (1 << 6))) throw new Error('AuthenticatorData has no Key')

  const view = new DataView(authData.buffer)
  const signCounter = view.getUint32(o); o += 4

  // https://w3c.github.io/webauthn/#sctn-attested-credential-data
  const aaguid = authData.slice(o, o += 16)
  const clen = view.getUint16(o); o += 2
  const credentialId = authData.slice(o, o += clen)

  // https://datatracker.ietf.org/doc/html/rfc9052#section-7
  // const publicKey = decode(authData.slice(o)) // cborg.decode fails; Refuses to decode COSE use of numerical keys
  const cose = decodeCBORHack(authData.slice(o)) // Decode cbor manually

  // Section 'COSE Key Type Parameters'
  // https://www.iana.org/assignments/cose/cose.xhtml
  if (cose[1] !== 2) throw new Error('Expected EC Coordinate pair')
  if (cose[3] !== -7) throw new Error('Expected ES256 Algorithm')
  const x = cose[-2]
  const y = cose[-3]
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) throw new Error('Expected X and Y coordinate to be buffers')
  const publicKey = ecPointCompress(x, y)
  return {
    rpidHash,
    flags,
    signCounter,
    aaguid,
    credentialId,
    publicKey,
    cose
  }
}

/**
 * Tiny unsafe CBOR decoder that supports COSE_key numerical keys
 * https://www.iana.org/assignments/cose/cose.xhtml
 * Section 'COSE Key Type Parameters'
 */
function decodeCBORHack (buf: Uint8Array) {
  if (!(buf instanceof Uint8Array)) throw new Error('Uint8ArrayExpected')
  const view = new DataView(buf.buffer)
  let o = 0
  const readByte = () => buf[o++]
  const readU8 = () => view.getUint8(o++) // @ts-ignore
  const readU16 = () => view.getUint16(o, undefined, o += 2) // @ts-ignore
  const readU32 = () => view.getUint16(o, undefined, o += 4) // @ts-ignore
  const readU64 = () => view.getBigUint64(o, undefined, o += 8) // @ts-ignore
  const readLength = l => l < 24 ? l : [readU8, readU16, readU32, readU64][l - 24]() // @ts-ignore
  const readMap = l => {
    const map = {} // @ts-ignore
    for (let i = 0; i < l; i++) map[readItem()] = readItem()
    return map
  } // @ts-ignore
  const readBuffer = l => buf.slice(o, o += l)
  function readItem () {
    const b = readByte()
    const l = readLength(b & 0x1f)
    switch (b >> 5) {
      case 0: return l // Uint
      case 1: return -(l + 1) // Negative integer
      case 2: return readBuffer(l) // binstr
      case 5: return readMap(l)
      default: throw new Error('UnsupportedType' + (b >> 5))
    }
  }
  return readItem()
}
