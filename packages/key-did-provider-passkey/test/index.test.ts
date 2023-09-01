// Low-level imports
import {
  decodeAuthenticatorData,
  createCacaoChallenge,
  decodeAttestationObject,
  verify,
  recoverPublicKey,
  storePublicKey,
  selectPublicKey,
  b64urlToObj
} from '../src/utils'
import { MockAuthenticator } from './mock-authenticator'
import { hexToBytes } from '@noble/curves/abstract/utils'
import { p256 } from '@noble/curves/p256'
import * as u8a from 'uint8arrays'

// High-level imports
import { PasskeyProvider } from '../src/index'
import type { GeneralJWS } from 'dids'

const toHex = (b: Uint8Array) => u8a.toString(b, 'hex')

// Stub navigator.credentials for nodeJS
// @ts-ignore
globalThis.navigator.credentials = new MockAuthenticator()

describe('@didtools/key-passkey', () => {
  let provider: PasskeyProvider
  let did: string
  let pk: Uint8Array

  beforeAll(async () => {
    provider = new PasskeyProvider()
    const res = await provider.createCredential({ name: 'rob' })
    did = res.did
    pk = res.publicKey
  })

  it('decodes public key', () => {
    // @ts-ignore
    const authenticator = globalThis.navigator.credentials as MockAuthenticator
    expect(u8a.toString(pk, 'hex')).toEqual(u8a.toString(authenticator.credentials[0].pk, 'hex'))
  })

  it('encodes DID', () => {
    expect(did).toContain('did:key:zDn')
  })

  it('authenticates correctly', async () => {
    const nonce = 'goblin'
    const aud = 'https://my.app'
    const paths = ['a', 'b']
    const resp = await provider.send({
      jsonrpc: '2.0',
      id: 0,
      method: 'did_authenticate',
      params: { nonce, aud, paths },
    })
    const jws = resp?.result as GeneralJWS
    debugger
    const payload = b64urlToObj(jws.payload)
    const header = b64urlToObj(jws.signatures[0].protected)
    expect(payload.aud).toEqual(aud)
    expect(payload.nonce).toEqual(nonce)
    expect(payload.paths).toEqual(paths)
    expect(payload.did).toEqual(did)
    expect(payload.exp).toBeGreaterThan(Date.now() / 1000)
    expect(header.kid).toEqual(expect.stringContaining(did)) // Not gonna work
    expect(header.alg).toEqual('P256N')
  })

  // This test was fixtured using the testbench,
  // leaving usage trail as comments.
  test.skip('Generate and sign Cacao challenge', async () => {
    debugger
    const [_hash] = await createCacaoChallenge()
    const challenge = hexToBytes('01711220b307b1cfb60c8d1af2ae1ae047de0fe0d2e7fe6ec0f944ec15461075d2dd3f33')
    console.log('Paste into testbench and sign:\n', toHex(challenge))
    // Response values after manual sign
    const sig = '3044022044f14bc61060910f631a641d4ad0c78fbe52aebbdb0a59fa299a9f0446be6bb9022055ea1743c96c2270521a279a4d7bdb6e8b971fd868e9a92162bbe73411486ab1'
    const authData = '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763050000000c'
    const clientDataJSON = '7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2241584553494c4d4873632d32444930613871346134456665442d4453355f357577506c4537425647454858533354387a222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a38303830222c2263726f73734f726967696e223a66616c73657d'
    const userHandle = '7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2241584553494c4d4873632d32444930613871346134456665442d4453355f357577506c4537425647454858533354387a222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a38303830222c2263726f73734f726967696e223a66616c73657d'

    const valid = verify(hexToBytes(sig), hexToBytes(userHandle), {
      authData: hexToBytes(authData),
      clientDataJSON: hexToBytes(clientDataJSON)
    })
    expect(valid).toEqual(true)
  })

})

describe('@didtools/key-passkey: R&D Sanity Checks', () => {

  // Data Extracted from: https://heavy-mint.surge.sh/
  test('Extract public key from AuthenticatorData', () => {
    /* UNUSED! chromium: toHex(window.createRes.response.getPublicKey()) */
    // const cder = '3059301306072a8648ce3d020106082a8648ce3d03010703420004b27c142c5f4cb610f715b03034d20be6009e60d8c96031fc72678387db2aa78e51eca9d3104b5a3a15805e8208f52349b11630943fee4ee6fe5fe21072ca9c1e'
    /* chromium: toHex(new Uint8Array(window.createRes.response.attestationObject)) */
    const chex = 'a363666d74646e6f6e656761747453746d74a068617574684461746158c4f689f6b7489197aacf01172f02a82e0715f72aff70d5f758b9b0f7d3999978d24500000004000000000000000000000000000000000040ab2767e20a0e6f33731c1849d5422b2295d655f051d889b0dc3ec16ca691231459c61fbf349fd5f65fe21b502be3b57dabf4c6a411c61778700c3691966a7a24a5010203262001215820b27c142c5f4cb610f715b03034d20be6009e60d8c96031fc72678387db2aa78e22582051eca9d3104b5a3a15805e8208f52349b11630943fee4ee6fe5fe21072ca9c1e'
    const atObj = hexToBytes(chex)
    const ao = decodeAttestationObject(atObj)
    const { publicKey } = decodeAuthenticatorData(ao.authData)
    expect(toHex(publicKey)).toEqual('02b27c142c5f4cb610f715b03034d20be6009e60d8c96031fc72678387db2aa78e')
  })

  test('Verify', () => {
    // Create Response
    // const credentialID = 'uL55YZaNagzepg8iz4URraORix3tPNT8m5yQZjwP1DqY_b4Q5lCdVGrhli3vrnnn'
    // CredentialID as hex: 'b8be7961968d6a0cdea60f22cf8511ada3918b1ded3cd4fc9b9c90663c0fd43a98fdbe10e6509d546ae1962defae79e7'

    // const attestationObject = 'a363666d74646e6f6e656761747453746d74a068617574684461746158c249960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763c500000003000000000000000000000000000000000030b8be7961968d6a0cdea60f22cf8511ada3918b1ded3cd4fc9b9c90663c0fd43a98fdbe10e6509d546ae1962defae79e7a5010203262001215820b8be7961968d6a0cdea60f22cfa915f5de34fab1847d1c2b2e0814b3e1fa15d6225820fcbf3b689071e6a42e02bc5f0f82da28eec7cf1bae7c69f9dde03dc5aeda366ea16b6372656450726f7465637402'
    const authData = '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763c500000003000000000000000000000000000000000030b8be7961968d6a0cdea60f22cf8511ada3918b1ded3cd4fc9b9c90663c0fd43a98fdbe10e6509d546ae1962defae79e7a5010203262001215820b8be7961968d6a0cdea60f22cfa915f5de34fab1847d1c2b2e0814b3e1fa15d6225820fcbf3b689071e6a42e02bc5f0f82da28eec7cf1bae7c69f9dde03dc5aeda366ea16b6372656450726f7465637402'

    const { publicKey } = decodeAuthenticatorData(hexToBytes(authData))

    // Sign Response
    // const hash = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' // Input
    const authData2 = '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000005'
    const sig = '3044022006b2c838abf114f97e3e57d0d2d0124d1e3f8089d707294bde2fa60c8ae0650002204723780cdd0c405147975aed229e84b7e4d47a8bb8aaa07407b1f842ba16fae1'

    const clientDataJSON = '7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2241414543417751464267634943516f4c4441304f4478415245684d554652595847426b6147787764486838222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a38303030222c2263726f73734f726967696e223a66616c73657d'

    // expect(Buffer.from(JSON.parse(Buffer.from(hexToBytes(clientDataJSON)).toString()).challenge, 'base64url').hexSlice()).toEqual(hash)
    // Verify
    const clientDataHash = p256.CURVE.hash(hexToBytes(clientDataJSON))
    const msg = u8a.concat([hexToBytes(authData2), clientDataHash])
    const msgHash = p256.CURVE.hash(msg)
    const valid = p256.verify(sig, msgHash, publicKey)
    expect(valid).toEqual(true)
  })

  test('PublicKey Recovery; Expect key to equal one of the recovered keys', () => {
    const authData = '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763c500000003000000000000000000000000000000000030b8be7961968d6a0cdea60f22cf8511ada3918b1ded3cd4fc9b9c90663c0fd43a98fdbe10e6509d546ae1962defae79e7a5010203262001215820b8be7961968d6a0cdea60f22cfa915f5de34fab1847d1c2b2e0814b3e1fa15d6225820fcbf3b689071e6a42e02bc5f0f82da28eec7cf1bae7c69f9dde03dc5aeda366ea16b6372656450726f7465637402'
    const { publicKey } = decodeAuthenticatorData(hexToBytes(authData))
    storePublicKey(publicKey)
    const clientDataJSON = '7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2241414543417751464267634943516f4c4441304f4478415245684d554652595847426b6147787764486838222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a38303030222c2263726f73734f726967696e223a66616c73657d'
    const authData2 = '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000005'
    const sig = '3044022006b2c838abf114f97e3e57d0d2d0124d1e3f8089d707294bde2fa60c8ae0650002204723780cdd0c405147975aed229e84b7e4d47a8bb8aaa07407b1f842ba16fae1'

    const keys = recoverPublicKey(hexToBytes(sig), hexToBytes(authData2), hexToBytes(clientDataJSON))
    const recoveredKey = selectPublicKey(keys[0], keys[1])
    if (!recoveredKey) throw new Error('Select Failed')
    expect(toHex(recoveredKey)).toEqual(toHex(publicKey))
  })
})

