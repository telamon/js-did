import { decodeAuthenticatorData } from '../src/index'
import { hexToBytes } from '@noble/curves/abstract/utils'
import { p256 } from '@noble/curves/p256'
import * as u8a from 'uint8arrays'
import { ecPointCompress } from '@didtools/key-webcrypto'
describe('WebAuthn', () => {
  // Data extracted from testbench / console: https://heavy-mint.surge.sh/
  test.skip('Extract public key from AuthenticatorData', () => {
    /* chromium: toHex(window.createRes.response.getPublicKey()) */
    // const cder = '3059301306072a8648ce3d020106082a8648ce3d03010703420004b27c142c5f4cb610f715b03034d20be6009e60d8c96031fc72678387db2aa78e51eca9d3104b5a3a15805e8208f52349b11630943fee4ee6fe5fe21072ca9c1e'
    /* chromium: toHex(new Uint8Array(window.createRes.response.attestationObject)) */
    const chex = 'a363666d74646e6f6e656761747453746d74a068617574684461746158c4f689f6b7489197aacf01172f02a82e0715f72aff70d5f758b9b0f7d3999978d24500000004000000000000000000000000000000000040ab2767e20a0e6f33731c1849d5422b2295d655f051d889b0dc3ec16ca691231459c61fbf349fd5f65fe21b502be3b57dabf4c6a411c61778700c3691966a7a24a5010203262001215820b27c142c5f4cb610f715b03034d20be6009e60d8c96031fc72678387db2aa78e22582051eca9d3104b5a3a15805e8208f52349b11630943fee4ee6fe5fe21072ca9c1e'
    const atObj = hexToBytes(chex)
    const { publicKey } = decodeAuthenticatorData(atObj)

    // Key Extraction looks nice:
    // toHex(publickKey)        02b27c142c5f4cb610f715b03034d20be6009e60d8c96031fc72678387db2aa78e
    // Chrome provided DER:   0004b27c142c5f4cb610f715b03034d20be6009e60d8c96031fc72678387db2aa78e51eca9d3104b5a3a15805e8208f52349b11630943fee4ee6fe5fe21072ca9c1e


    // Test verify
    const mHash = 'b917827161ed5ed122c8ebf82a4dfdb8bfc9920a7567a6c19867d58957814872'
    /* toHex(window.signRes.response.signature) */
    const sig = '304402207325dbd6588b17c5bd8a95e604fcc9f9e9b1e83b9bf42836d9de856c9462c4300220649f0de166883da74cab8e65826da92dd9b312997ac4172c37d6797c9448d5a5'
    /* toHex(window.signRes.response.authenticatorData) */
    const authData = 'f689f6b7489197aacf01172f02a82e0715f72aff70d5f758b9b0f7d3999978d20500000017'

    // const curveSig = p256.Signature.fromDER(sig)
    // curveSig.assertValidity() // Should not throw

    const msg = u8a.concat([hexToBytes(authData), hexToBytes(mHash)])
    const  valid = p256.verify(sig, msg, publicKey, { prehash: true })
    console.log('valid', valid)
    // toHex(window.signRes.response.clientDataJSON)
    // const clientDataJson = '7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22755265436357487458744569794f76344b6b3339754c5f4a6b6770315a3662426d47665669566542534849222c226f726967696e223a2268747470733a2f2f68656176792d6d696e742e73757267652e7368222c2263726f73734f726967696e223a66616c73652c226f746865725f6b6579735f63616e5f62655f61646465645f68657265223a22646f206e6f7420636f6d7061726520636c69656e74446174614a534f4e20616761696e737420612074656d706c6174652e205365652068747470733a2f2f676f6f2e676c2f796162506578227d'
  })

  test('Exports usable API', () => {
  })

  test('Decode and verify Authenticator data', () => {
  })


  test('Verify', () => {
    // Create Response
    // const kid = 'uL55YZaNagzepg8iz4URraORix3tPNT8m5yQZjwP1DqY_b4Q5lCdVGrhli3vrnnn'
    // kid:hex: 'b8be7961968d6a0cdea60f22cf8511ada3918b1ded3cd4fc9b9c90663c0fd43a98fdbe10e6509d546ae1962defae79e7'

    const attestationObject = 'a363666d74646e6f6e656761747453746d74a068617574684461746158c249960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763c500000003000000000000000000000000000000000030b8be7961968d6a0cdea60f22cf8511ada3918b1ded3cd4fc9b9c90663c0fd43a98fdbe10e6509d546ae1962defae79e7a5010203262001215820b8be7961968d6a0cdea60f22cfa915f5de34fab1847d1c2b2e0814b3e1fa15d6225820fcbf3b689071e6a42e02bc5f0f82da28eec7cf1bae7c69f9dde03dc5aeda366ea16b6372656450726f7465637402'
    const authData = '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763c500000003000000000000000000000000000000000030b8be7961968d6a0cdea60f22cf8511ada3918b1ded3cd4fc9b9c90663c0fd43a98fdbe10e6509d546ae1962defae79e7a5010203262001215820b8be7961968d6a0cdea60f22cfa915f5de34fab1847d1c2b2e0814b3e1fa15d6225820fcbf3b689071e6a42e02bc5f0f82da28eec7cf1bae7c69f9dde03dc5aeda366ea16b6372656450726f7465637402'
    const { publicKey } = decodeAuthenticatorData(hexToBytes(attestationObject))
    // Sign Response
    // const hash = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' // Input
    const authData2 = '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000005'
    const sig = '3044022006b2c838abf114f97e3e57d0d2d0124d1e3f8089d707294bde2fa60c8ae0650002204723780cdd0c405147975aed229e84b7e4d47a8bb8aaa07407b1f842ba16fae1'
    // TODO: rebuild from object?
    const clientDataJSON = '7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2241414543417751464267634943516f4c4441304f4478415245684d554652595847426b6147787764486838222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a38303030222c2263726f73734f726967696e223a66616c73657d'

    // expect(Buffer.from(JSON.parse(Buffer.from(hexToBytes(clientDataJSON)).toString()).challenge, 'base64url').hexSlice()).toEqual(hash)
    // Verify
    const clientDataHash = p256.CURVE.hash(hexToBytes(clientDataJSON))
    const msg = u8a.concat([hexToBytes(authData2), clientDataHash])
    const h2 = p256.CURVE.hash(msg)
    const valid = p256.verify(sig, h2, publicKey)
    expect(valid).toEqual(true)
  })
})
