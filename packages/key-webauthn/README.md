# key-webauthn

This package attempts to provide [passkey](https://passkey.org) support.

## Journey &amp; Caveats

### `Iteration 0`
The naive approach was to create a key-credential and use  
`navigator.credentials.get()` to generate signatures for cacao blocks.

This works.. But the `PublicKey` is provided only once during `navigator.credentials.create()`.  
This causes two issues:
1. Using _discoverable_ `get()` will use an unknown secret and produces unverifiable signatures.
2. `CredentialID` must be provided to the sign request to ensure the use of a specific key.

Effectively this means that `CredentialID` and `PublicKey` must be stored.

#### Results: `mixed`
![Webauthn Diagram](webauthn-v2.drawio.png)

We've successfully decoded `AttestationObject` and extracted the `PublicKey`
But webauthn was designed for Web2 environments.  
As such using on-chip/internal keys requires a central database
to provide a map between `Username` and (`CredentialID`, `PublicKey`) tuples.

### `Iteration 1`

We searched for alternatives not that do not require access to a central namespace.

**PRF extension**
The "Pseudo Random Function" extension described in [W3C Spec](https://w3c.github.io/webauthn/#prf-extension) can be used to deterministically generate the same secret given same RelayingParty
and same user-chosen KeyCredential.
- [PRF Example](https://github.com/oddsdk/passkeys/blob/main/packages/odd-passkeys/src/auth.js)

![Webauthn Diagram](webauthn-prf.drawio.png)
**Tradeoffs**

The tradeoff with PRF is that it uses "external" secrets relying on the browser's secure context.  
This is no different from using browser-extension based wallets.  
However not using hardware signing for users who posses secure hardware tags.. it's bit of a dissapointment.  
A benefit is that the choice of algorithm restriction is lifted, this removes some complexity
from the node-end as they nolonger are required to implement a custom signature verification method. (See diagram above)

**Compatibility**

The support for this extension is not complete; See [chart](https://github.com/oddsdk/passkeys/issues/13)

After discussions we identified two fallbacks in the absence of PRF support:

1. Use [Large Blob extension](https://w3c.github.io/webauthn/#sctn-large-blob-extension) to store a randomly generated secret for later retrevial on user return.
2. Provide fixed input to signing request and treat signature as external-secret. (This depends on the availability of a FIDO2/algorithm that does not use a random component in order to produce a deterministic result.)


### `Iteration 2`
Explore PRF support

#### Results: `negative`
PRF Support seems to be missing on Yubikey+Chrom\[e|ium\]+\[Linux|Windows\]
Confirmed via [Test Bench#prf-section](https://heavy-mint.surge.sh) and
 [3rd-party testbench](https://levischuck.com/blog/2023-02-prf-webauthn)

### `Iteration 3`

**PRF-fallback:** Deterministic Signature Generation  
Algorithm: `-7 ES256`, option discoverable: `true`

We explore the idea to use `credentials.get(known_input)` method as a PRNG.  
We know that `secp256k1` signatures contain a random component but not sure about `secp256r1.  
Verification done by producing 3 signatures using same input:

```
SIG1: 304402202d94cef1bc743ff6eff80d7e9ead7c343ebfecbefcbdb35f28505d710f54caf802201b252d8ae36bee149cffd2170524cf787da1aedc3dadf484aa3a627bce08072a
SIG2: 3044022009aa8115b01be60af0a595bd517074d226bcecae0127b58b27e2cf6522085e1b02201823a4a4eef9c5fa5e39a31992019d3d8c9761dbe80f5730624a184b8df0b04e
SIG3: 30450220650ab16cd209d57bdbe49031c8eb09b40a34af15f7915d06d25311ccef1a5261022100ce3bf05975760ca3d56bbce7d88a51da83223da8079ca3cd90a2887195c1c741
```

Looking at the response we notice a difference in bytelength of `clientDataJSON`
```
ClientDataJSON 1
'{"type":"webauthn.get","challenge":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","origin":"http://localhost:8080","crossOrigin":false}'

ClientDataJSON 2
'{"type":"webauthn.get","challenge":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","origin":"http://localhost:8080","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}'
```
It seems something has tampered with our inputs..  
Excerpt from https://goo.gl/yabPex :

> In order to guide sites away from doing this, Chromium will sometimes, randomly insert an extra member into clientDataJSON which references this documentation.

#### Results: `negative`

Using sign() as a PRNG does not work because of two reasons:
1. Random component
2. Random browser-vendor payload injection

The latter is troublesome, because it invalidates the idea of reconstructing `clientDataJSON` bytes from application data.
Hence `clientDataJSON` has to be stored together with `authenticatorData`


### `Iteration 4`
**Public Key Recovery**

In another attempt to use the hardware signing features in combination with discoverable credentials,
we explore if the public key can be recovered from the Signature.

Stumbled upon a [quote](https://old.reddit.com/r/crypto/comments/pu4yn4/secp256k1_recoverable_public_key_from_signature/hedvs9f/):

> The root of trust is always in the public key, not the signature.  
> A recovered public key is useless if there is no prior trust relationship associated with it.

#### Results: `positive`

There was no issue to recover public keys from the `p256` / `secp256r1` curve.

Package `@noble/curves` exposes recovery functions:
```js
import { p256 } from '@noble/curves/p256'
const publicKey = '...'
// Extract recovery bit
const recoveryBit = p256.ProjectivePoint.fromHex(publicKey).hasEvenY() ? 0 : 1

// Recover public key
const recoveredKey = p256.Signature.fromDER(sig)
    .addRecoveryBit(recoveryBit)
    .recoverPublicKey(msgHash)
    .toRawBytes(true)

console.log(recoveredKey === publicKey) // => true
```


### `Iteration 5`
Recovering `PublicKey` from signature is effectively a compression technique, instead of storing the 32bytes from creation we now need to find storage space for 1bit. 

W.I.P.
