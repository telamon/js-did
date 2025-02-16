## Webauthn AuthMethod and Verifier

Implements support to authenticate, authorize and verify blocks produced
by webauthn/passkey compatible hardware authenticators and OS/software implementations.

## Installation

```
npm install --save @didtools/key-webauthn
```

## Auth Usage

This module is designed to run in browser environments.

Create a Credential for first time use:
```js
import { WebauthnAuth } from '@didtools/key-webauthn'

const did = await WebauthnAuth.createDid('app-user')

const authMethod = await WebauthnAuth.getAuthMethod({ did })
const session = await DIDSession.authorize(authMethod, { resources: ['ceramic://nil'] })
```

## Verifier Usage

Verifiers are needed to verify different did:pkh signed payloads using CACAO. Libraries that need them will
consume a verifiers map allowing your to register the verifiers you want to support. 

```js
import { Cacao } from '@didtools/cacao'
import { WebauthnAuth } from '@didtools/key-webauthn'
import { DID } from 'dids'

const verifiers = {
	...WebauthnAuth.getVerifier()
}

// Directly with cacao
Cacao.verify(cacao, { verifiers, ...opts})

// With DIDS, reference DIDS for more details
const dids = // configured dids instance
await dids.verifyJWS(jws, { capability, verifiers, ...opts})
```

## Caveat: DID selection

The webauthn+fido2 standard was originally developed for use with databases and at that time
a pesudo random `CredentialID` was preferred over the use of public keys.  

The public key is exported only **once** when the credential is created - spec limitation.
There are 3 options for `getAuthMethod()`

#### Option 1. Known DID

```js
import { WebauthnAuth } from '@didtools/key-webauthn'

const authMethod = WebauthnAuth.getAuthMethod({ did: 'did:key:zDn...' })
```
#### Option 2. Probe

Probe the authenticator for public keys by asking user to sign a nonce:

```js
import { WebauthnAuth } from '@didtools/key-webauthn'

const dids = await WebauthnAuth.probeDIDs()
const authMethod = WebauthnAuth.getAuthMethod({ dids })
```

#### Option 3. Callback

Use a callback with the following call signature:

```ts
(did1: string, did2: string) => Promise<string>
```

Example that probes on-demand:
```js
import { WebauthnAuth } from '@didtools/key-webauthn'

const selectDIDs = async (did1, did2) {
    const dids = await WebauthnAuth.probeDIDs()
    if (dids.includes(did1)) return did1
    else return did2
}

const authMethod = WebauthnAuth.getAuthMethod({ selectDIDs })
```

## License

Apache-2.0 OR MIT
