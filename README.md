# DID

This library a simple interface to interact with DIDs that conform to the DID-provider interface.

## Installation

```sh
npm install dids
```

## Example usage

```js
import { DID } from 'dids'
import IdentityWallet from 'identity-wallet'

// See https://github.com/3box/identity-wallet-js
const wallet = new IdentityWallet(async () => true, {})
const alice = new DID(wallet.getDidProvider())

// Authenticate with the provider
await alice.authenticate()

// Read the DID string - this will throw an error if the DID instance is not authenticated
const aliceDID = alice.DID

// Create a JWS - this will throw an error if the DID instance is not authenticated
const jws = await alice.createJWS({ hello: 'world' })
```

## Interfaces and types

### CreateJWSOptions

```ts
interface CreateJWSOptions {
  protected?: Record<string, any>
  pubKeyId?: string
}
```

## API

### DID class

#### did.authenticated

**Returns** `boolean`

#### did.DID

> Accessing this property will throw an error if the instance is not authenticated

**Returns** `string`

#### did.authenticate()

**Returns** `Promise<string>`

#### did.createJWS()

> The instance needs to be authenticated before calling this method

**Arguments**

1. `payload: Record<string, any>`
1. `options?: CreateJWSOptions` to specify the `protected` header and/or `pubKeyId` to use for signing

**Returns** `Promise<string>`
