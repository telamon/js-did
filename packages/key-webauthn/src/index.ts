import { AccountId } from 'caip'
// import { Cacao, SiweMessage, AuthMethod, AuthMethodOpts } from '@didtools/cacao'
import { alloc } from 'uint8arrays/alloc'
// AFAIK: Webauthn requires a browser.
const { credentials } = globalThis.navigator
const { crypto } = globalThis

type WebauthnCreateOpts = {
    // Relaying party configuration (Consuming WebApp)
    rpid: PublicKeyCredentialCreationOptions['rp']['id'], // SecureContext Name
    rpname: PublicKeyCredentialCreationOptions['rp']['name'],

    // User facing identifiers (Shown on device/selection screens)
    // This seems to be the string displayed on windows/chrome (windows-hello credential store)
    name: PublicKeyCredentialCreationOptions['user']['name'],
    displayName: PublicKeyCredentialCreationOptions['user']['displayName'] // shown in system popups
}

export async function createAccount (opts?: WebauthnCreateOpts) {
    opts = {
        rpid: opts?.rpid ?? globalThis.location.hostname,
        rpname: opts?.rpname ?? 'Webapp connected to CeramicNetwork',
        name: opts?.name ?? 'ceramicuser',
        displayName: opts?.displayName ?? 'Ceramic User'
    }
    const chainId = 'eip155:1' // Webauthn is not related to ETH afaik.

    const config = {
        publicKey: {
            challenge: randomBytes(32),
            rp: { id: opts.rpid, name: opts.rpname },
            user: {
                id: randomBytes(32),
                name: opts.name,
                displayName: opts.displayName,
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
    } as CredentialCreationOptions

    const cred = await credentials.create(config)
    debugger
    const account_address = '' // Key Identifier (64)
    console.log('credentials.create()', opts, config, cred, account_address)
    return new AccountId({ address: account_address, chainId })
}
/*
export async function getAuthMethod () : Promise<AuthMethod> {
    return () => {
    }
} */

function randomBytes (n: number) {
    const b = alloc(n)
    crypto.getRandomValues(b)
    return b
}

/*
async function createCACAO(
  opts: AuthMethodOpts,
  ethProvider: any,
  account: AccountId
): Promise<Cacao> {
  const now = new Date()
  const oneWeekLater = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000)
  // const normAccount = normalizeAccountId(account)

  const siweMessage = new SiweMessage({
    domain: opts.domain,
    address: '???' // normAccount.address,
    statement: opts.statement ?? 'Give this application access to some of your data on Ceramic',
    uri: opts.uri,
    version: VERSION,
    nonce: opts.nonce ?? randomString(10),
    issuedAt: now.toISOString(),
    expirationTime: opts.expirationTime ?? oneWeekLater.toISOString(),
    chainId: normAccount.chainId.reference,
    resources: opts.resources,
  })
  const signature = await safeSend(ethProvider, 'personal_sign', [
    encodeHexStr(siweMessage.signMessage()),
    normAccount.address,
  ])
  siweMessage.signature = signature
  return Cacao.fromSiweMessage(siweMessage)

} */