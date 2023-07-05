import React, { useState } from 'react'
import { createAccount } from '@didtools/key-webauthn'
// import { DIDSession } from 'did-session'

export function WithWebauthnCacao () {
    const [optsVisible, setOptsVisible] = useState(false)
    return (<>
        <button onClick={() => setOptsVisible(!optsVisible)}>
            Webauthn + CACAO
        </button>
        {optsVisible && (
            <div>
                <button onClick={createIdentityHandler}>Create Identity</button>
                <button>Use Existing</button>
            </div>
        )}
    </>)
}

async function createIdentityHandler () {
    try {
     const did = await createAccount()
     console.info('Create Account done', did)
    } catch (err) {
        console.error('Create Identity failed:', err)
    }
}