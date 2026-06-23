/*
 * Copyright (c) 2023-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vci

import com.nimbusds.jose.jwk.JWK
import kotlinx.coroutines.test.runTest
import java.net.URI
import java.time.Clock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DPoPJwtFactoryTest {

    @Test
    fun `adds key attestation to token endpoint DPoP proof when requested`() = runTest {
        val signer = AttestedDpopSigner()
        val factory = DPoPJwtFactory(clock = Clock.systemUTC(), signer = signer)
        val nonce = Nonce("token-dpop-nonce")

        val jwt = factory.createDPoPJwt(
            htm = Htm.POST,
            htu = URI("https://issuer.example/token").toURL(),
            nonce = nonce,
            includeKeyAttestation = true,
        ).getOrThrow()

        assertEquals(nonce, signer.preparedNonce)
        assertEquals(WALLET_TRUST_EVIDENCE, jwt.jwtClaimsSet.getStringClaim("key_attestation"))
    }

    @Test
    fun `does not add key attestation to regular DPoP proof`() = runTest {
        val factory = DPoPJwtFactory(clock = Clock.systemUTC(), signer = AttestedDpopSigner())

        val jwt = factory.createDPoPJwt(
            htm = Htm.POST,
            htu = URI("https://issuer.example/credential").toURL(),
            nonce = Nonce("credential-dpop-nonce"),
        ).getOrThrow()

        assertNull(jwt.jwtClaimsSet.getStringClaim("key_attestation"))
    }

    private class AttestedDpopSigner : Signer<JWK>, DPoPKeyAttestationSigner {
        private val delegate = CryptoGenerator.ecSigner()

        var preparedNonce: Nonce? = null
            private set

        override val javaAlgorithm: String
            get() = delegate.javaAlgorithm

        override suspend fun prepareKeyAttestation(nonce: Nonce) {
            preparedNonce = nonce
        }

        override suspend fun acquire(): SignOperation<JWK> =
            delegate.acquire().copy(dpopKeyAttestation = WALLET_TRUST_EVIDENCE)

        override suspend fun release(signOperation: SignOperation<JWK>?) {
            delegate.release(signOperation)
        }
    }

    companion object {
        private const val WALLET_TRUST_EVIDENCE = "rwsca-wte"
    }
}
