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
package eu.europa.ec.eudi.openid4vci.internal.http

import eu.europa.ec.eudi.openid4vci.AttestationBasedClientAuthenticationSpec
import eu.europa.ec.eudi.openid4vci.Nonce
import io.ktor.client.call.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.json.Json

/**
 * Extracts the new Nonce value for DPoP from this [HttpResponse].
 */
internal fun HttpResponse.dpopNonce(): Nonce? = nonceHeader("DPoP-Nonce")

/**
 * Extracts the new Attestation-Based Client Authentication Challenge from this [HttpResponse].
 */
internal fun HttpResponse.abcaChallege(): Nonce? = nonceHeader(AttestationBasedClientAuthenticationSpec.CHALLENGE_HEADER)

private fun HttpResponse.nonceHeader(name: String): Nonce? = headers[name]?.let(::Nonce)

/**
 * Checks if this [HttpResponse] is from a Resource Server that requires a Nonce value to be included in the DPoP Header.
 */
internal fun HttpResponse.isResourceServerDpopNonceRequired(): Boolean =
    when (status) {
        HttpStatusCode.Unauthorized -> {
            val wwwAuthenticate = headers[HttpHeaders.WWWAuthenticate]
            wwwAuthenticate?.let {
                it.contains("DPoP") && it.contains("error=\"use_dpop_nonce\"")
            } ?: false
        }

        else -> false
    }

internal suspend fun HttpResponse.errorResponseOrFallback(): GenericErrorResponseTO {
    val contentType = contentType()?.withoutParameters()
    if (contentType == ContentType.Application.Json) {
        runCatching { body<GenericErrorResponseTO>() }.getOrNull()?.let { return it }
    }

    parseWwwAuthenticateError()?.let { return it }

    val bodyText = runCatching { bodyAsText() }.getOrNull().orEmpty().trim()
    if (bodyText.isNotEmpty()) {
        runCatching { Json.decodeFromString<GenericErrorResponseTO>(bodyText) }.getOrNull()?.let { return it }
    }

    return GenericErrorResponseTO(
        error = "http_${status.value}",
        errorDescription = "HTTP ${status.value} ${status.description}",
    )
}

private fun HttpResponse.parseWwwAuthenticateError(): GenericErrorResponseTO? {
    val header = headers[HttpHeaders.WWWAuthenticate] ?: return null
    val error = Regex("""error="([^"]+)"""").find(header)?.groupValues?.getOrNull(1) ?: return null
    val description = Regex("""error_description="([^"]+)"""").find(header)?.groupValues?.getOrNull(1)
    return GenericErrorResponseTO(error = error, errorDescription = description)
}
