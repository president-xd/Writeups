package no.nnsctf.agebarrier.service

import no.nnsctf.agebarrier.service.model.TokenDecodeResult

interface VerificationTokenService {
    fun issueToken(): String

    fun decodeToken(token: String): TokenDecodeResult
}