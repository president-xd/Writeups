package no.nnsctf.agebarrier.service.model

sealed class TokenDecodeResult {
    data object Failure : TokenDecodeResult()
    data class Success(val token: VerificationToken) : TokenDecodeResult()
}