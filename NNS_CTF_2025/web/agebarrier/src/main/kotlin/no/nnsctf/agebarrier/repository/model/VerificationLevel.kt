package no.nnsctf.agebarrier.repository.model

import java.time.Duration

sealed class VerificationLevel(
    val verificationDuration: Duration
) {
    data object Teen : VerificationLevel(Duration.ofDays(4749))
    data object Adult : VerificationLevel(Duration.ofDays(6575))
}