package no.nnsctf.agebarrier.repository.model

sealed class VerificationRequirement {
    data object None : VerificationRequirement()

    data class Required(
        val level: VerificationLevel,
        val legislation: String,
        val remark: String
    ) : VerificationRequirement()
}
