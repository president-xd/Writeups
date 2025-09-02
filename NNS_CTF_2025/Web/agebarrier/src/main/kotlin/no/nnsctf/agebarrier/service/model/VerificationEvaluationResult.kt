package no.nnsctf.agebarrier.service.model

sealed class VerificationEvaluationResult {
    data object Success : VerificationEvaluationResult()
    data object Failure : VerificationEvaluationResult()
}
