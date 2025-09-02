package no.nnsctf.agebarrier.service

import no.nnsctf.agebarrier.repository.model.VerificationLevel
import no.nnsctf.agebarrier.service.model.VerificationEvaluationResult
import no.nnsctf.agebarrier.service.model.VerificationToken

interface VerificationEvaluatorService {
    fun evaluate(token: VerificationToken, level: VerificationLevel): VerificationEvaluationResult
}