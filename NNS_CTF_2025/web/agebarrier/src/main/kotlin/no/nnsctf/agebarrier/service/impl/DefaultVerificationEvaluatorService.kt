package no.nnsctf.agebarrier.service.impl

import no.nnsctf.agebarrier.repository.model.VerificationLevel
import no.nnsctf.agebarrier.service.VerificationEvaluatorService
import no.nnsctf.agebarrier.service.model.VerificationEvaluationResult
import no.nnsctf.agebarrier.service.model.VerificationToken
import org.springframework.stereotype.Service
import java.time.LocalDate

@Service
class DefaultVerificationEvaluatorService : VerificationEvaluatorService {
    override fun evaluate(token: VerificationToken, level: VerificationLevel): VerificationEvaluationResult {
        val currentDate = LocalDate.now()
        val targetDate = token.date.plusDays(level.verificationDuration.toDays())

        return when (currentDate >= targetDate) {
            true -> VerificationEvaluationResult.Success
            false -> VerificationEvaluationResult.Failure
        }
    }
}