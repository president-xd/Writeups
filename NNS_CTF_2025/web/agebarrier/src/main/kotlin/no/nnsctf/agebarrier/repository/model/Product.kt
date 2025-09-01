package no.nnsctf.agebarrier.repository.model

import no.nnsctf.agebarrier.annotations.Sensitive

data class Product(
    val id: Int,
    val name: String,
    val description: String,
    @Sensitive val content: String,
    val verificationRequirement: VerificationRequirement
)
