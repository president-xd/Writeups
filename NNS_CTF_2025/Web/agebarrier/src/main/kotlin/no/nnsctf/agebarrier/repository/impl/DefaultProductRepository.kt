package no.nnsctf.agebarrier.repository.impl

import no.nnsctf.agebarrier.repository.ProductRepository
import no.nnsctf.agebarrier.repository.model.Product
import no.nnsctf.agebarrier.repository.model.VerificationLevel
import no.nnsctf.agebarrier.repository.model.VerificationRequirement
import org.springframework.stereotype.Repository

@Repository
class DefaultProductRepository : ProductRepository {
    private val products = listOf(
        Product(
            1,
            "Flýtibaka",
            "Educational content.",
            "https://open.kattis.com/problems/flytibaka",
            VerificationRequirement.None
        ),
        Product(
            2,
            "Tablet",
            "The gateway to modern brainrot.",
            "TODO: Add tablet",
            VerificationRequirement.Required(
                VerificationLevel.Teen,
                "Child Protections Act",
                "Protect pre-teens against brainrot."
            )
        ),
        Product(
            3,
            "Hard Flag",
            ":flushed:",
            System.getenv("FLAG") ?: "NNS{fakeflag}",
            VerificationRequirement.Required(
                VerificationLevel.Adult,
                "Humanity Protections Act",
                "Protect young population against harmful material."
            )
        )
    )

    override fun getProducts(): List<Product> = products

    // FIXME: O(N) performance is really bad!
    override fun getProduct(id: Int): Product? = products.first { it.id == id }
}
