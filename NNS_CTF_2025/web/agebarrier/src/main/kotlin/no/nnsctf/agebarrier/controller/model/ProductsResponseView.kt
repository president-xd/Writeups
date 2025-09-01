package no.nnsctf.agebarrier.controller.model

import no.nnsctf.agebarrier.repository.model.Product
import no.nnsctf.agebarrier.repository.model.VerificationRequirement

data class ProductsResponseView(val products: List<Item>) {
    data class Item(
        val id: Int,
        val name: String,
        val description: String,
        val verificationRequirement: VerificationRequirement
    ) {
        companion object {
            fun from(product: Product): Item =
                Item(product.id, product.name, product.description, product.verificationRequirement)
        }
    }
}
