package no.nnsctf.agebarrier.repository

import no.nnsctf.agebarrier.repository.model.Product

interface ProductRepository {
    fun getProducts(): List<Product>

    fun getProduct(id: Int): Product?
}