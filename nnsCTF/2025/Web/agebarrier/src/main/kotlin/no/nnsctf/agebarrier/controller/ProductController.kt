package no.nnsctf.agebarrier.controller

import no.nnsctf.agebarrier.controller.model.ProductClaimRequest
import no.nnsctf.agebarrier.controller.model.ProductClaimResponseView
import no.nnsctf.agebarrier.controller.model.ProductsResponseView
import no.nnsctf.agebarrier.repository.ProductRepository
import no.nnsctf.agebarrier.repository.model.VerificationRequirement
import no.nnsctf.agebarrier.service.VerificationEvaluatorService
import no.nnsctf.agebarrier.service.VerificationTokenService
import no.nnsctf.agebarrier.service.model.TokenDecodeResult
import no.nnsctf.agebarrier.service.model.VerificationEvaluationResult
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController
class ProductController(
    @Autowired
    private val productRepository: ProductRepository,
    @Autowired
    private val tokenService: VerificationTokenService,
    @Autowired
    private val verificationEvaluatorService: VerificationEvaluatorService,
) {
    @GetMapping("/products")
    fun getProducts(): ResponseEntity<ProductsResponseView> {
        val products = productRepository.getProducts()
            .map(ProductsResponseView.Item::from)
            .toList()

        return ResponseEntity.ok(ProductsResponseView(products))
    }

    @PostMapping("/products/{id}")
    fun claimProduct(
        @PathVariable("id") id: Int,
        @RequestBody body: ProductClaimRequest
    ): ResponseEntity<ProductClaimResponseView> {
        val product = productRepository.getProduct(id)
            ?: return ResponseEntity.notFound().build()

        val verificationToken = when (val result = tokenService.decodeToken(body.token)) {
            TokenDecodeResult.Failure -> return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
            is TokenDecodeResult.Success -> result.token
        }

        val verificationRequirement = product.verificationRequirement
        if (verificationRequirement is VerificationRequirement.Required) {
            val evaluationResult = verificationEvaluatorService.evaluate(
                verificationToken,
                verificationRequirement.level
            )
            if (evaluationResult !is VerificationEvaluationResult.Success) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build()
            }
        }

        return ResponseEntity.ok(ProductClaimResponseView(product.content))
    }
}