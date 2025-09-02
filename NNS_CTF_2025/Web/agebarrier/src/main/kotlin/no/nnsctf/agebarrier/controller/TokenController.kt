package no.nnsctf.agebarrier.controller

import no.nnsctf.agebarrier.controller.model.TokenResponseView
import no.nnsctf.agebarrier.service.VerificationTokenService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class TokenController(
    @Autowired
    private val tokenService: VerificationTokenService,
) {
    @PostMapping("/tokens")
    fun issueToken(): ResponseEntity<TokenResponseView> {
        val token = tokenService.issueToken()
        return ResponseEntity.ok(TokenResponseView(token))
    }
}