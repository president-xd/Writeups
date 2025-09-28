package no.nnsctf.agebarrier.service.impl

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.crypto.X25519Decrypter
import com.nimbusds.jose.crypto.X25519Encrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import no.nnsctf.agebarrier.service.DateTimeFormatterProviderService
import no.nnsctf.agebarrier.service.VerificationTokenService
import no.nnsctf.agebarrier.service.model.TokenDecodeResult
import no.nnsctf.agebarrier.service.model.VerificationToken
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import java.time.LocalDate
import java.time.LocalDateTime

@Service
class DefaultVerificationTokenService(
    @Autowired
    private val dateTimeFormatterProviderService: DateTimeFormatterProviderService
) : VerificationTokenService {
    private val ed25519Jwk = OctetKeyPairGenerator(Curve.Ed25519).generate()
    private val x25519Jwk = OctetKeyPairGenerator(Curve.X25519).generate()
    private val signer = Ed25519Signer(ed25519Jwk)
    private val verifier = Ed25519Verifier(ed25519Jwk.toPublicJWK())
    private val encrypter = X25519Encrypter(x25519Jwk.toPublicJWK())
    private val decrypter = X25519Decrypter(x25519Jwk)

    override fun issueToken(): String {
        val currentTime = dateTimeFormatterProviderService.get().format(LocalDateTime.now())
        val jwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.EdDSA).build(),
            JWTClaimsSet.Builder().claim("iss", currentTime).build()
        ).apply {
            sign(signer)
        }
        val jwe = JWEObject(
            JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM).build(),
            Payload(jwt)
        ).apply {
            encrypt(encrypter)
        }
        return jwe.serialize()
    }

    override fun decodeToken(token: String): TokenDecodeResult {
        try {
            val jwe = JWEObject.parse(token).apply {
                decrypt(decrypter)
            }
            val jwt = jwe.payload.toSignedJWT()
            if (!jwt.verify(verifier)) {
                return TokenDecodeResult.Failure
            }

            val issuedAtClaim = jwt.jwtClaimsSet.getStringClaim("iss")
            val issuedAt = LocalDate.from(dateTimeFormatterProviderService.get().parse(issuedAtClaim))

            return TokenDecodeResult.Success(VerificationToken(issuedAt))
        } catch (e: Exception) {
            return TokenDecodeResult.Failure
        }
    }
}