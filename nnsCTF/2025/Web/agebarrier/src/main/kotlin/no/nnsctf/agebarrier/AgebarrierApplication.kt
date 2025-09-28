package no.nnsctf.agebarrier

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
open class AgebarrierApplication

fun main(args: Array<String>) {
    runApplication<AgebarrierApplication>(*args)
}
