package no.nnsctf.agebarrier.service

import java.time.format.DateTimeFormatter

fun interface DateTimeFormatterProviderService {
    fun get(): DateTimeFormatter
}