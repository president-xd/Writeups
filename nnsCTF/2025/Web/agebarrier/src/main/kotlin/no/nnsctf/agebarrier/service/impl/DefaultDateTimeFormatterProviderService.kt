package no.nnsctf.agebarrier.service.impl

import no.nnsctf.agebarrier.service.DateTimeFormatterProviderService
import org.springframework.context.i18n.LocaleContextHolder
import org.springframework.stereotype.Service
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.time.format.ResolverStyle

@Service
class DefaultDateTimeFormatterProviderService : DateTimeFormatterProviderService {
    override fun get(): DateTimeFormatter {
        return DateTimeFormatter.ofLocalizedDate(FormatStyle.SHORT)
            .withLocale(LocaleContextHolder.getLocale())
            .withResolverStyle(ResolverStyle.LENIENT)
    }
}