package no.nav.klage.auth.test

import no.nav.klage.auth.TokenXAuthProperties
import no.nav.klage.auth.tokenXJwtDecoder
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.core.env.Environment
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get

@Configuration
@EnableWebSecurity
class TestTokenXSecurityConfiguration {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain =
        http
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeHttpRequests {
                it
                    .requestMatchers("/internal/health")
                    .permitAll()
                    .anyRequest()
                    .authenticated()
            }.oauth2ResourceServer { it.jwt { } }
            .build()

    @Bean
    fun jwtDecoder(environment: Environment): JwtDecoder = tokenXJwtDecoder(TokenXAuthProperties.from(environment))
}

@WebMvcTest(TestController::class)
@Import(TestTokenXSecurityConfiguration::class)
class TokenXSecurityContractSelfTest : TokenXSecurityContractTest() {
    override fun protectedRequest() = get("/api/hello")
}
