package no.nav.klage.auth.test

import no.nav.klage.auth.AzureAuthProperties
import no.nav.klage.auth.azureJwtDecoder
import org.springframework.boot.autoconfigure.SpringBootApplication
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
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@SpringBootApplication
class TestApplication

@RestController
class TestController {
    @GetMapping("/api/hello")
    fun hello() = "hello"
}

/** The same shape as the security configuration the apps are expected to have. */
@Configuration
@EnableWebSecurity
class TestSecurityConfiguration {
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
    fun jwtDecoder(environment: Environment): JwtDecoder = azureJwtDecoder(AzureAuthProperties.from(environment))
}

@WebMvcTest(TestController::class)
@Import(TestSecurityConfiguration::class)
class AzureSecurityContractSelfTest : AzureSecurityContractTest() {
    override fun protectedRequest() = get("/api/hello")
}
