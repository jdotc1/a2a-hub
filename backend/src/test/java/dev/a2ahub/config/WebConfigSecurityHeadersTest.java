package dev.a2ahub.config;

import dev.a2ahub.security.SecurityProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.Ordered;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class WebConfigSecurityHeadersTest {

    @Test
    void securityHeaderFilterIsRegisteredBeforeAuthenticationAndRateLimiting() {
        var registration = new WebConfig(new SecurityProperties()).securityHeadersFilter();
        assertThat(registration.getOrder()).isEqualTo(Ordered.HIGHEST_PRECEDENCE + 1);
        assertThat(registration.getOrder()).isLessThan(10);
    }

    @ParameterizedTest
    @ValueSource(ints = {401, 429})
    void securityHeadersSurviveEarlyRejection(int rejectionStatus) throws Exception {
        var filter = new WebConfig(new SecurityProperties()).securityHeadersFilter().getFilter();
        var request = new MockHttpServletRequest("POST", "/api/v1/agents");
        var response = new MockHttpServletResponse();
        FilterChain rejectingDownstreamFilter = (req, res) ->
                ((HttpServletResponse) res).setStatus(rejectionStatus);

        filter.doFilter(request, response, rejectingDownstreamFilter);

        assertThat(response.getStatus()).isEqualTo(rejectionStatus);
        assertThat(response.getHeader("Content-Security-Policy")).contains("default-src 'none'");
        assertThat(response.getHeader("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(response.getHeader("X-Frame-Options")).isEqualTo("DENY");
        assertThat(response.getHeader("Referrer-Policy")).isNotBlank();
        assertThat(response.getHeader("Strict-Transport-Security")).isNotBlank();
        assertThat(response.getHeader("Permissions-Policy")).isNotBlank();
        assertThat(response.getHeader("Cross-Origin-Opener-Policy")).isEqualTo("same-origin");
        assertThat(response.getHeader("Cross-Origin-Resource-Policy")).isEqualTo("same-origin");
    }
}
