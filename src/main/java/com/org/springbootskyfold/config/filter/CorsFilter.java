package com.org.springbootskyfold.config.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.Arrays;
import java.util.Collections;
import java.util.stream.Collectors;


@Component("CustomCorsFilter")
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorsFilter implements Filter {

    @Value("${security.accessControl.allowOrigins:}")
    private String accessControlAllowOrigins;

    @Value("${security.accessControl.allowHeaders:}")
    private String accessControlAllowHeaders;

    @Value("${security.accessControl.allowMethods:}")
    private String accessControlAllowMethods;

    @Value("${security.accessControl.maxAge:86400}")
    private long accessControlMaxAge;


    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) resp;

        String origin = request.getHeader("Origin");

        if (origin != null && !origin.isEmpty()) {
            String allowedOrigin = this.checkAndGetAllowedOrigin(origin, accessControlAllowOrigins());

            if (!accessControlAllowMethods().contains(request.getMethod())) {
                System.out.printf(String.format("Origem: %s, não autorizada a acessar recurso: %s %s %s", origin, allowedOrigin,
                        request.getRequestURI(), request.getMethod()));
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);

                return;
            }

            response.setHeader("Access-Control-Allow-Origin", origin);
            response.setHeader("Access-Control-Max-Age", String.valueOf(accessControlMaxAge));
            response.setHeader("Access-Control-Allow-Methods", String.join(",", accessControlAllowMethods()));
            response.setHeader("Access-Control-Allow-Headers", String.join(",", accessControlAllowHeaders()));

            if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
                response.setStatus(HttpServletResponse.SC_OK);

                return;
            }
        }
        chain.doFilter(req, resp);
    }

    private String checkAndGetAllowedOrigin(String origin, Set<String> accessControlAllowOrigins) {
        return accessControlAllowOrigins.stream()
                .map(String::trim)
                .filter(origin::equalsIgnoreCase)
                .findFirst()
                .orElse("");
    }

    private static boolean contains(Set<String> set, String value) {
        return set.stream()
                .anyMatch(s -> s != null && value.trim().equalsIgnoreCase(s.trim()));
    }

    public Set<String> accessControlAllowOrigins() {
        return toSetOfStrings(this.accessControlAllowOrigins);
    }

    public Set<String> accessControlAllowHeaders() {
        return toSetOfStrings(this.accessControlAllowHeaders);
    }

    public Set<String> accessControlAllowMethods() {
        return toSetOfStrings(this.accessControlAllowMethods);
    }

    private static Set<String> toSetOfStrings(String value) {
        if (value != null && !value.trim().isEmpty()) {
            return Arrays.stream(value.split(","))
                    .map(String::trim)
                    .collect(Collectors.toSet());
        }

        return Collections.emptySet();
    }

    private static Set<Pattern> toSetOfPatterns(String value) {
        if (value != null && !value.trim().isEmpty()) {
            return Arrays.stream(value.split(","))
                    .map(String::trim)
                    .map(Pattern::compile)
                    .collect(Collectors.toSet());
        }

        return Collections.emptySet();
    }
}