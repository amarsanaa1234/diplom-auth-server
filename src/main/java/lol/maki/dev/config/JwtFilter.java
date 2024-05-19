package lol.maki.dev.config;

import lol.maki.dev.Tools.Tools;
import lol.maki.dev.jwt.IdTokenEnhancer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtFilter extends OncePerRequestFilter {
    private static final String JWT_TOKEN_COOKIE_NAME = "JWT-TOKEN";
    private static final String SIGNING_KEY = "signingKey";
    private final JwtAccessTokenConverter tokenEnhancer;
    private final OAuth2AccessToken accessToken;
    private final OAuth2Authentication authentication;

    public JwtFilter(JwtAccessTokenConverter tokenEnhancer, OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        this.tokenEnhancer = tokenEnhancer;
        this.accessToken = accessToken;
        this.authentication = authentication;
    }

    @Override
    public void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        OAuth2AccessToken enhancedToken = tokenEnhancer.enhance(accessToken, authentication);
        if (enhancedToken == null || enhancedToken.getValue().isEmpty()) {
            String authService = getFilterConfig().getInitParameter("services.auth");
            httpServletResponse.sendRedirect(authService + "?redirect=" + httpServletRequest.getRequestURL());
        } else {
            httpServletRequest.setAttribute("username", enhancedToken.getValue());
            filterChain.doFilter(httpServletRequest, httpServletResponse);
        }
    }
}
