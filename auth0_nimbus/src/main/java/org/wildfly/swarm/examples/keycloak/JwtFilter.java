package org.wildfly.swarm.examples.keycloak;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Calendar;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebFilter(filterName = "jwtFilter", urlPatterns = "/*")
public class JwtFilter implements Filter {
  private final URL jwksUri = new URL("https://dev-4305394.okta.com/oauth2/default/v1/keys");

  public JwtFilter() throws MalformedURLException {
  }

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                       FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;
    System.out.println("In JwtFilter, path: " + request.getRequestURI());
    String authHeader = request.getHeader("authorization");
    try {
      if (authHeader == null) {
        throw new JwkException("");
      } else {
        String accessToken = authHeader.substring(authHeader.indexOf("Bearer ") + 7);
        //   validateThroughAuth0(accessToken);
        validateThroughNimbus(accessToken);
      }
    } catch (Exception e) {
      e.printStackTrace();
      response.setStatus(401);
      return;
    }
    chain.doFilter(request, response);
  }

  private void validateThroughAuth0(String accessToken) throws JwkException {
    DecodedJWT jwt = JWT.decode(accessToken);
    JwkProvider provider = new UrlJwkProvider(jwksUri);
    Jwk jwk = provider.get(jwt.getKeyId());
    Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
    algorithm.verify(jwt);
    if (jwt.getExpiresAt().before(Calendar.getInstance().getTime())) {
      throw new JwkException("");
    }
  }

  private void validateThroughNimbus(String accessToken) throws ParseException, JOSEException, BadJOSEException {
    ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
    JWKSource<SecurityContext> keySource =
          new RemoteJWKSet<>(jwksUri, new DefaultResourceRetriever(1000, 1000, 51200));
    JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
    JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
    jwtProcessor.setJWSKeySelector(keySelector);
//    jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>("https://dev-4305394.okta.com/oauth2/default",
//                "api://default", null));
    jwtProcessor.process(accessToken, null);
  }

  @Override
  public void init(FilterConfig filterConfig) { }

  @Override
  public void destroy() {
  }
}
