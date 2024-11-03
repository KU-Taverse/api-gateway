package ku.apigateway.filter;

import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Date;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    Environment env;
    public AuthorizationHeaderFilter(Environment env){
        super(Config.class);
        this.env = env;
    }
    public static class Config{}

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            // 쿠키에서 jwtToken을 찾기
            String jwt = null;
            if (request.getCookies().containsKey("jwtToken")) {
                jwt = request.getCookies().getFirst("jwtToken").getValue();
            }
            if(jwt == null ||!isJwtValid(jwt)){
                return onError(exchange,"no valid jwt", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        });
    }

    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;

        try {
            // JWT 파싱
            var claims = Jwts.parser()
                    .setSigningKey(env.getProperty("token.secret"))
                    .parseClaimsJws(jwt)
                    .getBody();

            // 만료 여부 확인
            if (claims.getExpiration().before(new Date())) {
                returnValue = false;
            }

            // subject 확인
            String subject = claims.getSubject();
            if (subject == null || subject.isEmpty()) {
                returnValue = false;
            }

            // status가 ADMIN인지 확인
            String status = claims.get("status", String.class);
            if (!"ADMIN".equals(status)) {
                returnValue = false;
            }
        } catch (Exception ex) {
            //log.error("JWT parsing error: {}", ex.getMessage());
            returnValue = false;
        }

        return returnValue;
    }

    //Mono, Flux -> WebFlux의 개념
    private Mono<Void> onError(ServerWebExchange exchange, String noAuthorizationHeader, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();

        // 리디렉션 설정
        response.setStatusCode(HttpStatus.FOUND); // 302 Redirect 상태 코드
        response.getHeaders().setLocation(URI.create("/manager-service/admin/login")); // 리디렉션 경로 설정

        return response.setComplete();

    }

}
