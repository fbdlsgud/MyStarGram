package com.himedia.spserver.security;

import com.himedia.spserver.security.filter.JWTCheckFilter;
import com.himedia.spserver.security.handler.APILoginFailHandler;
import com.himedia.spserver.security.handler.APILoginSuccessHandler;
import com.himedia.spserver.security.handler.CustomAccessDeniedHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

// 이 클래스는 security 에서  환경설정과 운영을 위해 사용할 클래스를 담아두는 스프링 컨테이너 입니다
@Configuration     // 이 클래스를 스프링 컨테이너로 사용하기위한 어너테이션
@RequiredArgsConstructor   // @Autowired 대신 사용할 자동 의존주입 어너테이션 (final 로 선언 필수)
public class CustomSecurityConfig {

    // 세개의 Bean 이 들어갑니다.
    // security 환경설정을 위한 Bean - 환경설정 후 설정된 객체(SecurityFilterChain)를 리턴해주는 매서드
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, CorsConfigurationSource corsConfigurationSource) throws Exception {
        // 전달받은 매개변수 http 로 security 환경설정후 build 된 객체를 리턴
        System.out.println("------------security config start-------------");

        // 서로다른 위치의 서버간 자료공유 규칙설정
        http.cors(
              httpSecurityCorsConfigurer -> {
                  httpSecurityCorsConfigurer.configurationSource( corsConfigurationSource() );
              }
        );

        // 신뢰할수 있는 사용자를 사칭한 변형공격에 대한 설정. 아예 그 에대한 요청을 disable
        http.csrf(config -> config.disable());

        // 세션에 상태저장을 하지 않을 환경 설정
        http.sessionManagement(
                sessionConfig->sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        // 로그인에 관한 설정
        http.formLogin(
                config -> {
                    // security에서 제공한 로컬 로그인 기능
                    config.loginPage("/member/loginlocal");
                    // 로그인 요청이 현재  url 오면  loadUserByUsername() 자동 호출
                    // loadUserByUsername 메서드는   CustomUserDetailService  클래스에 있습니다

                    //로그인 성공시 실행할 코드를 갖은 클래스
                    config.successHandler( new APILoginSuccessHandler() );
                    // 로그인 실패시 실행항 코드를 갖은 클래스
                    config.failureHandler( new APILoginFailHandler() );
                }
        );

        // 요청 토큰을 어디서 체크하고 검증할건지에 대한 설정
        http.addFilterBefore( new JWTCheckFilter() ,  UsernamePasswordAuthenticationFilter.class );
        // 토큰 유효성 검사 : new JWTCheckFilter()
        // 토큰안에 있는 사용자정보의 확인 : UsernamePasswordAuthenticationFilter.class
        // UsernamePasswordAuthenticationFilter.class 는 실제 로그인에도 사용되는 내장 클래스입니다

        // 요청 접근시 발생한 모든 예외처리에 대한 설정(로그인 오류, 토큰 오류 등등)
        http.exceptionHandling(
                config -> {
                    config.accessDeniedHandler(new CustomAccessDeniedHandler());
                }
        );

        return http.build();
    }

    // 패스워드 암호화를 Bean
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // CORS 설정을 위한 Bean
    private CorsConfigurationSource corsConfigurationSource() {
        // 새로운 CorsConfiguration 을 생성후 규칙 추가하고 리턴
        CorsConfiguration configuration = new CorsConfiguration();
        // 모든 아이피(출발지점)에  대해 응답 허용
        configuration.setAllowedOriginPatterns( Arrays.asList("*") );
        // "HEAD", "GET", "POST", "PUT", "DELETE" 요청에만 응답 허용
        configuration.setAllowedMethods( Arrays.asList("HEAD", "GET", "POST", "PUT", "DELETE") );
        // "Authorization", "Cache-Control", "Content-Type" 헤더에 대해서만 응답 허용
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        // 내 서버가 응답할 때 json을 JS에서 처리할 수 있게 설정
        configuration.setAllowCredentials(true);

        // 현재 설정사향등을 웹에 필요한 CORS 환경설정 클래스에 추가하여 리턴
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
