package com.himedia.spserver.security.handler;

import com.google.gson.Gson;
import com.himedia.spserver.dto.MemberDTO;
import com.himedia.spserver.security.util.JWTUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

public class APILoginSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 매개변수 authentication : 로그인에 성공한  유저의 MemberDTO 가 같이 포함된 객체

        // authentication에서 MemberDTO를 꺼냅니다
        MemberDTO memberDTO = (MemberDTO)authentication.getPrincipal();

        // getClaims 를 이용해서 사용자 정보를 Map 형태로 추출 : 토큰 생성용 자료
        Map<String, Object> claims = memberDTO.getClaims();

        // 사용장정보가 들어있는 Map 자료(claims)를 이용하여 토큰을 생성
        String accessToken = JWTUtil.generateToken(claims, 1);
        String refreshToken = JWTUtil.generateToken(claims, 60*24);

        claims.put("accessToken", accessToken);
        claims.put("refreshToken", refreshToken);

        Gson gson = new Gson();
        String jsonStr = gson.toJson(claims);  // claims에 있는 데이터를 json형태로 변환

        response.setContentType("application/json");  // response 에 전송될 데이터형을 설정
        response.setCharacterEncoding("UTF-8");   // 한글 인코딩 설정
        PrintWriter printWriter = response.getWriter();  // 출력도구를 얻어서
        printWriter.println(jsonStr);  // 얻어낸 도구로 출력  -> 전송
        printWriter.close();
    }
}
