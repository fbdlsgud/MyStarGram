package com.himedia.spserver.security.filter;

import com.himedia.spserver.dto.MemberDTO;
import com.himedia.spserver.security.util.CustomJWTException;
import com.himedia.spserver.security.util.JWTUtil;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


public class JWTCheckFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeaderStr = request.getHeader("Authorization");
        String accessToken = authHeaderStr.substring(7);
        try {
            Map<String, Object> claims = JWTUtil.validateToken(accessToken);
            int id = (int) claims.get("id");
            String email = (String) claims.get("email");
            String pwd = (String) claims.get("pwd");
            String nickname = (String) claims.get("nickname");
            String phone = (String) claims.get("phone");
            String snsid = (String) claims.get("snsid");
            String provider = (String) claims.get("provider");
            String profileimg = (String) claims.get("profileimg");
            String profilemsg = (String) claims.get("intro");
            List<String> list = new ArrayList<>();
            list.add("USER");
            MemberDTO memberDTO = new MemberDTO(email, pwd, id, nickname, phone, provider, snsid ,  profileimg, profilemsg, list);
            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(memberDTO, pwd , memberDTO.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            filterChain.doFilter(request, response);
        } catch (CustomJWTException e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request)  throws ServletException {
        String path = request.getRequestURI();
        System.out.println("check uri.............." + path);
        if(request.getMethod().equals("OPTIONS"))
            return true;
        if(path.equals("/member/test"))
            return true;
        if(path.startsWith("/member/loginlocal"))
            return true;
        if(path.startsWith("/images/"))
            return true;
        if(path.startsWith("/userimg/"))
            return true;
        if(path.startsWith("/img/"))
            return true;

        if(path.startsWith("/member/emailcheck"))
            return true;
        if(path.startsWith("/member/nicknamecheck"))
            return true;
        if(path.startsWith("/member/fileupload"))
            return true;
        if(path.startsWith("/member/join"))
            return true;

        if(path.startsWith("/member/kakaostart"))
            return true;
        if(path.startsWith("/member/kakaoLogin"))
            return true;

        if(path.startsWith("/member/getEmail"))
            return true;

        if(path.startsWith("/member/refresh"))
            return true;


        return false;
    }
}
