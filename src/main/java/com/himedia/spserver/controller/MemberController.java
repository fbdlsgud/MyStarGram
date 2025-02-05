package com.himedia.spserver.controller;

import com.google.gson.Gson;
import com.himedia.spserver.dto.KakaoProfile;
import com.himedia.spserver.dto.OAuthToken;
import com.himedia.spserver.entity.Follow;
import com.himedia.spserver.entity.Member;
import com.himedia.spserver.security.util.CustomJWTException;
import com.himedia.spserver.security.util.JWTUtil;
import com.himedia.spserver.service.MemberService;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;

@RestController
@RequestMapping("/member")
public class MemberController {

    @Autowired
    MemberService ms;

    @GetMapping("/test")
    public @ResponseBody String index(){
        return "<h1>Hello Security World</h1>";
    }

    @GetMapping("/getFollowings")
    public HashMap<String, Object> getFollowings(@RequestParam("userid") int userid){
        HashMap<String, Object> result = new HashMap<>();
        List<Follow> followings = ms.getFollowings(userid);
        if( followings == null ) followings = new ArrayList<>();
        result.put("followings", followings);
        //System.out.println(followings.get(0));
        return result;
    }

    @GetMapping("/getFollowers")
    public HashMap<String, Object> getFollowers(@RequestParam("userid") int userid){
        HashMap<String, Object> result = new HashMap<>();
        List<Follow> followers = ms.getFollowers(userid);
        if( followers == null ) followers = new ArrayList<>();
        result.put("followers", followers);
        return result;
    }


    @GetMapping("/getLoginUser")
    public HashMap<String , Object> getLoginUser(HttpSession session) {
        HashMap<String, Object> result = new HashMap<>();
        int id = (Integer) session.getAttribute("loginUser");

        // loginUser 멤버정보 조회
        Member member = ms.getMemberById(id);
        //System.out.println(member);

        // 로그인 유저의  follower 조회
        List<Follow> followers = ms.getFollowers(id);

        // 로그인 유저가 following하는 멤버 조회
        List<Follow> followings = ms.getFollowings(id);

        result.put("loginUser", member);
        result.put("followers", followers);
        result.put("followings", followings);

        return result;
    }


    @GetMapping("/logout")
    public HashMap<String, Object> logout(HttpSession session) {
        HashMap<String, Object> result = new HashMap<>();
        session.removeAttribute("loginUser");
        result.put("msg", "ok");
        return result;
    }


    @PostMapping("/emailcheck")
    public HashMap<String, Object> emailcheck( @RequestParam("email") String email ) {
        HashMap<String, Object> result = new HashMap<>();
        Member member = ms.getMember(email);
        if( member != null )
            result.put("msg", "no");
        else
            result.put("msg", "ok");
        return result;
    }

    @PostMapping("/nicknamecheck")
    public HashMap<String, Object> nicknamecheck( @RequestParam("nickname") String nickname ) {
        HashMap<String, Object> result = new HashMap<>();
        Member member = ms.getMemberByNickname(nickname);
        if( member != null )
            result.put("msg", "no");
        else
            result.put("msg", "ok");
        return result;
    }

    @Autowired
    ServletContext context;

    @PostMapping("/fileupload")
    public HashMap<String, Object> fileupload( @RequestParam("image") MultipartFile file ) {
        HashMap<String, Object> result = new HashMap<>();
        String path = context.getRealPath("/userimg");
        Calendar today = Calendar.getInstance();
        long dt = today.getTimeInMillis();
        String filename = file.getOriginalFilename();
        String fn1 = filename.substring(0, filename.indexOf(".") );
        String fn2 = filename.substring(filename.indexOf(".") );
        String uploadPath = path + "/" + fn1 + dt + fn2;
        try {
            file.transferTo( new File(uploadPath) );
            result.put("filename", fn1 + dt + fn2);
        } catch (IllegalStateException | IOException e) {
            e.printStackTrace();
        }
        return result;
    }

    @PostMapping("/join")
    public HashMap<String, Object> join( @RequestBody Member member){
        HashMap<String, Object> result = new HashMap<>();
        ms.insertMember( member);
        result.put("msg", "ok");
        return result;
    }


    @Value("${kakao.client_id}")
    private String client_id;

    @Value("${kakao.redirect_uri}")
    private String redirect_uri;

    @RequestMapping("/kakaostart")
    public @ResponseBody String kakaostart() {
        String a = "<script type='text/javascript'>"
                + "location.href='https://kauth.kakao.com/oauth/authorize?"
                + "client_id=" + client_id + "&"
                + "redirect_uri=" + redirect_uri + "&"
                + "response_type=code';" + "</script>";
        return a;
    }

    @RequestMapping("/kakaoLogin")
    public void kakaoLogin(HttpServletRequest request, HttpServletResponse response ) throws IOException {

        String code = request.getParameter("code");
        String endpoint = "https://kauth.kakao.com/oauth/token";
        URL url = new URL(endpoint);
        String bodyData = "grant_type=authorization_code&";
        bodyData += "client_id=" + client_id + "&";
        bodyData += "redirect_uri=" + redirect_uri + "&";
        bodyData += "code=" + code;

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=utf-8");
        conn.setDoOutput(true);
        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream(), "UTF-8"));
        bw.write(bodyData);
        bw.flush();
        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
        String input = "";
        StringBuilder sb = new StringBuilder();
        while ((input = br.readLine()) != null) {
            sb.append(input);
        }
        Gson gson = new Gson();
        OAuthToken oAuthToken = gson.fromJson(sb.toString(), OAuthToken.class);
        String endpoint2 = "https://kapi.kakao.com/v2/user/me";
        URL url2 = new URL(endpoint2);

        HttpsURLConnection conn2 = (HttpsURLConnection) url2.openConnection();
        conn2.setRequestProperty("Authorization", "Bearer " + oAuthToken.getAccess_token());
        conn2.setDoOutput(true);
        BufferedReader br2 = new BufferedReader(new InputStreamReader(conn2.getInputStream(), "UTF-8"));
        String input2 = "";
        StringBuilder sb2 = new StringBuilder();
        while ((input2 = br2.readLine()) != null) {
            sb2.append(input2);
            System.out.println(input2);
        }
        Gson gson2 = new Gson();
        KakaoProfile kakaoProfile = gson2.fromJson(sb2.toString(), KakaoProfile.class);
        KakaoProfile.KakaoAccount ac = kakaoProfile.getAccount();
        KakaoProfile.KakaoAccount.Profile pf = ac.getProfile();
        System.out.println("id : " + kakaoProfile.getId());
        System.out.println("KakaoAccount-Email : " + ac.getEmail());
        System.out.println("Profile-Nickname : " + pf.getNickname());

        Member member = ms.getMemberBySnsid( kakaoProfile.getId() );
        if( member == null) {
            member = new Member();
            member.setEmail( kakaoProfile.getId() );
            // 기존회원의 닉네임과 신규 카카오 회원의 닉네임이 중보되는 경우의 처리가 필요합니다.
            member.setNickname( pf.getNickname() );
            member.setProvider( "kakao" );
            member.setPwd( "kakao" );
            member.setSnsid( kakaoProfile.getId() );
            ms.insertMember(member);
        }
        HttpSession session = request.getSession();
        session.setAttribute("loginUser", member.getId() );
        response.sendRedirect("http://localhost:3000/savekakaoinfo/" + member.getId() );
    }


    @PostMapping("/emailcheckUpdate")
    public HashMap<String, Object> emailcheckUpdate(
            @RequestParam("email") String email,
            @RequestParam("id") int id ) {
        HashMap<String, Object> result = new HashMap<>();

        Member member = ms.getMemberById(id);
        String loginUserEmail = member.getEmail();
        Member updateMember = ms.getMember(email);
        if( loginUserEmail.equals(email) || updateMember == null ) {
            result.put("msg", "ok");
        }else{
            result.put("msg", "no");
        }
        return result;
    }


    @PostMapping("/nicknamecheckUpdate")
    public HashMap<String, Object> nicknamecheckUpdate(
            @RequestParam("nickname") String nickname,
            @RequestParam("id") int id) {
        HashMap<String, Object> result = new HashMap<>();

        Member member = ms.getMemberById(id);  // id로 멤버정보 조회
        String loginUserNickname = member.getNickname();  // 조회된 정보에서 닉네임 추출
        Member updateMember = ms.getMemberByNickname(nickname);   // 수정하려면 닉네임으로 멤버조회
        // 로그인유저의 닉네임과 수정하려는 닉네임 같거나
        // 다르다면 수정하려는 닉엠이 사용중이 아닐때  ok
        if( loginUserNickname.equals(nickname) || updateMember == null ) {
            result.put("msg", "ok");
        }else{
            result.put("msg", "no");
        }
        return result;
    }

    @PostMapping("/update")
    public HashMap<String, Object> update( @RequestBody Member member) {
        HashMap<String, Object> result = new HashMap<>();
        ms.updateMember( member );
        result.put("msg", "ok");
        return result;
    }


    @GetMapping("/getNickname/{memberid}")
    public HashMap<String, Object> getNickname( @PathVariable("memberid") int memberid ){
        HashMap<String, Object> result = new HashMap<>();
        Member member = ms.getMemberById(memberid);
        result.put("nickname", member.getNickname());
        return result;
    }


    @PostMapping("/follow")
    public HashMap<String, Object> follow( @RequestBody Follow follow) {
        HashMap<String, Object> result = new HashMap<>();
        ms.addFollow( follow );
        result.put("msg", "ok");
        return result;
    }



    @GetMapping("/getEmail")
    public HashMap<String, Object> getEmail(@RequestParam("userid") int userid) {
        HashMap<String, Object> result = new HashMap<>();
        Member member = ms.getMemberById(userid);
        result.put("email", member.getEmail());
        return result;
    }


    @GetMapping("/getMyPost")
    public HashMap<String, Object> getMyPost(@RequestParam("writer") int writer) {
        HashMap<String, Object> result = new HashMap<>();
        result.put("imgList", ms.getImgList( writer ));
        return result;
    }


    @GetMapping("/refresh")
    public HashMap<String, Object> refresh(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam("refreshToken") String refreshToken
    ) throws CustomJWTException {
        HashMap<String, Object> result = new HashMap<>();

        // refreshToken 이  null 인경우 NULL_REFRASH 라는 사용자 정의 으로 에외발생
        if( refreshToken == null ) throw new CustomJWTException("NULL_REFRASH");
        // accessToken이 null 이거나 7글자 미만이라면 INVALID_HEADER 라는 이름으로 사용자 정의 예외발생
        if( authHeader == null || authHeader.length() < 7 )
            throw new CustomJWTException("INVALID_HEADER");

        // header 에서  Authorization 항목의 7글자 이후 글자들(accessToken)를 추출
        String accessToken = authHeader.substring(7);

         if( checkExpierdToken( accessToken ) ){
             System.out.println("그데로 사용");
             // 현재의  accessToken  과 refreshToken 을 그데로 다시 리턴
             result.put("accessToken", accessToken);
             result.put("refreshToken", refreshToken);
         }else{
             System.out.println("토큰 교체");
             // accessToken 기간 만료시  refresh 토큰으로 재 검증하여 사용자 정보 추출
             Map<String, Object> claims = JWTUtil.validateToken(refreshToken);

             // access 토큰 교체
             String newAccessToken = JWTUtil.generateToken(claims, 1);
             String newRefreshToken = "";
             if(  checkTime( (Integer)claims.get("exp") )  )
                 newRefreshToken = JWTUtil.generateToken(claims, 60*24);
             else
                 newRefreshToken = refreshToken;

             result.put("accessToken", newAccessToken);
             result.put("refreshToken", newRefreshToken);
         }
        return result;
    }

    private boolean checkTime(Integer exp) {
        java.util.Date expDate = new java.util.Date( (long)exp * (1000 ));//밀리초로 변환
        long gap = expDate.getTime() - System.currentTimeMillis();//현재 시간과의 차이 계산
        long leftMin = gap / (1000 * 60); //분단위 변환
        //1시간도 안남았는지..
        return leftMin < 60;  // 한시간 미만으로 남았으면  true 그렇지 않으면 false 가 리턴
    }

    private boolean checkExpierdToken(String accessToken) {

        try {
            JWTUtil.validateToken(accessToken);
        } catch (CustomJWTException e) {
            if( e.getMessage().equals("Expired") ) return false;
        }
        return true;
    }

}
