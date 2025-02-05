package com.himedia.spserver.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.*;
import java.util.stream.Collectors;

public class MemberDTO extends User {
    public MemberDTO(String username, String password, int id, String nickname, String phone, String provider, String snsid , String profileimg, String profilemsg, List<String> authorities) {
        super(username, password,
                authorities.stream()
                .map( str -> new SimpleGrantedAuthority("ROLE_"+str) )
                .collect(Collectors.toList()));
        this.id = id;                                   this.email= username;
        this.pwd = password;                    this.nickname = nickname;
        this.phone = phone;                      this.provider = provider;
        this.snsid = snsid;                         this.profileimg = profileimg;
        this.profilemsg = profilemsg;          this.roleNames = authorities;
    }
    private int id;                                     private String email;
    private String pwd;                             private String nickname;
    private String phone;                          private String provider;
    private String snsid;                           private String profileimg;
    private String profilemsg;                   private List<String> roleNames = new ArrayList<String>();


    public Map<String, Object> getClaims() {
        Map<String, Object> dataMap = new HashMap<>();
        dataMap.put("id", id);
        dataMap.put("email", email);
        dataMap.put("pwd",pwd);
        dataMap.put("nickname", nickname);
        dataMap.put("phone", phone);
        dataMap.put("provider", provider);
        dataMap.put("snsid", snsid);
        dataMap.put("profileimg", profileimg);
        dataMap.put("profilemsg", profilemsg);
        dataMap.put("roleNames", roleNames);
        return dataMap;
    }
}
