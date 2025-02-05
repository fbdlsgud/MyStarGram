//package com.himedia.spserver;
//
//import com.himedia.spserver.dao.PostRepository;
//import com.himedia.spserver.dto.PostDto;
//import com.himedia.spserver.entity.Post;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//
//import java.util.List;
//
//@SpringBootTest
//class SpServerApplicationTests {
//
//    @Autowired
//    PostRepository pr;
//    @Test
//    void contextLoads() {
//        //BCryptPasswordEncoder pe = new BCryptPasswordEncoder();
//        //System.out.println(pe.encode("kakao"));
//        List<Post> list = pr.findAll();
//        System.out.println(list.get(1));
//    }
//
//}
