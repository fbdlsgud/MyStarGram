package com.himedia.spserver.controller;

import com.himedia.spserver.dto.Paging;
import com.himedia.spserver.entity.Images;
import com.himedia.spserver.entity.Likes;
import com.himedia.spserver.entity.Post;
import com.himedia.spserver.entity.Reply;
import com.himedia.spserver.service.PostService;
import jakarta.servlet.ServletContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;

@RestController
@RequestMapping("/post")
public class PostController {

    @Autowired
    PostService ps;

    @Autowired
    ServletContext context;

    @PostMapping("/fileupload")
    public HashMap<String,Object> fileupload(@RequestParam("image") MultipartFile file) {
        HashMap<String,Object> result = new HashMap<>();

        String path = context.getRealPath("/images");
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


    @PostMapping("/writePost")
    public HashMap<String,Object> writePost(@RequestBody Post post) {
        HashMap<String,Object> result = new HashMap<>();
        Post p = ps.insertPost(post);  // 방금 추가된 레코드의 id 를위해 추가된 레코드를 리턴
        result.put("postid", p.getId() );
        return result;
    }

    @PostMapping("/writeimages")
    public HashMap<String,Object> writeImages(@RequestBody Images images) {
        HashMap<String,Object> result = new HashMap<>();
        ps.insertImage( images );
        result.put("msg", "ok");
        return result;
    }


    @PostMapping("/getPostList")
    public HashMap<String,Object> getPostList(  @RequestParam("word") String word, @RequestParam("page") int page ) {
        HashMap<String,Object> result = new HashMap<>();
        Paging paging = new Paging();
        paging.setPage( page );
        paging.calPaging();

        List<Post> list = ps.getPostList( word );
        System.out.println( list);
        result.put("postList", list);


        result.put("postList2", ps.getPostList2( word, paging ) );
        result.put("paging", paging);
        return result;
    }

    @GetMapping("/getImages/{postid}")
    public HashMap<String,Object> getImages(@PathVariable("postid") int postid) {
        HashMap<String,Object> result = new HashMap<>();
        result.put("imgList", ps.getImagesList( postid ) );
        return result;
    }


    @GetMapping("/getLikeList/{postid}")
    public HashMap<String,Object> getLikeList(@PathVariable("postid") int postid) {
        HashMap<String,Object> result = new HashMap<>();
        result.put("likeList", ps.getLikeList( postid ) );
        return result;
    }


    @PostMapping("/addlike")
    public HashMap<String,Object> addLike(@RequestBody Likes likes) {
        HashMap<String,Object> result = new HashMap<>();
        ps.insertLikes(likes);
        result.put("msg", "ok");
        return result;
    }


    @PostMapping("/addReply")
    public HashMap<String,Object> addReply(@RequestBody Reply reply) {
        HashMap<String,Object> result = new HashMap<>();
        ps.addReply(reply);
        result.put("msg", "ok");
        return result;
    }


    @GetMapping("/getReplyList/{postid}")
    public HashMap<String,Object> getReplyList(@PathVariable("postid") int postid) {
        HashMap<String,Object> result = new HashMap<>();
        result.put("replyList2", ps.getReplyList2( postid ) );
        result.put("replyList", ps.getReplyList( postid ) );
        return result;
    }

    @DeleteMapping("/deleteReply/{replyid}")
    public HashMap<String,Object> deleteReply(@PathVariable("replyid") int replyid) {
        HashMap<String,Object> result = new HashMap<>();
        ps.deleteReply( replyid );
        result.put("msg", "ok");
        return result;

    }
}
