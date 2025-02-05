package com.himedia.spserver.dao;

import com.himedia.spserver.entity.Reply;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ReplyRspository extends JpaRepository<Reply, Integer> {

    List<Reply> findByPostidOrderByIdDesc(int postid);

    @Query(value="select r.*, m.nickname from Reply r, Member m  where r.postid=:postid and r.writer=m.id order by r.id desc", nativeQuery=true)
    List<Reply> getReplyList(@Param("postid") int postid);
}
