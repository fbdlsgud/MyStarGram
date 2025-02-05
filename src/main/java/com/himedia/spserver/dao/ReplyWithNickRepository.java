package com.himedia.spserver.dao;

import com.himedia.spserver.entity.Replywithnick;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ReplyWithNickRepository extends JpaRepository<Replywithnick, Integer> {

    List<Replywithnick> findByPostidOrderByIdDesc(int postid);
}
