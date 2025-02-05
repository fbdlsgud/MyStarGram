package com.himedia.spserver.dao;

import com.himedia.spserver.entity.Likes;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface LikesRepository  extends JpaRepository<Likes, Integer> {

    List<Likes> findByPostid(int postid);

    Optional<Likes> findByPostidAndLikeid(int postid, int likeid);
}
