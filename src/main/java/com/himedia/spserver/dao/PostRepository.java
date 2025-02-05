package com.himedia.spserver.dao;

import com.himedia.spserver.dto.PostDto;
import com.himedia.spserver.entity.Post;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface PostRepository extends JpaRepository<Post, Integer> {

    List<Post> findByIdIn(java.util.List<java.lang.Integer> poistidList);

    List<Post> findByWriter(int writer);


    @Query("select p from Post p where p.id in(select ph.postid from PostHash ph where ph.hashid=:hashid) ")
    List<Post> getPostListByTag(@Param("hashid") int hashid );


}
