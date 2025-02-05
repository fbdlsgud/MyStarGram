package com.himedia.spserver.dao;

import com.himedia.spserver.entity.PostHash;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PosthashRepository extends JpaRepository<PostHash, Integer> {

    List<PostHash> findByHashid(int id);
}
