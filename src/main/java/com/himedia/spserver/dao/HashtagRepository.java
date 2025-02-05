package com.himedia.spserver.dao;

import com.himedia.spserver.entity.Hashtag;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface HashtagRepository extends JpaRepository<Hashtag, Integer> {

    Optional<Hashtag> findByWord(String tag);
}
