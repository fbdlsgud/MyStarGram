package com.himedia.spserver.dao;

import com.himedia.spserver.entity.Images;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ImagesRepository extends JpaRepository<Images, Integer> {

    List<Images> findByPostid(int postid);

}
