package com.himedia.spserver.dao;

import com.himedia.spserver.entity.Postwithnickname;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PostWithNickRepository  extends JpaRepository<Postwithnickname, Integer> {

}
