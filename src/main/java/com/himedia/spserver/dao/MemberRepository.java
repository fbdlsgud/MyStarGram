package com.himedia.spserver.dao;

import com.himedia.spserver.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository  extends JpaRepository<Member, Integer> {
    //기본키로 검색하는 findBy~ 에 한해서 이곳에 기술하지 않아도 됩니다.  물론 써도 됩니다.
    Optional<Member> findByEmail(String email);
    Optional<Member> findByNickname(String nickname);
    Optional<Member> findBySnsid(String id);
}
