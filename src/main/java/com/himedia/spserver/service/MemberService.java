package com.himedia.spserver.service;

import com.himedia.spserver.dao.FollowRepository;
import com.himedia.spserver.dao.ImagesRepository;
import com.himedia.spserver.dao.MemberRepository;
import com.himedia.spserver.dao.PostRepository;
import com.himedia.spserver.entity.Follow;
import com.himedia.spserver.entity.Images;
import com.himedia.spserver.entity.Member;
import com.himedia.spserver.entity.Post;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@Transactional
public class MemberService {

    @Autowired
    MemberRepository mr;

    BCryptPasswordEncoder pe = new BCryptPasswordEncoder();

    public Member getMember(String email) {
        //System.out.println(email );
        //Member member = mdao.findByEmail(email);
        // return member;

        Optional<Member>  member = mr.findByEmail(email);
        if(member.isPresent()) {
            return member.get();
        }else{
            return null;
        }

    }

    public Member getMemberById(int id) {
        // Member member = mr.findById(id);
        // 자바 JSP 그리고 데이터 베이스 관련 등에서는 특히나 연산이난 검색의 결과가  NULL 인 상태를 걱정하고 지양합니다.
        // 검색이나 연산의 결과가  noll  일때와 아닐때에 따른 후속 연산이 분명히 구분되어야 할때 이 옵션을 사용합니다
        Optional<Member> member = mr.findById(id);
        //  isPresent() : 해당 객체가 인스턴스를 저장하고 있다면 true , null 이면  flase 를 리턴
        // isEmpty() : isPresent()의 반대값을 리턴합니다
        if(member.isPresent()) {
            return member.get();  // .get()  : 저장된 검색 결과를 추출하는 메서드
        }else{
            return null;
        }
    }

    public Member getMemberByNickname(String nickname) {
        Optional<Member> member = mr.findByNickname( nickname );
        if(member.isPresent()) return member.get();
        else  return null;
    }



    public void insertMember(Member member) {
        member.setPwd(pe.encode(member.getPwd()));
        mr.save(member);
    }

    public Member getMemberBySnsid(String id) {
        Optional<Member> member = mr.findBySnsid( id );
        if(member.isPresent()) return member.get();
        else  return null;
    }

    public void updateMember(Member member) {
        Optional<Member> memberOptional = mr.findById(member.getId());
        if(memberOptional.isPresent()) {
            Member updateMember = memberOptional.get();
            updateMember.setNickname(member.getNickname());
            updateMember.setEmail(member.getEmail());
            updateMember.setPwd( pe.encode( member.getPwd() ) );
            updateMember.setPhone(member.getPhone());
            updateMember.setProfileimg(member.getProfileimg());
            updateMember.setProfilemsg(member.getProfilemsg());
        }
    }

    @Autowired
    FollowRepository fr;

    public List<Follow> getFollowers(int id) {
        List<Follow> list = fr.findByFto(id);
        return list;
    }

    public List<Follow> getFollowings(int id) {
        List<Follow> list = fr.findByFfrom(id);
        return list;
    }

    public void addFollow(Follow follow) {
        Optional<Follow> followOptional = fr.findByFfromAndFto(follow.getFfrom(), follow.getFto());
        if(!followOptional.isPresent()) {
            fr.save(follow);
        }
    }

    @Autowired
    PostRepository pr;

    @Autowired
    ImagesRepository im;

    public List<String> getImgList(int writer) {
        List<String> finalList = new ArrayList<>();
        List<Post> plist = pr.findByWriter(writer);
        for( Post p : plist) {
            List<Images> ilist = im.findByPostid(p.getId());
            finalList.add( ilist.get(0).getSavefilename() );
        }
        return finalList;
    }
}
