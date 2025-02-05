package com.himedia.spserver.service;

import com.himedia.spserver.dao.*;
import com.himedia.spserver.dto.Paging;
import com.himedia.spserver.dto.PostDto;
import com.himedia.spserver.entity.*;
import com.himedia.spserver.service.dao.PostDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@Transactional
public class PostService {

    @Autowired
    PostRepository pr;
    @Autowired
    HashtagRepository hr;
    @Autowired
    PosthashRepository phr;
    @Autowired
    MemberRepository mr;

    public Post insertPost(Post post) {
        // 포스트 추가
        Optional<Member> member = mr.findById( post.getWriter() );
        if (member.isPresent()) post.setMember( member.get() );
        Post p = pr.save(post);  // 레코드추가 + 방금추가된 레코드를 새로운 엔티티객에 저장
        int postid= p.getId();  // 방금 추가된 레코드의  id 저장

        //  추가된 포스트의 content 추출
        String content = p.getContent();

        // content 에서 해시태그들만 추출
        Matcher m = Pattern.compile("#([0-9a-zA-Z가-힣]*)").matcher(content);
        List<String> tags = new ArrayList<String>();
        while (m.find()) {
            //System.out.println(m.group(1));
            tags.add(m.group(1));
        }

        // 추출된 해시테그들로 해시테그 작업
        int tagid = 0;
        for( String tag : tags ) {
            // tag 변수로 Hasgtag테이블 검색
            Optional<Hashtag> record = hr.findByWord(tag);
            // 있으면 아이디만 추출
            if( record.isPresent() ) tagid = record.get().getId();
             // 현재 워드가 없으면  hashtag 테이블에 새레코드 추가하고 아이디 추출
            else{
                Hashtag htnew = new Hashtag();
                htnew.setWord(tag);
                Hashtag htsave = hr.save(htnew);
                tagid = htsave.getId();
            }
            // 추출된 포스트 아이디와 테그 아이디로 posthash 테이블에 레코드 추가
            PostHash ph = new PostHash();
            ph.setPostid( postid );
            ph.setHashid( tagid );
            phr.save(ph);
        }
        // 추가된 post 리턴
        return p;
    }

    @Autowired
    ImagesRepository ir;

    public void insertImage(Images images) {
        ir.save(images);
    }


    public List<Post> getPostList(String word) {
        List<Post> list=null;
        if( word==null || word.equals("") ) {
            System.out.println("service : getPostList");
            list = pr.findAll(Sort.by(Sort.Direction.DESC, "id"));
        }else{
            // word로 hashtag 테이블 검색
            // select id from hashtag where word=?

            // 검색결과에 있는 tagid 들로  posthash테이블에서 postid 들을 검색
            // select postid from posthash where hashid=?

            // postid 들로 post 테이블에서  post 들을 검색
            // select * from post where id=?

            Optional<Hashtag> record = hr.findByWord(word);  // word 를 hasgtag 테이블에서 검색
            if( !record.isPresent() ) {
                list = pr.findAll(Sort.by(Sort.Direction.DESC, "id"));  // 검색 결과가 없으면 모두 검색
            }else{
                // hashtag 테이블의 id : record.get().getId()
                List<PostHash> phList = phr.findByHashid(  record.get().getId() );   // hashid로 PostHash 테이블 검색

                List<Integer> poistidList = new ArrayList<>();
                for( PostHash ph : phList ) {    // PostHash 들에서 postid 만 추출해서 List(poistidList) 로 재구성
                    poistidList.add( ph.getPostid() );
                }

                list = pr.findByIdIn( poistidList );  // poistidList 로 Post 테이블 검색
            }
        }
        return list;
    }

    public List<Images> getImagesList(int postid) {
        List<Images> list = ir.findByPostid( postid );
        return list;
    }

    @Autowired
    LikesRepository lr;

    public List<Likes> getLikeList(int postid) {
        List<Likes> list = lr.findByPostid( postid );
        // [ { id:1, postid:3, likeid:5} , {  id:2, postid:4, likeid:6} , {} ... ]  좋아요 테이블의 레코드 객체 리스트
        // [ 5, 4 , 6, ...]  멤버의 아이디들 리스트
        return list;
    }

    public void insertLikes(Likes likes) {
        Optional<Likes> recored = lr.findByPostidAndLikeid( likes.getPostid(), likes.getLikeid());
        if( recored.isPresent() ) {
            lr.delete( recored.get() );
        }else{
            Likes addlikes = new Likes();
            addlikes.setPostid( likes.getPostid());
            addlikes.setLikeid( likes.getLikeid() );
            lr.save( addlikes );
        }
    }

    @Autowired
    ReplyRspository rr;

    public void addReply(Reply reply) {
        Optional<Member> member = mr.findById( reply.getWriter() );
        if( member.isPresent() ) reply.setMember( member.get() );
        rr.save(reply);
    }

    @Autowired
    ReplyWithNickRepository rwnr;



    public void deleteReply(int replyid) {
        Optional<Reply> rep = rr.findById(replyid);
        if( rep.isPresent() ) {
            rr.delete( rep.get() );
        }
    }

    @Autowired
    PostWithNickRepository pwnr;

    public List<Replywithnick> getReplyList(int postid) {
        //return rr.findByPostidOrderByIdDesc(postid);
        // return rr.getReplyList( postid );
        return rwnr.findByPostidOrderByIdDesc( postid );
    }
    public Object getPostListWithNick() {
        return pwnr.findAll();
    }

    @Autowired
    PostDao pdao;

    public List<Post> getPostListPage(Pageable pageable) {
        //PageRequest pageRequest = PageRequest.of(paging.getStartNum(), paging.getDisplayRow() );
        //Page<Post> list = null;
        List<Post> list =  pr.findAll( );
        return list;
    }

    public List<Post> getPostList2( String word , Paging paging ) {
        List<Post> list = null;
        if( word == null || word.equals("") ) {
            // 검색어가 비어있으면 모두 검색
            list = pdao.getPostListByPaging( paging.getStartNum(), paging.getDisplayRow() );
        }else{
            Optional<Hashtag> hashtag = hr.findByWord(word);  // word 를 hasgtag 테이블에서 검색
            if( !hashtag.isPresent() ) {
                // 검색하려는 단어가 한번도 등록된적이 없으면 모두검색
                list = pr.findAll(Sort.by(Sort.Direction.DESC, "id"));  // 검색 결과가 없으면 모두 검색
            }else{
                // 검색하려는 단어가 hashag 테이블에 있는 단어라면
                // List<PostHash> phList = phr.findByHashid(  record.get().getId() );
                list = pdao.getPostListByTagByPage( hashtag.get().getId(), paging.getStartNum(), paging.getDisplayRow()  );
            }
        }
        return list;
    }

    public List<Reply> getReplyList2(int postid) {
        return rr.findByPostidOrderByIdDesc( postid );
    }


}


// Distincgt : findDistinctByName("scott");  -  이름이  scott 인 레코드를 검색하되 동일인은 하나만 결과로 얻습니다
// And : findByNameAndGender("scott", "F") -  이름이  scott 이면서  성별이 F인 레코드 검색 - 동시 만족
// Or : findByNameOrGender("scott", "F") - 이름이  scott 이거나  성별이 F인 레코드 검색 - 둘중 하나이상 만족
//  findByName("scott") - 이름이  scott 인 레코드 검색
//  findByNameIs("scott"), findByNameEquals("scott")  -  findByName("scott")와  같은 표션

// LessThan : findByAgeLessThan(10)   age가 10보다 작은(<)
// LessThanEqual : findByAgeLessThanEqual(10)   age가 10보다 작거나 같은 (<=)
// GreaterThan  : findByAgeGreaterThan(10)   나이가 10보다 큰(>)
// GreaterThanEqual : findByAgeGreaterThanEqual(10)  나이가 10보다 크거나 같은(>=)

// Between	: findByStartDateBetween( 1, 10)  StartDate가  1과 10의 사이 값들 검색
// 같은 표현 : findByStartDateLessThanEqualAndGreaterThanEqual(1,10)

// After : findByStartDateAfter(날짜)    날짜 이후
// Before : findByStartDateBefore(날짜)   날짜 이전

// Like : findByNameLike("scott")  이름에 "scott:을 포함하는
// StartingWith	: findByNameStartingWith("scott")    이름이 "scott"으로 시작하는
// StartingWith	: findByNameEndingWith("scott")    이름이 "scott"으로 끝나는
// Containing : findByNameContaining("scott")  이름에 "scott"을 포함하는 (Like 와 유사)
// 평소에 사용하던  where name like '%철수%' 는 Containing 을 사용합니다
// Like 를 사용하면   where name like '철수' 와 같이 동작하므로 결과가 없을수도 잇습니다


// OrderBy : findByAgeOrderByIdDesc()  -  id 필드기준으로 내림차순 정렬
// In :	findByAgeIn(Collection<Age> ages)  - In함수 사용 age 필드가  Collection<Age> ages 안에 포함된 값대상으로 검색
// true : findByActiveTrue()    active 필드값이  true
// False : findByActiveFalse()    active 필드값이  false
// IgnoreCase	findByNameIgnoreCase("scott")  이름에서 "scott'을 검색하되 대소문자 구분하지 않음


















