package com.himedia.spserver.service.dao;

import com.himedia.spserver.entity.Post;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class PostDao {

    @Autowired
    EntityManager em;


    public List<Post> getPostListByPaging(int startNum, int displayRow) {
        String spql = "select p from Post p order by p.id desc";
        Query query = em.createQuery(spql);
        query.setFirstResult(startNum);
        query.setMaxResults(displayRow);
        return query.getResultList();
    }



    public List<Post> getPostListByTagByPage(int hashid, int startNum, int displayRow) {
        String spql = "select p from Post p where p.id in(select ph.postid from PostHash ph where ph.hashid=:hashid)";
        Query query = em.createQuery(spql);
        query.setParameter("hashid", hashid);
        query.setFirstResult(startNum);
        query.setMaxResults(displayRow);
        return query.getResultList();
    }
}
