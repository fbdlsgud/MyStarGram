package com.himedia.spserver.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.sql.Timestamp;

@Entity
@Getter
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class Replywithnick {
    @Id
    private int id;
    private int postid;
    private int writer;
    private String content;
    private Timestamp writedate;
    private String nickname;
}
