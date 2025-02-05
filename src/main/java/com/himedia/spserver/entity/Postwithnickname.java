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
public class Postwithnickname {
    @Id
    private int id;
    private String content;
    private int writer;
    private Timestamp writedate;
    private String nickname;
}
