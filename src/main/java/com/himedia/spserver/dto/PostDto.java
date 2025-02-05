package com.himedia.spserver.dto;

import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import java.sql.Timestamp;

@Data
public class PostDto {
    private int id;
    private String content;
    private int writer;
    private Timestamp writedate;
    private String nickname;
}
