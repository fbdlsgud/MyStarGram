package com.himedia.spserver.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jdk.jfr.Enabled;
import lombok.Data;

@Entity
@Data
public class Follow {

    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    private int id;
    private int ffrom;
    private int fto;
}
