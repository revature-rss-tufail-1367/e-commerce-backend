package com.revature.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private int quantity;
    private double price;
    @Column(name = "sale_rate")
    private double saleRate;
    private String description;
    private String image;
    private String name;
    @Column(name = "is_sale")
    private boolean isSale;
}
