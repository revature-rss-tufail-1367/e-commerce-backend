package com.revature;

import com.revature.models.Product;
import com.revature.services.ProductService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

@SpringBootTest
public class SaleItemTests {

    @Autowired
    private ProductService productService;

    @Test
    void createUpdatedEntity(){
        Product product = productService.save(new Product(9,3,12.00,10,"hat's are nice","imageURL","hat",true));
        Assertions.assertNotNull(product);
    }

    @Test
    void filterEntities(){
        List<Product> sales = productService.findSaleItems();
        Assertions.assertNotEquals(productService.findAll().size(),sales.size());
    }

}
