package com.revature.services;

import com.revature.dtos.ProductInfo;
import com.revature.models.Product;
import com.revature.repositories.ProductRepository;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class ProductServiceImpl implements ProductService{

    private final ProductRepository productRepository;

    public ProductServiceImpl(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    public List<Product> findAll() {
        return productRepository.findAll();
    }

    public List<Product> findSaleItems(){ return findAll().stream().filter(Product::isSale).collect(Collectors.toList());}

    public Optional<Product> findById(int id) {
        return productRepository.findById(id);
    }

    public Product save(Product product) {
        return productRepository.save(product);
    }
    
    public List<Product> saveAll(List<Product> productList, List<ProductInfo> metadata) {
    	return productRepository.saveAll(productList);
    }

    public List<Product> searchProduct(String searchParam){
        String regex = "(.*)+" + searchParam.toLowerCase() + "(.*)+";

        List<Product> products = productRepository.findAll();
        List<Product> result = new ArrayList<>();
        for (Product p : products) {
            if (p.getName().matches(regex) || p.getDescription().matches(regex)) {
                result.add(p);
            }
        }

        return result;
    }

    public void delete(int id) {
        productRepository.deleteById(id);
    }
}
