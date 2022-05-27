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

    /**
     * Filters the list of product names and descriptions based on whether the searchParam is contained or the total list
     * if an empty string is supplied.
     * @param searchParam The search keyword or the empty string.
     * @return The filtered list containing products whose names or descriptions contain the search keyword if not the
     * empty string. The full list of products, otherwise.
     */
    public List<Product> searchProduct(String searchParam){
        if (searchParam == null || searchParam.equals("")) {
            return productRepository.findAll();
        }
        String regex = "(.*)+" + searchParam.toLowerCase() + "(.*)+";

        List<Product> products = productRepository.findAll();
        List<Product> result = new ArrayList<>();
        for (Product p : products) {
            if (p.getName().toLowerCase().matches(regex) || p.getDescription().toLowerCase().matches(regex)) {
                result.add(p);
            }
        }

        return result;
    }

    public void delete(int id) {
        productRepository.deleteById(id);
    }

}
