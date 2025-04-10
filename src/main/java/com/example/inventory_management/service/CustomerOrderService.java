package com.example.inventory_management.service;

import com.example.inventory_management.model.Batch;
import com.example.inventory_management.model.CustomerOrder;
import com.example.inventory_management.model.OrderProduct;
import com.example.inventory_management.model.Product;
import com.example.inventory_management.repository.CustomerOrderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class CustomerOrderService {

    @Autowired
    private CustomerOrderRepository customerOrderRepository;

    @Autowired
    private BatchService batchService;

    @Autowired
    private ProductService productService;

    @Autowired
    private InventoryService inventoryService;

    // Create a new order
    public CustomerOrder placeOrder(CustomerOrder order) {
        order.setTimestamp(LocalDateTime.now());
        order.setStatus("Pending");  
        double profit=0;
        List<Batch> batches;
        Map<String, Integer> mapBatches = new HashMap<String, Integer>();
        Map<OrderProduct, Integer> mapProducts = new HashMap<OrderProduct, Integer>();
        for(OrderProduct it : order.getProducts()) {
            int count = it.getQuantity();
            batches = batchService.findByProductId(it.getProductId());
            batches.sort(Comparator.comparing(Batch::getCreated));
            for(Batch batch : batches) {
                if(count >= batch.getQuantity()) {
                    mapBatches.put(batch.getBatchId(), batch.getQuantity());
                }
                else {
                    mapBatches.put(batch.getBatchId(), count);
                }
            }
            if(count > 0) {
                return null;
            }
            mapProducts.put(it, count);
        }
        for (Map.Entry<String, Integer> entry : mapBatches.entrySet()) {
            profit = batchService.getBatchById(entry.getKey()).get().getPrice() - batchService.getBatchById(entry.getKey()).get().getCost();
        }
        order.setProfitOnProducts(profit);
        inventoryService.updateInventory(mapBatches, mapProducts);
        return customerOrderRepository.save(order);
    }

    public CustomerOrder updateOrderStatus(String orderId, String status) {
        Optional<CustomerOrder> optionalOrder = customerOrderRepository.findById(orderId);
        if (optionalOrder.isPresent()) {
            CustomerOrder order = optionalOrder.get();
            order.setStatus(status);
            if(status.equals("Cancelled")) {
                for(OrderProduct it : order.getProducts()) {
                    Optional<Batch> batch = batchService.getBatchByCriteria(it.getProductId(), it.getCostAtOrder(), it.getPriceAtOrder(), it.getSupplierId());
                    if(batch.isPresent()) {
                        Batch batch1=batch.get();
                        batch1.setQuantity(batch.get().getQuantity()+it.getQuantity());
                        batchService.saveBatch(batch1);
                    }
                    else {
                        Batch newBatch = new Batch();
                        newBatch.setCost(it.getCostAtOrder());
                        newBatch.setPrice(it.getPriceAtOrder());
                        newBatch.setProductId(it.getProductId());
                        newBatch.setSupplierId(it.getSupplierId());
                        newBatch.setQuantity(it.getQuantity());
                        newBatch.setCreated(LocalDateTime.now());
                        batchService.saveBatch(newBatch);
                        Optional<Product> product = productService.getProductById(it.getProductId());
                        if(product.isPresent()) {
                            product.get().getBatches().add(newBatch);
                        }
                        else {
                            return null;
                        }
                    }
                }
            }
            return customerOrderRepository.save(order);
        }
        return null;
    }

    // Get all orders
    public List<CustomerOrder> getAllOrders() {
        return customerOrderRepository.findAll();
    }

    // Get order by ID
    public Optional<CustomerOrder> getOrderById(String orderId) {
        return customerOrderRepository.findById(orderId);
    }

    // Get orders by customer ID
    public List<CustomerOrder> getOrdersByCustomerId(String customerId) {
        return customerOrderRepository.findByCustomerId(customerId);
    }

    // Delete order
    public void deleteOrder(String orderId) {
        customerOrderRepository.deleteById(orderId);
    }

    public List<CustomerOrder> findAllByMonthAndYearAndRole(String role, int month, int year) {
        List<CustomerOrder> customerOrder = findAllByMonthAndYear(month, year);
        List<CustomerOrder> finalList = new ArrayList<>();
        for(CustomerOrder it : customerOrder) {
            if(it.getOrderedby().getName().equals(role)) {
                finalList.add(it);
            }
        }
        return finalList;
    }

    public List<CustomerOrder> findAllByMonthAndYear(int month, int year) {
        List<CustomerOrder> customerOrder = customerOrderRepository.findAll();
        List<CustomerOrder> finalList = new ArrayList<>();
        for(CustomerOrder it : customerOrder) {
            if(it.getTimestamp().getMonthValue() == month && it.getTimestamp().getYear() == year) {
                finalList.add(it);
            }
        }
        return finalList;
    }
}
