package com.dailycodebuffer.Oauthresourceserver.controller;

import com.dailycodebuffer.Oauthresourceserver.dto.OrderDto;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@RestController
public class OrderController {

    @GetMapping("/order-status")
    @PreAuthorize("hasAuthority('SCOPE_openid')")
    public String orderStatus() {

        return "its working";
    }

    @GetMapping("/orders")
    @PreAuthorize("hasAnyRole('VIEW','ADMIN')")
    public List<OrderDto> getOrders() {
        return Arrays.asList(new OrderDto(UUID.randomUUID(),"Laptop"));
    }

    @PostMapping("/orders")
    @PreAuthorize("hasRole('ADMIN')")
    public UUID createOrder(@RequestBody String orderType) {
        return UUID.randomUUID(); //assuming that we have created the order and we got the UUID
    }
}
