package com.chengxi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
//@EnableZuulProxy简单理解为@EnableZuulServer的增强版，当Zuul与Eureka、Ribbon等组件配合使用时，我们使用@EnableZuulProxy。
@SpringBootApplication
@EnableZuulProxy            // 开启zuul的网关功能，他是一个组合注解，集成了eureka客户端注解。
//@EnableDiscoveryClient      // 开启eureka客户端的消费者
public class ZuulTestApplication {

    public static void main(String[] args) {
        SpringApplication.run(ZuulTestApplication.class, args);
    }
}
