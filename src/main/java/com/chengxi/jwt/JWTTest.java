package com.chengxi.jwt;

import io.jsonwebtoken.Claims;

/**
 * @author chengxi
 * @date 2018/12/10 20:22
 */
public class JWTTest {

    public static void main(String[] args) {
        // 目前加密的盐只能使用英文
        String token = JWTUtil.createToken(1, "小熙","admin", 100);

        System.out.println("加密之后的值："+token);

        Claims parseToken = JWTUtil.parseToken(token,"admin");

        System.out.println("解密后的值："+parseToken);
    }

}
