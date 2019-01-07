package com.chengxi;

import com.chengxi.jwt.JWTUtil;
import com.chengxi.ras.RsaUtils;
import io.jsonwebtoken.Claims;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.PrivateKey;
import java.security.PublicKey;

@RunWith(SpringRunner.class)
@SpringBootTest
public class ZuulTestApplicationTests {

    @Value("${sc.jwt.secret}")
    private String secret;

    @Value("${sc.jwt.pubKeyPath}")
    private String pubKeyPath;

    @Value("${sc.jwt.priKeyPath}")
    private String priKeyPath;

    @Value("${sc.jwt.expire}")
    private Integer expire;

    private PublicKey publicKey;

    private PrivateKey privateKey;

    @Test
    public void contextLoads() throws Exception {
        System.out.println(secret);
        System.out.println(pubKeyPath);
        System.out.println(priKeyPath);
        System.out.println(expire);


        // 第一步：创建公私秘钥,根据路径存放
        RsaUtils.generateKey(pubKeyPath,priKeyPath,secret);

        // 第二步：取出公私秘钥
        publicKey = RsaUtils.getPublicKey(pubKeyPath);
        privateKey = RsaUtils.getPrivateKey(priKeyPath);

        // 第三步：根据公钥加密生成token
        String token = JWTUtil.createToken(1, "小熙", publicKey+"", expire);
        System.out.println("加密后的token："+token);

        // 第四步：根据私钥解析token
        Claims parseToken = JWTUtil.parseToken(token, privateKey + "");
        System.out.println("解析后的token："+parseToken);
    }

}
