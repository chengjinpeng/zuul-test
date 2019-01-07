package com.chengxi.jwt;

import com.chengxi.ras.RsaUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.joda.time.DateTime;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 *   用于生成和解析token，公私秘钥请查看RsaUtils工具类，本类中方法可能不全，可以举一反三的修改
 *
 *
 * @author: XinQi.Yuan
 *      修改: chengxi
 * @create: 2018-05-26 15:43
 **/
public class JwtUtils {
    /**
     * 私钥加密token
     *
     * @param userId、userName      载荷中的数据
     * @param privateKey    私钥
     * @param expireMinutes 过期时间，单位秒
     * @return
     * @throws Exception
     */
    public static String generateToken(Integer userId, String userName, PrivateKey privateKey, int expireMinutes) throws Exception {
        return Jwts.builder()
                .claim("userId", userId)
                .claim("userName", userName)
                .setExpiration(DateTime.now().plusMinutes(expireMinutes).toDate())
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }

    /**
     * 私钥加密token
     *
     * @param userId、userName      载荷中的数据
     * @param privateKey    私钥字节数组
     * @param expireMinutes 过期时间，单位秒
     * @return
     * @throws Exception
     */
    public static String generateToken(Integer userId, String userName, byte[] privateKey, int expireMinutes) throws Exception {
        return Jwts.builder()
                .claim("userId", userId)
                .claim("userName", userName)
                .setExpiration(DateTime.now().plusMinutes(expireMinutes).toDate())
                .signWith(SignatureAlgorithm.RS256, RsaUtils.getPrivateKey(privateKey))
                .compact();
    }

    /**
     * 公钥解析token
     *
     * @param token     用户请求中的token
     * @param publicKey 公钥
     * @return
     * @throws Exception
     */
    private static Jws<Claims> parserToken(String token, PublicKey publicKey) {
        return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token);
    }

    /**
     * 公钥解析token
     *
     * @param token     用户请求中的token
     * @param publicKey 公钥字节数组
     * @return
     * @throws Exception
     */
    private static Jws<Claims> parserToken(String token, byte[] publicKey) throws Exception {
        return Jwts.parser().setSigningKey(RsaUtils.getPublicKey(publicKey))
                .parseClaimsJws(token);
    }

    /**
     * 获取token中的用户信息
     *
     * @param token     用户请求中的令牌
     * @param publicKey 公钥
     * @return 用户信息
     * @throws Exception
     */
    public static String getInfoFromToken(String token, PublicKey publicKey) throws Exception {
        Jws<Claims> claimsJws = parserToken(token, publicKey);
        Claims body = claimsJws.getBody();
        return body+"";
    }

    /**
     * 获取token中的用户信息
     *
     * @param token     用户请求中的令牌
     * @param publicKey 公钥
     * @return 用户信息
     * @throws Exception
     */
    public static String getInfoFromToken(String token, byte[] publicKey) throws Exception {
        Jws<Claims> claimsJws = parserToken(token, publicKey);
        Claims body = claimsJws.getBody();
        return body+"";
    }


}


//需要导入的坐标
//<properties>
//<jjwt.version>0.7.0</jjwt.version>
//<joda-time.version>2.9.6</joda-time.version>
//</properties>
//
//<dependencies>
//<dependency>
//<groupId>io.jsonwebtoken</groupId>
//<artifactId>jjwt</artifactId>
//<version>${jjwt.version}</version>
//</dependency>
//<!-- https://mvnrepository.com/artifact/joda-time/joda-time -->
//<dependency>
//<groupId>joda-time</groupId>
//<artifactId>joda-time</artifactId>
//<version>${joda-time.version}</version>
//</dependency>
//</dependencies>