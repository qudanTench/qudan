package com.zhangheng.springboot.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by 蜡笔小新不爱吃青椒 on 2018/11/13.
 */
public class JwtUtil {

    private final static Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    private static final String APP_KEY = "qudan_key"; //进行数字签名的私钥，一定要保管好

//    /**
//     *
//     * @param username
//     * @param userId
//     * @param audience
//     * @param issuer
//     * @param TTLMillis
//     * @param base64Security
//     * @return
//     */
//    public static String createJWT(String username, Integer userId,
//                                   String audience, String issuer, long TTLMillis, String base64Security){
//        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
//
//        long nowMillis = System.currentTimeMillis();
//        Date now = new Date(nowMillis);
//
//        //生成签名密钥
//        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(base64Security);
//        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
//
//        //添加构成JWT的参数
//        JwtBuilder builder = Jwts.builder().setHeaderParam("typ", "JWT")
//                .claim("unique_name", username)
//                .claim("userid", userId)
//                .setIssuer(issuer)
//                .setAudience(audience)
//                .signWith(signatureAlgorithm, signingKey);
//        //添加Token过期时间
//        if (TTLMillis >= 0) {
//            long expMillis = nowMillis + TTLMillis;
//            Date exp = new Date(expMillis);
//            builder.setExpiration(exp).setNotBefore(now);
//        }
//
//        //生成JWT
//        return builder.compact();
//    }
//
//    /**
//     * 解析jwt
//     */
//    public static Claims parseJWT(String jsonWebToken, String base64Security){
//        try{
//            Claims claims = Jwts.parser()
//                    .setSigningKey(DatatypeConverter.parseBase64Binary(base64Security))
//                    .parseClaimsJws(jsonWebToken).getBody();
//            return claims;
//        }catch (Exception e){
//            logger.error(e.getMessage());
//            return null;
//        }
//    }

    /**
     * 一个JWT实际上就是一个字符串，它由三部分组成，头部(Header)、载荷(Payload)与签名(Signature)
     * @param id 当前用户ID
     * @param issuer 该JWT的签发者，是否使用是可选的
     * @param subject 该JWT所面向的用户，是否使用是可选的
     * @param ttlMillis 什么时候过期，这里是一个Unix时间戳，是否使用是可选的
     * @param audience 接收该JWT的一方，是否使用是可选的
     * @return
     */
    public static String createJWT(String id,String issuer,String subject,long ttlMillis, String audience){


        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(APP_KEY);

        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

        JwtBuilder jwtBuilder = Jwts.builder()
                .setId(id)
                .setSubject(subject)
                .setIssuedAt(now)
                .setIssuer(issuer)
                .setAudience(audience)
                .signWith(signatureAlgorithm,signingKey);
        //设置Token的过期时间
        if(ttlMillis >=0){
            long expMillis = nowMillis + ttlMillis;
            Date exp = new Date(expMillis);
            jwtBuilder.setExpiration(exp);
        }

        return jwtBuilder.compact();

    }

    //私钥解密token信息
    public static Claims getClaims(String jwt) {

        try{
            return Jwts.parser()
                    .setSigningKey(DatatypeConverter.parseBase64Binary(APP_KEY))
                    .parseClaimsJws(jwt).getBody();
        }catch (Exception e){
            logger.error(e.getMessage());
            return null;
        }
    }
}
