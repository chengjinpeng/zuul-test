package com.chengxi.ras;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/***
 *   此类是利用RSA算法生成公私秘钥。（底层是欧拉函数）
 *   在非对称加密中利用私有秘钥进行加密，传输到另一端之后可以使用公有秘钥解密。反之亦然
 *   举例如在： jwt中使用的密钥就可以是该算法生成的公私秘钥
 *              （因为该算法的特殊性，所以加密时使用公钥，解密时用私钥仍可以加解密无误。不用使用同一把钥匙，提高了安全性（非对称加密，消耗性能、降低效率、延缓时间））
 *
 * Created by ace on 2018/5/10.
 * @author XinQi.Yuan
 *       修改：chengxi
 * */
public class RsaUtils {

    /**
     * 从文件中读取公钥
     *
     * @param filename   公钥保存路径，相对于classpath
     * @return           公钥对象
     * @throws Exception
     */
    public static PublicKey getPublicKey(String filename) throws Exception {

        byte[] bytes = readFile(filename);

        return getPublicKey(bytes);

    }



    /**
     * 从文件中读取密钥
     *
     * @param filename      私钥保存路径，相对于classpath
     * @return              私钥对象
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(String filename) throws Exception {

        byte[] bytes = readFile(filename);

        return getPrivateKey(bytes);

    }


    /**
     * 获取公钥
     *
     * @param bytes     公钥的字节形式
     * @return          公钥对象
     * @throws Exception
     */
    public static PublicKey getPublicKey(byte[] bytes) throws Exception {

        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);

        KeyFactory factory = KeyFactory.getInstance("RSA");

        return factory.generatePublic(spec);

    }


    /**
     * 获取密钥
     *
     * @param bytes         私钥的字节形式
     * @return              私钥对象
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(byte[] bytes) throws Exception {

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);

        KeyFactory factory = KeyFactory.getInstance("RSA");

        return factory.generatePrivate(spec);

    }


    /**
     * 根据密文，生存rsa公钥和私钥,并写入指定文件
     *
     * @param publicKeyFilename     公钥文件路径
     * @param privateKeyFilename    私钥文件路径
     * @param secret                生成密钥的明文
     * @throws Exception
     */
    public static void generateKey(String publicKeyFilename, String privateKeyFilename, String secret) throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        SecureRandom secureRandom = new SecureRandom(secret.getBytes());

        keyPairGenerator.initialize(1024, secureRandom);

        KeyPair keyPair = keyPairGenerator.genKeyPair();

        // 获取公钥并写出

        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();

        writeFile(publicKeyFilename, publicKeyBytes);

        // 获取私钥并写出

        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();

        writeFile(privateKeyFilename, privateKeyBytes);

    }

    private static byte[] readFile(String fileName) throws Exception {

        return Files.readAllBytes(new File(fileName).toPath());

    }

    private static void writeFile(String destPath, byte[] bytes) throws IOException {

        File dest = new File(destPath);

        if (!dest.exists()) {

            dest.createNewFile();

        }

        Files.write(dest.toPath(), bytes);

    }


    /**
     *  测试使用
     * @param args
     */
    public static void main(String[] args) throws Exception {
        // 调用generateKey方法，输入公私钥的地址，生成秘钥的明文（原料）。即可在指定的地方生成秘钥
        RsaUtils.generateKey("D:/cjp/key.pub","D:/cjp/key.pri","程熙");

        // 这是输入地址获取公有秘钥的，还有一个是输入字节对象获取的。下面获取私有秘钥同理
        PublicKey publicKey = RsaUtils.getPublicKey("D:/cjp/key.pub");
        System.out.println("这是公有的秘钥："+publicKey);

        PrivateKey privateKey = RsaUtils.getPrivateKey("D:/cjp/key.pri");
        System.out.println("这是私有的秘钥："+privateKey);


        System.out.println("ok");
    }

}
