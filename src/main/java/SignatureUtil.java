import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @description: RSA数字签名工具类
 * @author：Favor
 * @date: 2024/5/31
 */
public class SignatureUtil {

    /**
     * 初始化密钥
     *
     * @return
     * @throws Exception
     */
    public static RSAPrivateKey init() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        File sourceFile = new File(MainUtil.TARGET_PATH + File.separator + "PublicKey");
        if (sourceFile.exists()) {
            sourceFile.delete();
        }
        System.out.println("序列号认证码保存地址：" + sourceFile.getAbsolutePath());
        serializeObjectToFile(rsaPublicKey, String.valueOf(sourceFile));
        return rsaPrivateKey;
    }

    /**
     * 执行签名
     *
     * @param src
     * @param rsaPrivateKey
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static void rsaSign(String src, RSAPrivateKey rsaPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initSign(privateKey);
        signature.update(src.getBytes());
        byte[] result = signature.sign();
        File sourceFile = new File(MainUtil.TARGET_PATH + File.separator + "SN");
        if (sourceFile.exists()) {
            sourceFile.delete();
        }
        System.out.println("序列号保存地址：" + sourceFile.getAbsolutePath());
        System.out.println("序列号(RSA数字签名)为: " + byteArrayToHexString(result));
        serializeObjectToFile(byteArrayToHexString(result), String.valueOf(sourceFile));
    }

    /**
     * 验证签名
     *
     * @param src
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean rsaVerify(String src) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        File keyFile = new File(MainUtil.TARGET_PATH + File.separator + "PublicKey");
        if (!keyFile.exists()) {
            throw new RuntimeException("PublicKey文件不存在: " + keyFile.getAbsolutePath());
        }
        File snFile = new File(MainUtil.TARGET_PATH + File.separator + "SN");
        if (!snFile.exists()) {
            throw new RuntimeException("SN文件不存在: " + snFile.getAbsolutePath());
        }
        RSAPublicKey rsaPublicKey = deserializeObjectFromFile(String.valueOf(keyFile));
        String sn=deserializeObjectFromFile(String.valueOf(snFile));
        byte[] result = hexStringToByteArray(sn);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initVerify(publicKey);
        signature.update(src.getBytes());
        boolean bool = signature.verify(result);
        if (bool) {
            System.out.println("序列号认证通过");
        } else {
            System.out.println("序列号认证未通过");
        }
        return bool;
    }

    /**
     * 将给定的对象序列化到指定的文件中
     *
     * @param object
     * @param filePath
     */
    public static <T> void serializeObjectToFile(T object, String filePath) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            oos.writeObject(object);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 从指定文件中读取对象，并将其反序列化为可用的 Java 对象
     *
     * @param filePath
     * @return
     */
    public static <T> T deserializeObjectFromFile(String filePath) {
        T object = null;

        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            object = (T) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        return object;
    }

    /**
     * 将字节数组转换为十六进制字符串
     *
     * @param bytes
     * @return
     */
    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * 将十六进制字符串转换为字节数组
     *
     * @param hexString
     * @return
     */
    public static byte[] hexStringToByteArray(String hexString) {
        if (hexString.length() % 2 != 0) {
            throw new IllegalArgumentException("序列号长度错误，请检查！");
        }
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            String hex = hexString.substring(i, i + 2);
            bytes[i / 2] = (byte) Integer.parseInt(hex, 16);
        }

        return bytes;
    }
}