import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

/**
 * @description: 主程序工具类
 * @author：Favor
 * @date: 2024/5/31
 */
public class MainUtil {
    public static final String TARGET_PATH = ".";// 项目内相对路径，用于存放程序输出的文件和序列号认证码文件


    /**
     * （1）读取授权机器的网卡mac地址生成hash值
     * （2）用用户名和以上hash值产生一个新的hash值，采用数字签名技术产生序列号
     *
     * @throws Exception
     */
    public static void generateSerials() throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println("\n请输入用户名: ");
        String hash2 = getHash(scanner.nextLine());
        //给hash2进行RSA数字签名产生序列号
        RSAPrivateKey rsaPrivateKey = SignatureUtil.init();
        SignatureUtil.rsaSign(hash2, rsaPrivateKey);
    }

    /**
     * 对序列号进行认证
     *
     * @return
     * @throws Exception
     */
    public static boolean verifySerials() throws Exception {
        Scanner scanner = new Scanner(System.in);
        File tmp = new File(TARGET_PATH);
        System.out.println("\n进行序列号认证前，请确保序列号认证码文件PublicKey和保序列号文件SN已经放到指定位置: " + tmp.getAbsolutePath());
        System.out.println("请输入用户名: ");
        String hash2 = getHash(scanner.nextLine());
        return SignatureUtil.rsaVerify(hash2);
    }

    /**
     * 对受保护的内容进行加密
     */
    public static void encrypt() throws Exception {
        Scanner scanner = new Scanner(System.in);
        File sourceFile;
        File encFile;
        System.out.println("\n对文件进行加密前请先认证序列号！");
        if (verifySerials()) {
            System.out.println("接下来对文件进行加密");
        } else {
            System.out.println("未授权禁止加密文件！");
            return;
        }
        System.out.println("请输入你的加密密钥(长度不能小于16位): ");
        String key = scanner.nextLine();
        System.out.println("请输入需要加密文件的绝对路径: ");
        String absolutePath = scanner.nextLine().replace("\"", "");
        sourceFile = new File(absolutePath);
        String fileName = sourceFile.getName();
        if (!sourceFile.exists()) {
            throw new RuntimeException("文件不存在: " + sourceFile.getAbsolutePath());
        }
        encFile = new File(TARGET_PATH + File.separator + "enc_" + fileName);
        System.out.println("加密后文件路径为: " + encFile.getAbsolutePath());
        if (encFile.exists()) {
            encFile.delete();
        }
        // 加密
        try (FileInputStream fis = new FileInputStream(sourceFile);
             FileOutputStream fos = new FileOutputStream(encFile, true)) {
            FileCryptoUtil.encryptFile(fis, fos, key);
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException |
                 InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 对受保护的内容进行解密
     */
    public static void decrypt() throws Exception {
        Scanner scanner = new Scanner(System.in);
        File sourceFile;
        File decFile;
        System.out.println("\n对文件进行解密前请先认证序列号！");
        if (verifySerials()) {
            System.out.println("接下来对文件进行解密");
        } else {
            System.out.println("未授权禁止解密文件！");
            return;
        }
        System.out.println("请输入你的解密密钥(长度不能小于16位): ");
        String key = scanner.nextLine();

        System.out.println("请输入需要解密文件的绝对路径: ");
        String absolutePath = scanner.nextLine().replace("\"", "");

        sourceFile = new File(absolutePath);

        String fileName = sourceFile.getName();
        if (!sourceFile.exists()) {
            throw new RuntimeException("文件不存在: " + sourceFile.getAbsolutePath());
        }
        decFile = new File(TARGET_PATH + File.separator + "dec_" + fileName);
        System.out.println("解密后文件路径为: " + decFile.getAbsolutePath());
        if (decFile.exists()) {
            decFile.delete();
        }
        // 解密
        try (FileInputStream fis = new FileInputStream(sourceFile);
             FileOutputStream fos = new FileOutputStream(decFile, true)) {
            FileCryptoUtil.decryptedFile(fis, fos, key);
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException |
                 InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static void embedWaterMark() throws Exception {
        File sourceFile;
        File embedFile;
        Scanner scanner = new Scanner(System.in);
        System.out.println("\n对文件添加数字水印前请先认证序列号！");
        File tmp = new File(TARGET_PATH);
        System.out.println("\n进行序列号认证前，请确保序列号认证码文件PublicKey和保序列号文件SN已经放到指定位置: " + tmp.getAbsolutePath());
        System.out.println("请输入用户名: ");
        String userName = scanner.nextLine();
        String hash2 = getHash(userName);

        if (SignatureUtil.rsaVerify(hash2)) {
            System.out.println("接下来对文件添加数字水印");
        } else {
            System.out.println("未授权禁止添加数字水印！");
            return;
        }
        System.out.println("请输入需要添加数字水印文件的绝对路径: ");
        String absolutePath = scanner.nextLine().replace("\"", "");
        sourceFile = new File(absolutePath);

        String fileName = sourceFile.getName();
        if (!sourceFile.exists()) {
            throw new RuntimeException("文件不存在: " + sourceFile.getAbsolutePath());
        }
        embedFile = new File(TARGET_PATH + File.separator + "embed_" + fileName);
        System.out.println("添加数字水印后文件路径为: " + embedFile.getAbsolutePath());
        if (embedFile.exists()) {
            embedFile.delete();
        }
        WaterMarkUtil.embedWaterMark(sourceFile,embedFile, userName);
    }
    public static void extractWaterMark() throws IOException {
        File sourceFile;
        Scanner scanner = new Scanner(System.in);
        System.out.println("请输入需要提取数字水印文件的绝对路径: ");
        String absolutePath = scanner.nextLine().replace("\"", "");
        sourceFile = new File(absolutePath);
        if (!sourceFile.exists()) {
            throw new RuntimeException("文件不存在: " + sourceFile.getAbsolutePath());
        }
        System.out.println("文件中的数字水印为: "+WaterMarkUtil.extractWaterMark(sourceFile));
    }
    /**
     * 获取当前计算机上所有网络接口的MAC地址列表
     *
     * @return
     * @throws Exception
     */
    public static List<String> getMacList() throws Exception {
        java.util.Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
        StringBuilder sb = new StringBuilder();
        ArrayList<String> tmpMacList = new ArrayList<>();
        while (en.hasMoreElements()) {
            NetworkInterface iface = en.nextElement();
            List<InterfaceAddress> addrs = iface.getInterfaceAddresses();
            for (InterfaceAddress addr : addrs) {
                InetAddress ip = addr.getAddress();
                NetworkInterface network = NetworkInterface.getByInetAddress(ip);
                if (network == null) {
                    continue;
                }
                byte[] mac = network.getHardwareAddress();
                if (mac == null) {
                    continue;
                }
                sb.delete(0, sb.length());
                for (int i = 0; i < mac.length; i++) {
                    sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                }
                tmpMacList.add(sb.toString());
            }
        }
        if (tmpMacList.size() <= 0) {
            return tmpMacList;
        }
        return tmpMacList.stream().distinct().collect(Collectors.toList());
    }

    /**
     * 使用网卡mac地址生成hash值hash1
     * 用用户名userName和以上hash值hash1产生一个新的hash值hash2
     *
     * @param userName
     * @return
     * @throws Exception
     */
    public static String getHash(String userName) throws Exception {
        String hash1 = SHA256(getMacList().toString());
        return SHA256(userName + hash1);
    }

    /**
     * SHA256摘要算法,接受字符串作为输入
     *
     * @param input
     * @return
     */
    public static String SHA256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(input.getBytes());
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}
