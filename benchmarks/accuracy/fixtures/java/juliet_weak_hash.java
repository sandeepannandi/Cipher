import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class WeakHashExample {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest("sensitive".getBytes());
        System.out.println(new String(digest));
    }
}
