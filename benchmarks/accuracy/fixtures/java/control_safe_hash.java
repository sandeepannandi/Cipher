import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SafeHashExample {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest("sensitive".getBytes());
        System.out.println(new String(digest));
    }
}
