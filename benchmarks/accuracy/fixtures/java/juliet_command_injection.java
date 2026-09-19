import java.io.IOException;

public class CommandInjectionExample {
    public static void main(String[] args) throws IOException {
        String input = args.length > 0 ? args[0] : "echo ok";
        Runtime.getRuntime().exec("sh -c '" + input + "'");
    }
}
