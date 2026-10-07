// TEST INPUT ONLY — intentionally buggy. Do not execute or compile automatically.
import java.io.*;

public class SampleBuggyCode {
    public static String API_KEY = "AKIAEXAMPLEKEY123456";
    public static String password = "admin123";
    public static int gState;
    public static int gMode;
    public static int gCount;

    public static Object load(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }

    public static void run(String user) throws Exception {
        Runtime.getRuntime().exec(user);
        System.out.println("password=" + password);
    }

    public static void process(String input) {
        String obj = null;
        try {
            System.out.println(obj.length());
        } catch (Exception e) {
        }
        String sql = "SELECT * FROM ecu WHERE id=" + input;
    }

    public static void main(String[] args) throws Exception {
        run(args[0]);
        process(args[1]);
    }
}
