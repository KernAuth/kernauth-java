import java.util.Scanner;

public final class Main {
  public static void main(String[] args) {
    KernAuth app = new KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__");
    if (!app.check(licenseKey())) {
      System.out.println(app.message);
      System.exit(1);
    }
    System.out.println("Status: active");
    System.out.println(app.expiresAt == null ? "Expires: Lifetime" : "Expires: " + app.expiresAt);
  }

  private static String licenseKey() {
    String fromEnv = System.getenv("KERN_LICENSE_KEY");
    if (fromEnv != null && !fromEnv.isBlank()) return fromEnv.trim();
    System.out.print("Enter license: ");
    String line = new Scanner(System.in).nextLine();
    return line == null ? "" : line.trim();
  }
}
