public final class KernAuthTest {
  public static void main(String[] args) {
    String body = KernAuth.checkBody("pub_harbor_desktop", "KERN-ABCD-EFGH-IJKL-MNOP");
    if (!body.equals("{\"protocol_version\":1,\"public_app_id\":\"pub_harbor_desktop\",\"client_version\":\"1.0.0\",\"license_key\":\"KERN-ABCD-EFGH-IJKL-MNOP\"}")) {
      throw new RuntimeException("body");
    }
    if (!KernAuth.apiMessage("{\"error\":{\"message\":\"Update required\"}}", "no").equals("Update required")) {
      throw new RuntimeException("message");
    }
    if (!KernAuth.apiMessage("{}", "no").equals("no")) throw new RuntimeException("fallback");
    System.out.println("Java check passed");
  }
}
