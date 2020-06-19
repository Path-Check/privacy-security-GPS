import java.nio.charset.StandardCharsets;

public class Util {

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    //Original source: https://stackoverflow.com/a/9855338/1389357
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static void main(String args[]){
      byte[] b = args[0].getBytes(StandardCharsets.UTF_8);
      System.out.println(Util.bytesToHex(b));

    }

}
