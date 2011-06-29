/**
 * 
 */
package org.webreformatter.commons.digests;

import java.security.MessageDigest;
import java.util.Random;

import junit.framework.TestCase;

/**
 * @author kotelnikov
 */
public class SHA1Test extends TestCase {

    protected MessageDigest fDigest;

    protected SHA1 fSha;

    /**
     * @param name
     */
    public SHA1Test(String name) {
        super(name);
    }

    @Override
    protected void setUp() throws Exception {
        fDigest = MessageDigest.getInstance("SHA1");
        fSha = new SHA1();
    }

    private void sha1(String string, String control) {
        fSha.update(string);
        String test = fSha.getDigestString();
        // System.out.println(control + " - " + test);
        assertEquals(control, test);
    }

    public void test() throws Exception {
        test(new String[0]);
        test("");
        test("abc");
        test("abc", "cde", "efg");
        test(" qsdg qsdg qsdg qsdg qsdg qsdgj\n"
            + "mlqsdgkj qmlsdjg mqlsdgj qmsdgj \n "
            + "qsldjkg abc");
        test(" qsdg qsdg qsdg qsdg qsdg qsdgj\n"
            + "mlqsdgkj qmlsdjg mqlsdgj qmsdgj \n "
            + "qsldjkg abc", " qsdg qsdg qsdg qsdg qsdg qsdgj\n"
            + "mlqsdgkj qmlsdjg mqlsdgj qmsdgj \n "
            + "qsldjkg abc", " qsdg qsdg qsdg qsdg qsdg qsdgj\n"
            + "mlqsdgkj qmlsdjg mqlsdgj qmsdgj \n "
            + "qsldjkg abc", " qsdg qsdg qsdg qsdg qsdg qsdgj\n"
            + "mlqsdgkj qmlsdjg mqlsdgj qmsdgj \n "
            + "qsldjkg abc", " qsdg qsdg qsdg qsdg qsdg qsdgj\n"
            + "mlqsdgkj qmlsdjg mqlsdgj qmsdgj \n "
            + "qsldjkg abc", " qsdg qsdg qsdg qsdg qsdg qsdgj\n"
            + "mlqsdgkj qmlsdjg mqlsdgj qmsdgj \n "
            + "qsldjkg abc", " qsdg qsdg qsdg qsdg qsdg qsdgj\n"
            + "mlqsdgkj qmlsdjg mqlsdgj qmsdgj \n "
            + "qsldjkg abc", " qsdg qsdg qsdg qsdg qsdg qsdgj\n"
            + "mlqsdgkj qmlsdjg mqlsdgj qmsdgj \n "
            + "qsldjkg abc", " qsdg qsdg qsdg qsdg qsdg qsdgj\n"
            + "mlqsdgkj qmlsdjg mqlsdgj qmsdgj \n "
            + "qsldjkg abc", " qsdg qsdg qsdg qsdg qsdg qsdgj\n"
            + "mlqsdgkj qmlsdjg mqlsdgj qmsdgj \n "
            + "qsldjkg abc", " qsdg qsdg qsdg qsdg qsdg qsdgj\n"
            + "mlqsdgkj qmlsdjg mqlsdgj qmsdgj \n "
            + "qsldjkg abc");
        String first = test("Мама мыла раму");
        String second = test("Мама ", "мыла ", "раму");
        assertEquals(first, second);
        test("Мама ", "мыла ", "раму", "abc");
    }

    private String test(final String... strings) throws Exception {
        for (String string : strings) {
            fDigest.update(string.getBytes("UTF-8"));
        }
        byte[] array = fDigest.digest();
        String control = toHex(array);

        for (String string : strings) {
            fSha.update(string);
        }
        String test = fSha.getDigestString();
        // System.out.println(control + " - " + test);
        assertEquals(control, test);
        return test;
    }

    /**
     * @param size
     */
    private void testByteSequence(int size) {
        final byte[] buf = new byte[size];
        Random random = new Random(System.currentTimeMillis());
        random.nextBytes(buf);

        fDigest.update(buf);
        byte[] array = fDigest.digest();
        String control = toHex(array);

        fSha.update(new SHA1.IByteProvider() {
            int fPos;

            public int getNext() {
                if (fPos >= buf.length) {
                    return -1;
                }
                return buf[fPos++] & 0xFF;
            }
        });
        String test = fSha.getDigestString();
        // System.out.println(control + " - " + test);
        assertEquals(control, test);

        // Check that byte-by-byte update method gives the same result
        for (int i = 0; i < buf.length; i++) {
            fSha.update(buf[i]);
        }
        test = fSha.getDigestString();
        System.out.println(control + " - " + test);
        assertEquals(control, test);
    }

    public void testByteSequences() throws Exception {
        testByteSequence(100);
        testByteSequence(1024);
        testByteSequence(1024 * 100);
        testByteSequence(1024 * 1024);
    }

    public void testKnownHashes() {
        sha1("", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        sha1("!", "0ab8318acaf6e678dd02e2b5c343ed41111b393d");
        sha1("\"", "2ace62c1befa19e3ea37dd52be9f6d508c5163e6");
        sha1("#", "d08f88df745fa7950b104e4a707a31cfce7b5841");
        sha1("$", "3cdf2936da2fc556bfa533ab1eb59ce710ac80e5");
        sha1("%", "4345cb1fa27885a8fbfe7c0c830a592cc76a552b");
        sha1("&", "7c4d33785daa5c2370201ffa236b427aa37c9996");
        sha1("'", "bb589d0621e5472f470fa3425a234c74b1e202e8");
        sha1("(", "28ed3a797da3c48c309a4ef792147f3c56cfec40");
        sha1(")", "e7064f0b80f61dbc65915311032d27baa569ae2a");
        sha1("*", "df58248c414f342c81e056b40bee12d17a08bf61");
        sha1("+", "a979ef10cc6f6a36df6b8a323307ee3bb2e2db9c");
        sha1(",", "5c10b5b2cd673a0616d529aa5234b12ee7153808");
        sha1("-", "3bc15c8aae3e4124dd409035f32ea2fd6835efc9");
        sha1(".", "3a52ce780950d4d969792a2559cd519d7ee8c727");
        sha1("/", "42099b4af021e53fd8fd4e056c2568d7c2e3ffa8");
        sha1("0", "b6589fc6ab0dc82cf12099d1c2d40ab994e8410c");
        sha1("1", "356a192b7913b04c54574d18c28d46e6395428ab");
        sha1("2", "da4b9237bacccdf19c0760cab7aec4a8359010b0");
        sha1("3", "77de68daecd823babbb58edb1c8e14d7106e83bb");
        sha1("4", "1b6453892473a467d07372d45eb05abc2031647a");
        sha1("5", "ac3478d69a3c81fa62e60f5c3696165a4e5e6ac4");
        sha1("6", "c1dfd96eea8cc2b62785275bca38ac261256e278");
        sha1("7", "902ba3cda1883801594b6e1b452790cc53948fda");
        sha1("8", "fe5dbbcea5ce7e2988b8c69bcfdfde8904aabc1f");
        sha1("9", "0ade7c2cf97f75d009975f4d720d1fa6c19f4897");
        sha1(":", "05a79f06cf3f67f726dae68d18a2290f6c9a50c9");
        sha1(";", "2d14ab97cc3dc294c51c0d6814f4ea45f4b4e312");
        sha1("<", "c4dd3c8cdd8d7c95603dd67f1cd873d5f9148b29");
        sha1("=", "21606782c65e44cac7afbb90977d8b6f82140e76");
        sha1(">", "091385be99b45f459a231582d583ec9f3fa3d194");
        sha1("?", "5bab61eb53176449e25c2c82f172b82cb13ffb9d");
        sha1("@", "9a78211436f6d425ec38f5c4e02270801f3524f8");
        sha1("A", "6dcd4ce23d88e2ee9568ba546c007c63d9131c1b");
        sha1("B", "ae4f281df5a5d0ff3cad6371f76d5c29b6d953ec");
        sha1("C", "32096c2e0eff33d844ee6d675407ace18289357d");
        sha1("D", "50c9e8d5fc98727b4bbc93cf5d64a68db647f04f");
        sha1("E", "e0184adedf913b076626646d3f52c3b49c39ad6d");
        sha1("F", "e69f20e9f683920d3fb4329abd951e878b1f9372");
        sha1("G", "a36a6718f54524d846894fb04b5b885b4e43e63b");
        sha1("H", "7cf184f4c67ad58283ecb19349720b0cae756829");
        sha1("I", "ca73ab65568cd125c2d27a22bbd9e863c10b675d");
        sha1("J", "58668e7669fd564d99db5d581fcdb6a5618440b5");
        sha1("K", "a7ee38bb7be4fc44198cb2685d9601dcf2b9f569");
        sha1("L", "d160e0986aca4714714a16f29ec605af90be704d");
        sha1("M", "c63ae6dd4fc9f9dda66970e827d13f7c73fe841c");
        sha1("N", "b51a60734da64be0e618bacbea2865a8a7dcd669");
        sha1("O", "08a914cde05039694ef0194d9ee79ff9a79dde33");
        sha1("P", "511993d3c99719e38a6779073019dacd7178ddb9");
        sha1("Q", "c3156e00d3c2588c639e0d3cf6821258b05761c7");
        sha1("R", "06576556d1ad802f247cad11ae748be47b70cd9c");
        sha1("S", "02aa629c8b16cd17a44f3a0efec2feed43937642");
        sha1("T", "c2c53d66948214258a26ca9ca845d7ac0c17f8e7");
        sha1("U", "b2c7c0caa10a0cca5ea7d69e54018ae0c0389dd6");
        sha1("V", "c9ee5681d3c59f7541c27a38b67edf46259e187b");
        sha1("W", "e2415cb7f63df0c9de23362326ad3c37a9adfc96");
        sha1("X", "c032adc1ff629c9b66f22749ad667e6beadf144b");
        sha1("Y", "23eb4d3f4155395a74e9d534f97ff4c1908f5aac");
        sha1("Z", "909f99a779adb66a76fc53ab56c7dd1caf35d0fd");
        sha1("[", "1e5c2f367f02e47a8c160cda1cd9d91decbac441");
        sha1("\\", "08534f33c201a45017b502e90a800f1b708ebcb3");
        sha1("]", "4ff447b8ef42ca51fa6fb287bed8d40f49be58f1");
        sha1("^", "5e6f80a34a9798cafc6a5db96cc57ba4c4db59c2");
        sha1("_", "53a0acfad59379b3e050338bf9f23cfc172ee787");
        sha1("`", "7e15bb5c01e7dd56499e37c634cf791d3a519aee");
        sha1("a", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
        sha1("b", "e9d71f5ee7c92d6dc9e92ffdad17b8bd49418f98");
        sha1("c", "84a516841ba77a5b4648de2cd0dfcb30ea46dbb4");
        sha1("d", "3c363836cf4e16666669a25da280a1865c2d2874");
        sha1("e", "58e6b3a414a1e090dfc6029add0f3555ccba127f");
        sha1("f", "4a0a19218e082a343a1b17e5333409af9d98f0f5");
        sha1("g", "54fd1711209fb1c0781092374132c66e79e2241b");
        sha1("h", "27d5482eebd075de44389774fce28c69f45c8a75");
        sha1("i", "042dc4512fa3d391c5170cf3aa61e6a638f84342");
        sha1("j", "5c2dd944dde9e08881bef0894fe7b22a5c9c4b06");
        sha1("k", "13fbd79c3d390e5d6585a21e11ff5ec1970cff0c");
        sha1("l", "07c342be6e560e7f43842e2e21b774e61d85f047");
        sha1("m", "6b0d31c0d563223024da45691584643ac78c96e8");
        sha1("n", "d1854cae891ec7b29161ccaf79a24b00c274bdaa");
        sha1("o", "7a81af3e591ac713f81ea1efe93dcf36157d8376");
        sha1("p", "516b9783fca517eecbd1d064da2d165310b19759");
        sha1("q", "22ea1c649c82946aa6e479e1ffd321e4a318b1b0");
        sha1("r", "4dc7c9ec434ed06502767136789763ec11d2c4b7");
        sha1("s", "a0f1490a20d0211c997b44bc357e1972deab8ae3");
        sha1("t", "8efd86fb78a56a5145ed7739dcb00c78581c5375");
        sha1("u", "51e69892ab49df85c6230ccc57f8e1d1606caccc");
        sha1("v", "7a38d8cbd20d9932ba948efaa364bb62651d5ad4");
        sha1("w", "aff024fe4ab0fece4091de044c58c9ae4233383a");
        sha1("x", "11f6ad8ec52a2984abaafd7c3b516503785c2072");
        sha1("y", "95cb0bfd2977c761298d9624e4b4d4c72a39974a");
        sha1("z", "395df8f7c51f007019cb30201c49e884b46b92fa");
        sha1("{", "60ba4b2daa4ed4d070fec06687e249e0e6f9ee45");
        sha1("|", "3eb416223e9e69e6bb8ee19793911ad1ad2027d8");
        sha1("}", "c2b7df6201fdd3362399091f0a29550df3505b6a");
        sha1("~", "fb3c6e4de85bd9eae26fdc63e75f10a7f39e850e");
    }

    private String toHex(byte[] array) {
        StringBuffer buf = new StringBuffer();
        for (byte element : array) {
            String str = Integer.toHexString(element & 0xFF);
            if (str.length() < 2) {
                buf.append('0');
            }
            buf.append(str);
        }
        return buf.toString();
    }

}
