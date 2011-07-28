/* ************************************************************************** *
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership.
 * 
 * This file is licensed to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 * ************************************************************************** */
package org.webreformatter.commons.digests;

/**
 * This class is used to calculate SHA1 digests of binary data. This class can
 * be used to calculate hashes of multiple byte sequences until method
 * {@link #getDigest()} or {@link #getDigestString()} is called. These methods
 * "finalize" digest calculation, return the digest and reset all internal
 * fields. So after these method calls the same {@link SHA1} class can be
 * re-used to calculate a new digest. This class can be used on the server side
 * as well as in GWT clients because it does not use bytes - all digest
 * calculations are based on manipulations with integers.
 * 
 * @author kotelnikov
 */
public class SHA1 {

    /**
     * Instances of this class are used to get bytes for which the hash should
     * be calculated
     * 
     * @author kotelnikov
     */
    public interface IByteProvider {

        /**
         * Loads and returns the next byte of the sequence for which the hash
         * should be calculated; this method returns -1 if there is no more
         * available bytes.
         * 
         * @return the next byte or -1 if there is nothing to return
         */
        int getNext();
    }

    /**
     * This is a byte provider translating a given string to the corresponding
     * sequence of bytes. This class represents the string using UTF-8 encoding.
     * So each character of the string will be translated from one to three
     * bytes depending on character.
     * 
     * @author kotelnikov
     */
    public static class StringByteProvider implements IByteProvider {

        private int[] fBuf = { 0, 0, 0 };

        private int fBufLen = 0;

        private int fBufPos = 0;

        private String fMessage;

        private int fPos;

        public StringByteProvider(String msg) {
            fMessage = msg;
        }

        /**
         * @see org.webreformatter.rdf.org.webreformatter.rdf.ns.SHA1.IByteProvider#getNext()
         */
        public int getNext() {
            if (fBufPos == fBufLen) {
                if (fPos == fMessage.length()) {
                    return -1;
                }
                char c = fMessage.charAt(fPos++);
                fBufPos = 0;
                if (c < 128) {
                    fBufLen = 1;
                    fBuf[0] = c;
                    fBuf[1] = 0;
                    fBuf[2] = 0;
                } else if ((c > 127) && (c < 2048)) {
                    fBufLen = 2;
                    fBuf[0] = (c >>> 6) | 192;
                    fBuf[1] = (c & 63) | 128;
                    fBuf[2] = 0;
                } else {
                    fBufLen = 3;
                    fBuf[0] = (c >>> 12) | 224;
                    fBuf[1] = ((c >>> 6) & 63) | 128;
                    fBuf[2] = (c & 63) | 128;
                }
            }
            int result = fBuf[fBufPos++] & 0xFF;
            return result;
        }

    }

    protected static int addToArray(int[] array, int pos, int val) {
        int i = 32;
        array[pos++] = (val >>> (i -= 8)) & 0xFF;
        array[pos++] = (val >>> (i -= 8)) & 0xFF;
        array[pos++] = (val >>> (i -= 8)) & 0xFF;
        array[pos++] = (val >>> (i -= 8)) & 0xFF;
        return pos;
    }

    protected static void appendByteToBuf(StringBuilder buf, int val) {
        String str = Integer.toHexString(val & 0xFF);
        if (str.length() < 2) {
            buf.append('0');
        }
        buf.append(str);
    }

    public static void appendIntToBuf(StringBuilder buf, int val) {
        int i = 32;
        appendByteToBuf(buf, val >>> (i -= 8));
        appendByteToBuf(buf, val >>> (i -= 8));
        appendByteToBuf(buf, val >>> (i -= 8));
        appendByteToBuf(buf, val >>> (i -= 8));
    }

    public static int[] getDigestAsByteArray(int[] digest) {
        int pos = 0;
        int[] array = new int[20];
        pos = addToArray(array, pos, digest[0]);
        pos = addToArray(array, pos, digest[1]);
        pos = addToArray(array, pos, digest[2]);
        pos = addToArray(array, pos, digest[3]);
        pos = addToArray(array, pos, digest[4]);
        return array;
    }

    public static String getDigestAsString(int[] digest) {
        StringBuilder buf = new StringBuilder();
        appendIntToBuf(buf, digest[0]);
        appendIntToBuf(buf, digest[1]);
        appendIntToBuf(buf, digest[2]);
        appendIntToBuf(buf, digest[3]);
        appendIntToBuf(buf, digest[4]);
        return buf.toString();
    }

    private static int rotateLeft(int n, int s) {
        return (n << s) | (n >>> (32 - s));
    }

    public static String toHex(int[] array) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < array.length; i++) {
            String str = Integer.toHexString(array[i] & 0xFF);
            if (str.length() < 2) {
                buf.append('0');
            }
            buf.append(str);
        }
        return buf.toString();
    }

    private int[] fBuf;

    private int fBufPos;

    private int[] fDigest;

    private int fLength;

    private int fValue;

    /**
     * 
     */
    public SHA1() {
        super();
        reset();
    }

    public SHA1(SHA1 digest) {
        this();
        System.arraycopy(digest.fBuf, 0, fBuf, 0, fBuf.length);
        fBufPos = digest.fBufPos;
        System.arraycopy(digest.fDigest, 0, fDigest, 0, fDigest.length);
        fLength = digest.fLength;
        fValue = digest.fValue;
    }

    /**
     * This method adds two values using 16-bit operations. This is a workaround
     * for bugs in some java script interpreters.
     */
    protected int add(int x, int y) {
        int l = (x & 0xFFFF) + (y & 0xFFFF);
        int h = (x >> 16) + (y >> 16) + (l >> 16);
        return (h << 16) | (l & 0xFFFF);
        // return (x + y) & 0x0ffffffff;
    };

    /**
     * @param val
     */
    private void addToBuf(int val) {
        fBuf[fBufPos % 16] = val;
        fBufPos++;
        if (fBufPos % 16 == 0) {
            for (int i = 16; i <= 79; i++) {
                fBuf[i] = rotateLeft(fBuf[i - 3]
                    ^ fBuf[i - 8]
                    ^ fBuf[i - 14]
                    ^ fBuf[i - 16], 1);
            }
            int a = fDigest[0];
            int b = fDigest[1];
            int c = fDigest[2];
            int d = fDigest[3];
            int e = fDigest[4];
            for (int i = 0; i < 80; i++) {
                int f = fBuf[i];
                int temp = 0;
                switch (i / 20) {
                    case 0:
                        temp = add(
                            add(((b & c) | (~b & d)), add(e, f)),
                            0x5A827999);
                        break;
                    case 1:
                        temp = add(add((b ^ c ^ d), add(e, f)), 0x6ED9EBA1);
                        break;
                    case 2:
                        temp = add(
                            add(((b & c) | (b & d) | (c & d)), add(e, f)),
                            0x8F1BBCDC);
                        break;
                    case 3:
                        temp = add(add((b ^ c ^ d), add(e, f)), 0xCA62C1D6);
                        break;
                }
                temp = add(rotateLeft(a, 5), temp);
                e = d;
                d = c;
                c = rotateLeft(b, 30);
                b = a;
                a = temp;
            }
            fDigest[0] = add(fDigest[0], a);
            fDigest[1] = add(fDigest[1], b);
            fDigest[2] = add(fDigest[2], c);
            fDigest[3] = add(fDigest[3], d);
            fDigest[4] = add(fDigest[4], e);
        }
    }

    private void doUpdate(int value) {
        fLength++;
        int shift = fLength % 4;
        fValue |= value << (32 - 8 * shift);
        if (shift == 0) {
            addToBuf(fValue);
            fValue = 0;
        }
    }

    /**
     * 
     */
    protected void finish() {
        int shift = fLength % 4;
        fValue |= (0x080000000 >>> (shift * 8));
        addToBuf(fValue);
        while (fBufPos % 16 != 14) {
            addToBuf(0);
        }
        addToBuf(fLength >>> 29);
        addToBuf((fLength << 3));
    }

    /**
     * @return
     */
    public int[] getDigest() {
        finish();
        int[] array = getDigestAsByteArray(fDigest);
        reset();
        return array;
    }

    public String getDigestString() {
        finish();
        String result = getDigestAsString(fDigest);
        reset();
        return result;
    }

    protected int[] getInternalDigest() {
        return fDigest;
    }

    private void reset() {
        fDigest = new int[5];
        fDigest[0] = 0x67452301;
        fDigest[1] = 0xEFCDAB89;
        fDigest[2] = 0x98BADCFE;
        fDigest[3] = 0x10325476;
        fDigest[4] = 0xC3D2E1F0;
        fBuf = new int[80];
        fBufPos = 0;
        fLength = 0;
        fValue = 0;
    }

    @Override
    public String toString() {
        return getDigestAsString(fDigest);
    }

    public SHA1 update(IByteProvider iterator) {
        while (true) {
            int x = iterator.getNext();
            if (x < 0) {
                break;
            }
            doUpdate(x);
        }
        return this;
    }

    public SHA1 update(int value) {
        value = value & 0xFF;
        doUpdate(value);
        return this;
    }

    public SHA1 update(String msg) {
        update(new StringByteProvider(msg));
        return this;
    }

}
