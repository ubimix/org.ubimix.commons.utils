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

import org.webreformatter.commons.digests.SHA1.IByteProvider;

/**
 * This class is used to calculate SHA1 digests of binary data. This class can
 * be used to calculate hashes of multiple byte sequences until method
 * {@link #getDigest()} or {@link #getDigestString()} is called. These methods
 * "finalize" digest calculation, return the digest and reset all internal
 * fields. So after these method calls the same {@link Sha1Digest} class can be
 * re-used to calculate a new digest. This class can be used on the server side
 * as well as in GWT clients because it does not use bytes - all digest
 * calculations are based on manipulations with integers.
 * 
 * @author kotelnikov
 */
public class Sha1Digest {

    public static class Builder {
        private SHA1 fDigest = new SHA1();

        public Sha1Digest build() {
            SHA1 copy = new SHA1(fDigest);
            copy.finish();
            int[] digest = copy.getInternalDigest();
            return new Sha1Digest(digest);
        }

        @Override
        public String toString() {
            return fDigest.toString();
        }

        public Builder update(IByteProvider iterator) {
            fDigest.update(iterator);
            return this;
        }

        public Builder update(int value) {
            fDigest.update(value);
            return this;
        }

        public Builder update(String msg) {
            fDigest.update(msg);
            return this;
        }

    }

    public static Sha1Digest.Builder builder() {
        return new Builder();
    }

    private int[] fDigest;

    private Sha1Digest(int[] digest) {
        fDigest = digest;
    }

    /**
     * @return an array where each cell corresponds to a byte
     */
    public int[] getDigest() {
        return SHA1.getDigestAsByteArray(fDigest);
    }

    /**
     * Returns an array of integer values where each value corresponds to 4
     * bytes.
     * 
     * @return an array of integer values where each value corresponds to 4
     *         bytes
     */
    public int[] getInternalDigest() {
        return fDigest;
    }

    @Override
    public String toString() {
        return SHA1.getDigestAsString(fDigest);
    }

}
