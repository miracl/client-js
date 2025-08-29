'use strict';

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

function AES() {

    var AES = function() {
        this.Nk = 0;
        this.Nr = 0;
        this.mode = 0;
        this.fkey = [];
        this.rkey = [];
        this.f = [];
    };

    // AES constants
    AES.ECB = 0;
    AES.CBC = 1;
    AES.CFB1 = 2;
    AES.CFB2 = 3;
    AES.CFB4 = 5;
    AES.OFB1 = 14;
    AES.OFB2 = 15;
    AES.OFB4 = 17;
    AES.OFB8 = 21;
    AES.OFB16 = 29;
    AES.CTR1 = 30;
    AES.CTR2 = 31;
    AES.CTR4 = 33;
    AES.CTR8 = 37;
    AES.CTR16 = 45;

    AES.prototype = {
        /* reset cipher - mode or iv */
        reset: function(m, iv) {
            var i;

            this.mode = m;

            for (i = 0; i < 16; i++) {
                this.f[i] = 0;
            }

            if (this.mode != AES.ECB && iv !== null) {
                for (i = 0; i < 16; i++) {
                    this.f[i] = iv[i];
                }
            }
        },

        getreg: function() {
            var ir = [],
                i;

            for (i = 0; i < 16; i++) {
                ir[i] = this.f[i];
            }

            return ir;
        },

        increment: function() {
            var i;

            for (i = 0; i < 16; i++) {
                this.f[i]++;

                if ((this.f[i] & 0xff) != 0) {
                    break;
                }
            }
        },

        /* Initialise cipher */
        init: function(m, nk, key, iv) {
            /* Key Scheduler. Create expanded encryption key */
            var CipherKey = [],
                b = [],
                i, j, k, N, nr;

            nk /= 4;

            if (nk != 4 && nk != 6 && nk != 8) {
                return false;
            }

            nr = 6 + nk;

            this.Nk = nk;
            this.Nr = nr;


            this.reset(m, iv);
            N = 4 * (nr + 1);

            for (i = j = 0; i < nk; i++, j += 4) {
                for (k = 0; k < 4; k++) {
                    b[k] = key[j + k];
                }
                CipherKey[i] = AES.pack(b);
            }

            for (i = 0; i < nk; i++) {
                this.fkey[i] = CipherKey[i];
            }

            for (j = nk, k = 0; j < N; j += nk, k++) {
                this.fkey[j] = this.fkey[j - nk] ^ AES.SubByte(AES.ROTL24(this.fkey[j - 1])) ^ (AES.rco[k]) & 0xff;
                for (i = 1; i < nk && (i + j) < N; i++) {
                    this.fkey[i + j] = this.fkey[i + j - nk] ^ this.fkey[i + j - 1];
                }
            }

            /* now for the expanded decrypt key in reverse order */

            for (j = 0; j < 4; j++) {
                this.rkey[j + N - 4] = this.fkey[j];
            }

            for (i = 4; i < N - 4; i += 4) {
                k = N - 4 - i;
                for (j = 0; j < 4; j++) {
                    this.rkey[k + j] = AES.InvMixCol(this.fkey[i + j]);
                }
            }

            for (j = N - 4; j < N; j++) {
                this.rkey[j - N + 4] = this.fkey[j];
            }
        },

        /* Encrypt a single block */
        ecb_encrypt: function(buff) {
            var b = [],
                p = [],
                q = [],
                t, i, j, k;

            for (i = j = 0; i < 4; i++, j += 4) {
                for (k = 0; k < 4; k++) {
                    b[k] = buff[j + k];
                }
                p[i] = AES.pack(b);
                p[i] ^= this.fkey[i];
            }

            k = 4;

            /* State alternates between p and q */
            for (i = 1; i < this.Nr; i++) {
                q[0] = this.fkey[k] ^ AES.ftable[p[0] & 0xff] ^
                    AES.ROTL8(AES.ftable[(p[1] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.ftable[(p[2] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.ftable[(p[3] >>> 24) & 0xff]);
                q[1] = this.fkey[k + 1] ^ AES.ftable[p[1] & 0xff] ^
                    AES.ROTL8(AES.ftable[(p[2] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.ftable[(p[3] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.ftable[(p[0] >>> 24) & 0xff]);
                q[2] = this.fkey[k + 2] ^ AES.ftable[p[2] & 0xff] ^
                    AES.ROTL8(AES.ftable[(p[3] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.ftable[(p[0] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.ftable[(p[1] >>> 24) & 0xff]);
                q[3] = this.fkey[k + 3] ^ AES.ftable[p[3] & 0xff] ^
                    AES.ROTL8(AES.ftable[(p[0] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.ftable[(p[1] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.ftable[(p[2] >>> 24) & 0xff]);

                k += 4;
                for (j = 0; j < 4; j++) {
                    t = p[j];
                    p[j] = q[j];
                    q[j] = t;
                }
            }

            /* Last Round */

            q[0] = this.fkey[k] ^ (AES.fbsub[p[0] & 0xff] & 0xff) ^
                AES.ROTL8(AES.fbsub[(p[1] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.fbsub[(p[2] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.fbsub[(p[3] >>> 24) & 0xff] & 0xff);

            q[1] = this.fkey[k + 1] ^ (AES.fbsub[p[1] & 0xff] & 0xff) ^
                AES.ROTL8(AES.fbsub[(p[2] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.fbsub[(p[3] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.fbsub[(p[0] >>> 24) & 0xff] & 0xff);

            q[2] = this.fkey[k + 2] ^ (AES.fbsub[p[2] & 0xff] & 0xff) ^
                AES.ROTL8(AES.fbsub[(p[3] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.fbsub[(p[0] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.fbsub[(p[1] >>> 24) & 0xff] & 0xff);

            q[3] = this.fkey[k + 3] ^ (AES.fbsub[(p[3]) & 0xff] & 0xff) ^
                AES.ROTL8(AES.fbsub[(p[0] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.fbsub[(p[1] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.fbsub[(p[2] >>> 24) & 0xff] & 0xff);

            for (i = j = 0; i < 4; i++, j += 4) {
                b = AES.unpack(q[i]);
                for (k = 0; k < 4; k++) {
                    buff[j + k] = b[k];
                }
            }
        },

        /* Decrypt a single block */
        ecb_decrypt: function(buff) {
            var b = [],
                p = [],
                q = [],
                t, i, j, k;

            for (i = j = 0; i < 4; i++, j += 4) {
                for (k = 0; k < 4; k++) {
                    b[k] = buff[j + k];
                }
                p[i] = AES.pack(b);
                p[i] ^= this.rkey[i];
            }

            k = 4;

            /* State alternates between p and q */
            for (i = 1; i < this.Nr; i++) {
                q[0] = this.rkey[k] ^ AES.rtable[p[0] & 0xff] ^
                    AES.ROTL8(AES.rtable[(p[3] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.rtable[(p[2] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.rtable[(p[1] >>> 24) & 0xff]);
                q[1] = this.rkey[k + 1] ^ AES.rtable[p[1] & 0xff] ^
                    AES.ROTL8(AES.rtable[(p[0] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.rtable[(p[3] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.rtable[(p[2] >>> 24) & 0xff]);
                q[2] = this.rkey[k + 2] ^ AES.rtable[p[2] & 0xff] ^
                    AES.ROTL8(AES.rtable[(p[1] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.rtable[(p[0] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.rtable[(p[3] >>> 24) & 0xff]);
                q[3] = this.rkey[k + 3] ^ AES.rtable[p[3] & 0xff] ^
                    AES.ROTL8(AES.rtable[(p[2] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.rtable[(p[1] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.rtable[(p[0] >>> 24) & 0xff]);

                k += 4;

                for (j = 0; j < 4; j++) {
                    t = p[j];
                    p[j] = q[j];
                    q[j] = t;
                }
            }

            /* Last Round */

            q[0] = this.rkey[k] ^ (AES.rbsub[p[0] & 0xff] & 0xff) ^
                AES.ROTL8(AES.rbsub[(p[3] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.rbsub[(p[2] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.rbsub[(p[1] >>> 24) & 0xff] & 0xff);
            q[1] = this.rkey[k + 1] ^ (AES.rbsub[p[1] & 0xff] & 0xff) ^
                AES.ROTL8(AES.rbsub[(p[0] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.rbsub[(p[3] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.rbsub[(p[2] >>> 24) & 0xff] & 0xff);
            q[2] = this.rkey[k + 2] ^ (AES.rbsub[p[2] & 0xff] & 0xff) ^
                AES.ROTL8(AES.rbsub[(p[1] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.rbsub[(p[0] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.rbsub[(p[3] >>> 24) & 0xff] & 0xff);
            q[3] = this.rkey[k + 3] ^ (AES.rbsub[p[3] & 0xff] & 0xff) ^
                AES.ROTL8(AES.rbsub[(p[2] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.rbsub[(p[1] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.rbsub[(p[0] >>> 24) & 0xff] & 0xff);

            for (i = j = 0; i < 4; i++, j += 4) {
                b = AES.unpack(q[i]);
                for (k = 0; k < 4; k++) {
                    buff[j + k] = b[k];
                }
            }

        },

        /* Encrypt using selected mode of operation */
        encrypt: function(buff) {
            var st = [],
                bytes, fell_off, j;

            // Supported Modes of Operation

            fell_off = 0;

            switch (this.mode) {
                case AES.ECB:
                    this.ecb_encrypt(buff);
                    return 0;

                case AES.CBC:
                    for (j = 0; j < 16; j++) {
                        buff[j] ^= this.f[j];
                    }
                    this.ecb_encrypt(buff);
                    for (j = 0; j < 16; j++) {
                        this.f[j] = buff[j];
                    }
                    return 0;

                case AES.CFB1:
                case AES.CFB2:
                case AES.CFB4:
                    bytes = this.mode - AES.CFB1 + 1;
                    for (j = 0; j < bytes; j++) {
                        fell_off = (fell_off << 8) | this.f[j];
                    }
                    for (j = 0; j < 16; j++) {
                        st[j] = this.f[j];
                    }
                    for (j = bytes; j < 16; j++) {
                        this.f[j - bytes] = this.f[j];
                    }
                    this.ecb_encrypt(st);
                    for (j = 0; j < bytes; j++) {
                        buff[j] ^= st[j];
                        this.f[16 - bytes + j] = buff[j];
                    }
                    return fell_off;

                case AES.OFB1:
                case AES.OFB2:
                case AES.OFB4:
                case AES.OFB8:
                case AES.OFB16:
                    bytes = this.mode - AES.OFB1 + 1;
                    this.ecb_encrypt(this.f);
                    for (j = 0; j < bytes; j++) {
                        buff[j] ^= this.f[j];
                    }
                    return 0;

                case AES.CTR1:
                case AES.CTR2:
                case AES.CTR4:
                case AES.CTR8:
                case AES.CTR16:
                    bytes = this.mode - AES.CTR1 + 1;
                    for (j = 0; j < 16; j++) {
                        st[j] = this.f[j];
                    }
                    this.ecb_encrypt(st);
                    for (j = 0; j < bytes; j++) {
                        buff[j] ^= st[j];
                    }
                    this.increment();
                    return 0;

                default:
                    return 0;
            }
        },

        /* Decrypt using selected mode of operation */
        decrypt: function(buff) {
            var st = [],
                bytes,fell_off, j;

            // Supported modes of operation
            fell_off = 0;
            switch (this.mode) {
                case AES.ECB:
                    this.ecb_decrypt(buff);
                    return 0;

                case AES.CBC:
                    for (j = 0; j < 16; j++) {
                        st[j] = this.f[j];
                        this.f[j] = buff[j];
                    }
                    this.ecb_decrypt(buff);
                    for (j = 0; j < 16; j++) {
                        buff[j] ^= st[j];
                        st[j] = 0;
                    }
                    return 0;

                case AES.CFB1:
                case AES.CFB2:
                case AES.CFB4:
                    bytes = this.mode - AES.CFB1 + 1;
                    for (j = 0; j < bytes; j++) {
                        fell_off = (fell_off << 8) | this.f[j];
                    }
                    for (j = 0; j < 16; j++) {
                        st[j] = this.f[j];
                    }
                    for (j = bytes; j < 16; j++) {
                        this.f[j - bytes] = this.f[j];
                    }
                    this.ecb_encrypt(st);
                    for (j = 0; j < bytes; j++) {
                        this.f[16 - bytes + j] = buff[j];
                        buff[j] ^= st[j];
                    }
                    return fell_off;

                case AES.OFB1:
                case AES.OFB2:
                case AES.OFB4:
                case AES.OFB8:
                case AES.OFB16:
                    bytes = this.mode - AES.OFB1 + 1;
                    this.ecb_encrypt(this.f);
                    for (j = 0; j < bytes; j++) {
                        buff[j] ^= this.f[j];
                    }
                    return 0;

                case AES.CTR1:
                case AES.CTR2:
                case AES.CTR4:
                case AES.CTR8:
                case AES.CTR16:
                    bytes = this.mode - AES.CTR1 + 1;
                    for (j = 0; j < 16; j++) {
                        st[j] = this.f[j];
                    }
                    this.ecb_encrypt(st);
                    for (j = 0; j < bytes; j++) {
                        buff[j] ^= st[j];
                    }
                    this.increment();
                    return 0;

                default:
                    return 0;
            }
        },

        /* Clean up and delete left-overs */
        end: function() {
            var i;

            for (i = 0; i < 4 * (this.Nr + 1); i++) {
                this.fkey[i] = this.rkey[i] = 0;
            }

            for (i = 0; i < 16; i++) {
                this.f[i] = 0;
            }
        }
    };

    /* static functions */

    AES.ROTL8 = function(x) {
        return (((x) << 8) | ((x) >>> 24));
    };

    AES.ROTL16 = function(x) {
        return (((x) << 16) | ((x) >>> 16));
    };

    AES.ROTL24 = function(x) {
        return (((x) << 24) | ((x) >>> 8));
    };

    /* pack 4 bytes into a 32-bit Word */
    AES.pack = function(b) {
        return (((b[3]) & 0xff) << 24) | ((b[2] & 0xff) << 16) | ((b[1] & 0xff) << 8) | (b[0] & 0xff);
    };

    /* unpack bytes from a word */
    AES.unpack = function(a) {
        var b = [];
        b[0] = (a & 0xff);
        b[1] = ((a >>> 8) & 0xff);
        b[2] = ((a >>> 16) & 0xff);
        b[3] = ((a >>> 24) & 0xff);
        return b;
    };

    /* x.y= AntiLog(Log(x) + Log(y)) */
    AES.bmul = function(x, y) {
        var ix = (x & 0xff),
            iy = (y & 0xff),
            lx = (AES.ltab[ix]) & 0xff,
            ly = (AES.ltab[iy]) & 0xff;

        if (x !== 0 && y !== 0) {
            return AES.ptab[(lx + ly) % 255];
        } else {
            return 0;
        }
    };

    //  if (x && y)

    AES.SubByte = function(a) {
        var b = AES.unpack(a);
        b[0] = AES.fbsub[b[0] & 0xff];
        b[1] = AES.fbsub[b[1] & 0xff];
        b[2] = AES.fbsub[b[2] & 0xff];
        b[3] = AES.fbsub[b[3] & 0xff];
        return AES.pack(b);
    };

    /* dot product of two 4-byte arrays */
    AES.product = function(x, y) {
        var xb = AES.unpack(x),
            yb = AES.unpack(y);

        return (AES.bmul(xb[0], yb[0]) ^ AES.bmul(xb[1], yb[1]) ^ AES.bmul(xb[2], yb[2]) ^ AES.bmul(xb[3], yb[3])) & 0xff;
    };

    /* matrix Multiplication */
    AES.InvMixCol = function(x) {
        var b = [],
            y, m;

        m = AES.pack(AES.InCo);
        b[3] = AES.product(m, x);
        m = AES.ROTL24(m);
        b[2] = AES.product(m, x);
        m = AES.ROTL24(m);
        b[1] = AES.product(m, x);
        m = AES.ROTL24(m);
        b[0] = AES.product(m, x);
        y = AES.pack(b);

        return y;
    };

    /* Inverse Coefficients */
    AES.InCo = [0xB, 0xD, 0x9, 0xE];
    AES.rco = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47];

    AES.ptab = [
        1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53,
        95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170,
        229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49,
        83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205,
        76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136,
        131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154,
        181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163,
        254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160,
        251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65,
        195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117,
        159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
        155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84,
        252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202,
        69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14,
        18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23,
        57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, 1
    ];
    AES.ltab = [
        0, 255, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3,
        100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193,
        125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120,
        101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142,
        150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56,
        102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16,
        126, 110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186,
        43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87,
        175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232,
        44, 215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160,
        127, 12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183,
        204, 187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157,
        151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209,
        83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171,
        68, 17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165,
        103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7
    ];
    AES.fbsub = [
        99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
        202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
        183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
        4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
        9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
        83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
        208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
        81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
        205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
        96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
        224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
        231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
        186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
        112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
        225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
        140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22
    ];
    AES.rbsub = [
        82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
        124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
        84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
        8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
        114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146,
        108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132,
        144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6,
        208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107,
        58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
        150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110,
        71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27,
        252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244,
        31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
        96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
        160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
        23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125
    ];
    AES.ftable = [
        0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6, 0xdf2f2ff, 0xbd6b6bd6,
        0xb16f6fde, 0x54c5c591, 0x50303060, 0x3010102, 0xa96767ce, 0x7d2b2b56,
        0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 0x9a7676ec, 0x45caca8f, 0x9d82821f,
        0x40c9c989, 0x877d7dfa, 0x15fafaef, 0xeb5959b2, 0xc947478e, 0xbf0f0fb,
        0xecadad41, 0x67d4d4b3, 0xfda2a25f, 0xeaafaf45, 0xbf9c9c23, 0xf7a4a453,
        0x967272e4, 0x5bc0c09b, 0xc2b7b775, 0x1cfdfde1, 0xae93933d, 0x6a26264c,
        0x5a36366c, 0x413f3f7e, 0x2f7f7f5, 0x4fcccc83, 0x5c343468, 0xf4a5a551,
        0x34e5e5d1, 0x8f1f1f9, 0x937171e2, 0x73d8d8ab, 0x53313162, 0x3f15152a,
        0xc040408, 0x52c7c795, 0x65232346, 0x5ec3c39d, 0x28181830, 0xa1969637,
        0xf05050a, 0xb59a9a2f, 0x907070e, 0x36121224, 0x9b80801b, 0x3de2e2df,
        0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea, 0x1b090912, 0x9e83831d,
        0x742c2c58, 0x2e1a1a34, 0x2d1b1b36, 0xb26e6edc, 0xee5a5ab4, 0xfba0a05b,
        0xf65252a4, 0x4d3b3b76, 0x61d6d6b7, 0xceb3b37d, 0x7b292952, 0x3ee3e3dd,
        0x712f2f5e, 0x97848413, 0xf55353a6, 0x68d1d1b9, 0x0, 0x2cededc1,
        0x60202040, 0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6, 0xbe6a6ad4, 0x46cbcb8d,
        0xd9bebe67, 0x4b393972, 0xde4a4a94, 0xd44c4c98, 0xe85858b0, 0x4acfcf85,
        0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed, 0xc5434386, 0xd74d4d9a,
        0x55333366, 0x94858511, 0xcf45458a, 0x10f9f9e9, 0x6020204, 0x817f7ffe,
        0xf05050a0, 0x443c3c78, 0xba9f9f25, 0xe3a8a84b, 0xf35151a2, 0xfea3a35d,
        0xc0404080, 0x8a8f8f05, 0xad92923f, 0xbc9d9d21, 0x48383870, 0x4f5f5f1,
        0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142, 0x30101020, 0x1affffe5,
        0xef3f3fd, 0x6dd2d2bf, 0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3,
        0xe15f5fbe, 0xa2979735, 0xcc444488, 0x3917172e, 0x57c4c493, 0xf2a7a755,
        0x827e7efc, 0x473d3d7a, 0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6,
        0xa06060c0, 0x98818119, 0xd14f4f9e, 0x7fdcdca3, 0x66222244, 0x7e2a2a54,
        0xab90903b, 0x8388880b, 0xca46468c, 0x29eeeec7, 0xd3b8b86b, 0x3c141428,
        0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad, 0x3be0e0db, 0x56323264,
        0x4e3a3a74, 0x1e0a0a14, 0xdb494992, 0xa06060c, 0x6c242448, 0xe45c5cb8,
        0x5dc2c29f, 0x6ed3d3bd, 0xefacac43, 0xa66262c4, 0xa8919139, 0xa4959531,
        0x37e4e4d3, 0x8b7979f2, 0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda,
        0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949, 0xb46c6cd8, 0xfa5656ac,
        0x7f4f4f3, 0x25eaeacf, 0xaf6565ca, 0x8e7a7af4, 0xe9aeae47, 0x18080810,
        0xd5baba6f, 0x887878f0, 0x6f25254a, 0x722e2e5c, 0x241c1c38, 0xf1a6a657,
        0xc7b4b473, 0x51c6c697, 0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e,
        0xdd4b4b96, 0xdcbdbd61, 0x868b8b0d, 0x858a8a0f, 0x907070e0, 0x423e3e7c,
        0xc4b5b571, 0xaa6666cc, 0xd8484890, 0x5030306, 0x1f6f6f7, 0x120e0e1c,
        0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969, 0x91868617, 0x58c1c199,
        0x271d1d3a, 0xb99e9e27, 0x38e1e1d9, 0x13f8f8eb, 0xb398982b, 0x33111122,
        0xbb6969d2, 0x70d9d9a9, 0x898e8e07, 0xa7949433, 0xb69b9b2d, 0x221e1e3c,
        0x92878715, 0x20e9e9c9, 0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5,
        0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a, 0xdabfbf65, 0x31e6e6d7,
        0xc6424284, 0xb86868d0, 0xc3414182, 0xb0999929, 0x772d2d5a, 0x110f0f1e,
        0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d, 0x3a16162c
    ];
    AES.rtable = [
        0x50a7f451, 0x5365417e, 0xc3a4171a, 0x965e273a, 0xcb6bab3b, 0xf1459d1f,
        0xab58faac, 0x9303e34b, 0x55fa3020, 0xf66d76ad, 0x9176cc88, 0x254c02f5,
        0xfcd7e54f, 0xd7cb2ac5, 0x80443526, 0x8fa362b5, 0x495ab1de, 0x671bba25,
        0x980eea45, 0xe1c0fe5d, 0x2752fc3, 0x12f04c81, 0xa397468d, 0xc6f9d36b,
        0xe75f8f03, 0x959c9215, 0xeb7a6dbf, 0xda595295, 0x2d83bed4, 0xd3217458,
        0x2969e049, 0x44c8c98e, 0x6a89c275, 0x78798ef4, 0x6b3e5899, 0xdd71b927,
        0xb64fe1be, 0x17ad88f0, 0x66ac20c9, 0xb43ace7d, 0x184adf63, 0x82311ae5,
        0x60335197, 0x457f5362, 0xe07764b1, 0x84ae6bbb, 0x1ca081fe, 0x942b08f9,
        0x58684870, 0x19fd458f, 0x876cde94, 0xb7f87b52, 0x23d373ab, 0xe2024b72,
        0x578f1fe3, 0x2aab5566, 0x728ebb2, 0x3c2b52f, 0x9a7bc586, 0xa50837d3,
        0xf2872830, 0xb2a5bf23, 0xba6a0302, 0x5c8216ed, 0x2b1ccf8a, 0x92b479a7,
        0xf0f207f3, 0xa1e2694e, 0xcdf4da65, 0xd5be0506, 0x1f6234d1, 0x8afea6c4,
        0x9d532e34, 0xa055f3a2, 0x32e18a05, 0x75ebf6a4, 0x39ec830b, 0xaaef6040,
        0x69f715e, 0x51106ebd, 0xf98a213e, 0x3d06dd96, 0xae053edd, 0x46bde64d,
        0xb58d5491, 0x55dc471, 0x6fd40604, 0xff155060, 0x24fb9819, 0x97e9bdd6,
        0xcc434089, 0x779ed967, 0xbd42e8b0, 0x888b8907, 0x385b19e7, 0xdbeec879,
        0x470a7ca1, 0xe90f427c, 0xc91e84f8, 0x0, 0x83868009, 0x48ed2b32,
        0xac70111e, 0x4e725a6c, 0xfbff0efd, 0x5638850f, 0x1ed5ae3d, 0x27392d36,
        0x64d90f0a, 0x21a65c68, 0xd1545b9b, 0x3a2e3624, 0xb1670a0c, 0xfe75793,
        0xd296eeb4, 0x9e919b1b, 0x4fc5c080, 0xa220dc61, 0x694b775a, 0x161a121c,
        0xaba93e2, 0xe52aa0c0, 0x43e0223c, 0x1d171b12, 0xb0d090e, 0xadc78bf2,
        0xb9a8b62d, 0xc8a91e14, 0x8519f157, 0x4c0775af, 0xbbdd99ee, 0xfd607fa3,
        0x9f2601f7, 0xbcf5725c, 0xc53b6644, 0x347efb5b, 0x7629438b, 0xdcc623cb,
        0x68fcedb6, 0x63f1e4b8, 0xcadc31d7, 0x10856342, 0x40229713, 0x2011c684,
        0x7d244a85, 0xf83dbbd2, 0x1132f9ae, 0x6da129c7, 0x4b2f9e1d, 0xf330b2dc,
        0xec52860d, 0xd0e3c177, 0x6c16b32b, 0x99b970a9, 0xfa489411, 0x2264e947,
        0xc48cfca8, 0x1a3ff0a0, 0xd82c7d56, 0xef903322, 0xc74e4987, 0xc1d138d9,
        0xfea2ca8c, 0x360bd498, 0xcf81f5a6, 0x28de7aa5, 0x268eb7da, 0xa4bfad3f,
        0xe49d3a2c, 0xd927850, 0x9bcc5f6a, 0x62467e54, 0xc2138df6, 0xe8b8d890,
        0x5ef7392e, 0xf5afc382, 0xbe805d9f, 0x7c93d069, 0xa92dd56f, 0xb31225cf,
        0x3b99acc8, 0xa77d1810, 0x6e639ce8, 0x7bbb3bdb, 0x97826cd, 0xf418596e,
        0x1b79aec, 0xa89a4f83, 0x656e95e6, 0x7ee6ffaa, 0x8cfbc21, 0xe6e815ef,
        0xd99be7ba, 0xce366f4a, 0xd4099fea, 0xd67cb029, 0xafb2a431, 0x31233f2a,
        0x3094a5c6, 0xc066a235, 0x37bc4e74, 0xa6ca82fc, 0xb0d090e0, 0x15d8a733,
        0x4a9804f1, 0xf7daec41, 0xe50cd7f, 0x2ff69117, 0x8dd64d76, 0x4db0ef43,
        0x544daacc, 0xdf0496e4, 0xe3b5d19e, 0x1b886a4c, 0xb81f2cc1, 0x7f516546,
        0x4ea5e9d, 0x5d358c01, 0x737487fa, 0x2e410bfb, 0x5a1d67b3, 0x52d2db92,
        0x335610e9, 0x1347d66d, 0x8c61d79a, 0x7a0ca137, 0x8e14f859, 0x893c13eb,
        0xee27a9ce, 0x35c961b7, 0xede51ce1, 0x3cb1477a, 0x59dfd29c, 0x3f73f255,
        0x79ce1418, 0xbf37c773, 0xeacdf753, 0x5baafd5f, 0x146f3ddf, 0x86db4478,
        0x81f3afca, 0x3ec468b9, 0x2c342438, 0x5f40a3c2, 0x72c31d16, 0xc25e2bc,
        0x8b493c28, 0x41950dff, 0x7101a839, 0xdeb30c08, 0x9ce4b4d8, 0x90c15664,
        0x6184cb7b, 0x70b632d5, 0x745c6c48, 0x4257b8d0
    ];

    return AES;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* AMCL BIG number class */
function BIG(ctx) {

    /* General purpose Constructor */
    var BIG = function(x) {
        this.w = new Array(BIG.NLEN);

        switch (typeof(x)) {
            case "object":
                this.copy(x);
                break;

            case "number":
                this.zero();
                this.w[0] = x;
                break;

            default:
                this.zero();
        }
    };

    BIG.CHUNK = 32;
    BIG.MODBYTES = ctx.config["@NB"];
    BIG.BASEBITS = ctx.config["@BASE"];
    BIG.NLEN = (1 + (Math.floor((8 * BIG.MODBYTES - 1) / BIG.BASEBITS)));
    BIG.DNLEN = 2 * BIG.NLEN;
    BIG.BMASK = (1 << BIG.BASEBITS) - 1;
    BIG.BIGBITS = (8 * BIG.MODBYTES);
    BIG.NEXCESS = (1 << (BIG.CHUNK - BIG.BASEBITS - 1));
    BIG.MODINV = (Math.pow(2, -BIG.BASEBITS));

    BIG.prototype = {
        /* set to zero */
        zero: function() {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] = 0;
            }

            return this;
        },

        /* set to one */
        one: function() {
            var i;

            this.w[0] = 1;
            for (i = 1; i < BIG.NLEN; i++) {
                this.w[i] = 0;
            }

            return this;
        },

        get: function(i) {
            return this.w[i];
        },

        set: function(i, x) {
            this.w[i] = x;
        },

        /* test for zero */
        iszilch: function() {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                if (this.w[i] !== 0) {
                    return false;
                }
            }

            return true;
        },

        /* test for unity */
        isunity: function() {
            var i;

            for (i = 1; i < BIG.NLEN; i++) {
                if (this.w[i] !== 0) {
                    return false;
                }
            }

            if (this.w[0] != 1) {
                return false;
            }

            return true;
        },

        /* Conditional swap of two BIGs depending on d using XOR - no branches */
        cswap: function(b, d) {
            var c = d,
                t, i;

            c = ~(c - 1);

            for (i = 0; i < BIG.NLEN; i++) {
                t = c & (this.w[i] ^ b.w[i]);
                this.w[i] ^= t;
                b.w[i] ^= t;
            }
        },

        /* Conditional move of BIG depending on d using XOR - no branches */
        cmove: function(b, d) {
            var c = d,
                i;

            c = ~(c - 1);

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] ^= (this.w[i] ^ b.w[i]) & c;
            }
        },

        /* copy from another BIG */
        copy: function(y) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] = y.w[i];
            }

            return this;
        },

        /* copy from bottom half of ctx.DBIG */
        hcopy: function(y) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] = y.w[i];
            }

            return this;
        },

        /* copy from ROM */
        rcopy: function(y) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] = y[i];
            }

            return this;
        },

        xortop: function(x) {
            this.w[BIG.NLEN - 1] ^= x;
        },

        ortop: function(x) {
            this.w[BIG.NLEN - 1] |= x;
        },

        /* normalise BIG - force all digits < 2^BASEBITS */
        norm: function() {
            var carry = 0,
                d, i;

            for (i = 0; i < BIG.NLEN - 1; i++) {
                d = this.w[i] + carry;
                this.w[i] = d & BIG.BMASK;
                carry = d >> BIG.BASEBITS;
            }

            this.w[BIG.NLEN - 1] = (this.w[BIG.NLEN - 1] + carry);

            return (this.w[BIG.NLEN - 1] >> ((8 * BIG.MODBYTES) % BIG.BASEBITS));
        },

        /* quick shift right by less than a word */
        fshr: function(k) {
            var r, i;

            /* shifted out part */
            r = this.w[0] & ((1 << k) - 1);

            for (i = 0; i < BIG.NLEN - 1; i++) {
                this.w[i] = (this.w[i] >> k) | ((this.w[i + 1] << (BIG.BASEBITS - k)) & BIG.BMASK);
            }

            this.w[BIG.NLEN - 1] = this.w[BIG.NLEN - 1] >> k;

            return r;
        },

        /* General shift right by k bits */
        shr: function(k) {
            var n = k % BIG.BASEBITS,
                m = Math.floor(k / BIG.BASEBITS),
                i;

            for (i = 0; i < BIG.NLEN - m - 1; i++) {
                this.w[i] = (this.w[m + i] >> n) | ((this.w[m + i + 1] << (BIG.BASEBITS - n)) & BIG.BMASK);
            }

            this.w[BIG.NLEN - m - 1] = this.w[BIG.NLEN - 1] >> n;

            for (i = BIG.NLEN - m; i < BIG.NLEN; i++) {
                this.w[i] = 0;
            }

            return this;
        },

        /* quick shift left by less than a word */
        fshl: function(k) {
            var i;

            this.w[BIG.NLEN - 1] = ((this.w[BIG.NLEN - 1] << k)) | (this.w[BIG.NLEN - 2] >> (BIG.BASEBITS - k));

            for (i = BIG.NLEN - 2; i > 0; i--) {
                this.w[i] = ((this.w[i] << k) & BIG.BMASK) | (this.w[i - 1] >> (BIG.BASEBITS - k));
            }

            this.w[0] = (this.w[0] << k) & BIG.BMASK;

            /* return excess - only used in ff.js */
            return (this.w[BIG.NLEN - 1] >> ((8 * BIG.MODBYTES) % BIG.BASEBITS));
        },

        /* General shift left by k bits */
        shl: function(k) {
            var n = k % BIG.BASEBITS,
                m = Math.floor(k / BIG.BASEBITS),
                i;

            this.w[BIG.NLEN - 1] = (this.w[BIG.NLEN - 1 - m] << n);

            if (BIG.NLEN > m + 2) {
                this.w[BIG.NLEN - 1] |= (this.w[BIG.NLEN - m - 2] >> (BIG.BASEBITS - n));
            }

            for (i = BIG.NLEN - 2; i > m; i--) {
                this.w[i] = ((this.w[i - m] << n) & BIG.BMASK) | (this.w[i - m - 1] >> (BIG.BASEBITS - n));
            }

            this.w[m] = (this.w[0] << n) & BIG.BMASK;

            for (i = 0; i < m; i++) {
                this.w[i] = 0;
            }

            return this;
        },

        /* return length in bits */
        nbits: function() {
            var k = BIG.NLEN - 1,
                bts, c;

            this.norm();

            while (k >= 0 && this.w[k] === 0) {
                k--;
            }

            if (k < 0) {
                return 0;
            }

            bts = BIG.BASEBITS * k;
            c = this.w[k];

            while (c !== 0) {
                c = Math.floor(c / 2);
                bts++;
            }

            return bts;
        },

        /* convert this to string */
        toString: function() {
            var s = "",
                len = this.nbits(),
                b, i;

            if (len % 4 === 0) {
                len = Math.floor(len / 4);
            } else {
                len = Math.floor(len / 4);
                len++;
            }

            if (len < BIG.MODBYTES * 2) {
                len = BIG.MODBYTES * 2;
            }

            for (i = len - 1; i >= 0; i--) {
                b = new BIG(0);
                b.copy(this);
                b.shr(i * 4);
                s += (b.w[0] & 15).toString(16);
            }

            return s;
        },

        /* this+=y */
        add: function(y) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] += y.w[i];
            }

            return this;
        },


        /* this|=y */
        or: function(y) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] |= y.w[i];
            }

            return this;
        },


        /* return this+x */
        plus: function(x) {
            var s = new BIG(0),
                i;

            for (i = 0; i < BIG.NLEN; i++) {
                s.w[i] = this.w[i] + x.w[i];
            }

            return s;
        },

        /* this+=i, where i is int */
        inc: function(i) {
            this.norm();
            this.w[0] += i;
            return this;
        },

        /* this-=y */
        sub: function(y) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] -= y.w[i];
            }

            return this;
        },

        /* reverse subtract this=x-this */
        rsub: function(x) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] = x.w[i] - this.w[i];
            }

            return this;
        },

        /* this-=i, where i is int */
        dec: function(i) {
            this.norm();
            this.w[0] -= i;
            return this;
        },

        /* return this-x */
        minus: function(x) {
            var d = new BIG(0),
                i;

            for (i = 0; i < BIG.NLEN; i++) {
                d.w[i] = this.w[i] - x.w[i];
            }

            return d;
        },

        /* multiply by small integer */
        imul: function(c) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] *= c;
            }

            return this;
        },

        /* convert this BIG to byte array */
        tobytearray: function(b, n) {
            var c = new BIG(0),
                i;

            this.norm();
            c.copy(this);

            for (i = BIG.MODBYTES - 1; i >= 0; i--) {
                b[i + n] = c.w[0] & 0xff;
                c.fshr(8);
            }

            return this;
        },

        /* convert this to byte array */
        toBytes: function(b) {
            this.tobytearray(b, 0);
        },

        /* set this[i]+=x*y+c, and return high part */
        muladd: function(x, y, c, i) {
            var prod = x * y + c + this.w[i];
            this.w[i] = prod & BIG.BMASK;
            return ((prod - this.w[i]) * BIG.MODINV);
        },

        /* multiply by larger int */
        pmul: function(c) {
            var carry = 0,
                ak, i;

            for (i = 0; i < BIG.NLEN; i++) {
                ak = this.w[i];
                this.w[i] = 0;
                carry = this.muladd(ak, c, carry, i);
            }

            return carry;
        },

        /* multiply by still larger int - results requires a ctx.DBIG */
        pxmul: function(c) {
            var m = new ctx.DBIG(0),
                carry = 0,
                j;

            for (j = 0; j < BIG.NLEN; j++) {
                carry = m.muladd(this.w[j], c, carry, j);
            }

            m.w[BIG.NLEN] = carry;

            return m;
        },

        /* divide by 3 */
        div3: function() {
            var carry = 0,
                ak, base, i;

            this.norm();
            base = (1 << BIG.BASEBITS);

            for (i = BIG.NLEN - 1; i >= 0; i--) {
                ak = (carry * base + this.w[i]);
                this.w[i] = Math.floor(ak / 3);
                carry = ak % 3;
            }
            return carry;
        },

        /* set x = x mod 2^m */
        mod2m: function(m) {
            var i, wd, bt, msk;

            wd = Math.floor(m / BIG.BASEBITS);
            bt = m % BIG.BASEBITS;
            msk = (1 << bt) - 1;
            this.w[wd] &= msk;

            for (i = wd + 1; i < BIG.NLEN; i++) {
                this.w[i] = 0;
            }
        },

        /* a=1/a mod 2^256. This is very fast! */
        invmod2m: function() {
            var U = new BIG(0),
                b = new BIG(0),
                c = new BIG(0),
                i, t1, t2;

            U.inc(BIG.invmod256(this.lastbits(8)));

            for (i = 8; i < BIG.BIGBITS; i <<= 1) {
                U.norm();
                b.copy(this);
                b.mod2m(i);
                t1 = BIG.smul(U, b);
                t1.shr(i);
                c.copy(this);
                c.shr(i);
                c.mod2m(i);

                t2 = BIG.smul(U, c);
                t2.mod2m(i);
                t1.add(t2);
                t1.norm();
                b = BIG.smul(t1, U);
                t1.copy(b);
                t1.mod2m(i);

                t2.one();
                t2.shl(i);
                t1.rsub(t2);
                t1.norm();
                t1.shl(i);
                U.add(t1);
            }

            U.mod2m(BIG.BIGBITS);
            this.copy(U);
            this.norm();
        },

        /* reduce this mod m */
        mod: function(m) {
            var k = 0,
                r = new BIG(0);

            this.norm();

            if (BIG.comp(this, m) < 0) {
                return;
            }

            do {
                m.fshl(1);
                k++;
            } while (BIG.comp(this, m) >= 0);

            while (k > 0) {
                m.fshr(1);

                r.copy(this);
                r.sub(m);
                r.norm();
                this.cmove(r, (1 - ((r.w[BIG.NLEN - 1] >> (BIG.CHUNK - 1)) & 1)));

                k--;
            }
        },
        /* this/=m */
        div: function(m) {
            var k = 0,
                d = 0,
                e = new BIG(1),
                b = new BIG(0),
                r = new BIG(0);

            this.norm();
            b.copy(this);
            this.zero();

            while (BIG.comp(b, m) >= 0) {
                e.fshl(1);
                m.fshl(1);
                k++;
            }

            while (k > 0) {
                m.fshr(1);
                e.fshr(1);

                r.copy(b);
                r.sub(m);
                r.norm();
                d = (1 - ((r.w[BIG.NLEN - 1] >> (BIG.CHUNK - 1)) & 1));
                b.cmove(r, d);
                r.copy(this);
                r.add(e);
                r.norm();
                this.cmove(r, d);

                k--;
            }
        },
        /* return parity of this */
        parity: function() {
            return this.w[0] % 2;
        },

        /* return n-th bit of this */
        bit: function(n) {
            if ((this.w[Math.floor(n / BIG.BASEBITS)] & (1 << (n % BIG.BASEBITS))) > 0) {
                return 1;
            } else {
                return 0;
            }
        },

        /* return last n bits of this */
        lastbits: function(n) {
            var msk = (1 << n) - 1;
            this.norm();
            return (this.w[0]) & msk;
        },

        isok: function() {
            var ok = true,
                i;

            for (i = 0; i < BIG.NLEN; i++) {
                if ((this.w[i] >> BIG.BASEBITS) != 0) {
                    ok = false;
                }
            }

            return ok;
        },

        /* Jacobi Symbol (this/p). Returns 0, 1 or -1 */
        jacobi: function(p) {
            var m = 0,
                t = new BIG(0),
                x = new BIG(0),
                n = new BIG(0),
                zilch = new BIG(0),
                one = new BIG(1),
                n8, k;

            if (p.parity() === 0 || BIG.comp(this, zilch) === 0 || BIG.comp(p, one) <= 0) {
                return 0;
            }

            this.norm();
            x.copy(this);
            n.copy(p);
            x.mod(p);

            while (BIG.comp(n, one) > 0) {
                if (BIG.comp(x, zilch) === 0) {
                    return 0;
                }

                n8 = n.lastbits(3);
                k = 0;

                while (x.parity() === 0) {
                    k++;
                    x.shr(1);
                }

                if (k % 2 == 1) {
                    m += (n8 * n8 - 1) / 8;
                }

                m += (n8 - 1) * (x.lastbits(2) - 1) / 4;
                t.copy(n);
                t.mod(x);
                n.copy(x);
                x.copy(t);
                m %= 2;
            }

            if (m === 0) {
                return 1;
            } else {
                return -1;
            }
        },

        /* this=1/this mod p. Binary method */
        invmodp: function(p) {
            var u = new BIG(0),
                v = new BIG(0),
                x1 = new BIG(1),
                x2 = new BIG(0),
                t = new BIG(0),
                one = new BIG(1);

            this.mod(p);
            u.copy(this);
            v.copy(p);

            while (BIG.comp(u, one) !== 0 && BIG.comp(v, one) !== 0) {
                while (u.parity() === 0) {
                    u.fshr(1);
                    if (x1.parity() !== 0) {
                        x1.add(p);
                        x1.norm();
                    }
                    x1.fshr(1);
                }

                while (v.parity() === 0) {
                    v.fshr(1);
                    if (x2.parity() !== 0) {
                        x2.add(p);
                        x2.norm();
                    }
                    x2.fshr(1);
                }

                if (BIG.comp(u, v) >= 0) {
                    u.sub(v);
                    u.norm();
                    if (BIG.comp(x1, x2) >= 0) {
                        x1.sub(x2);
                    } else {
                        t.copy(p);
                        t.sub(x2);
                        x1.add(t);
                    }
                    x1.norm();
                } else {
                    v.sub(u);
                    v.norm();
                    if (BIG.comp(x2, x1) >= 0) {
                        x2.sub(x1);
                    } else {
                        t.copy(p);
                        t.sub(x1);
                        x2.add(t);
                    }
                    x2.norm();
                }
            }

            if (BIG.comp(u, one) === 0) {
                this.copy(x1);
            } else {
                this.copy(x2);
            }
        },

        /* return this^e mod m */
        powmod: function(e, m) {
            var a = new BIG(1),
                z = new BIG(0),
                s = new BIG(0),
                bt;

            this.norm();
            e.norm();
            z.copy(e);
            s.copy(this);

            for (;;) {
                bt = z.parity();
                z.fshr(1);
                if (bt == 1) {
                    a = BIG.modmul(a, s, m);
                }

                if (z.iszilch()) {
                    break;
                }

                s = BIG.modsqr(s, m);
            }

            return a;
        }
    };

    /* convert from byte array to BIG */
    BIG.frombytearray = function(b, n) {
        var m = new BIG(0),
            i;

        for (i = 0; i < BIG.MODBYTES; i++) {
            m.fshl(8);
            m.w[0] += b[i + n] & 0xff;
        }

        return m;
    };

    BIG.fromBytes = function(b) {
        return BIG.frombytearray(b, 0);
    };

    /* return a*b where product fits a BIG */
    BIG.smul = function(a, b) {
        var c = new BIG(0),
            carry, i, j;

        for (i = 0; i < BIG.NLEN; i++) {
            carry = 0;

            for (j = 0; j < BIG.NLEN; j++) {
                if (i + j < BIG.NLEN) {
                    carry = c.muladd(a.w[i], b.w[j], carry, i + j);
                }
            }
        }

        return c;
    };

    /* Compare a and b, return 0 if a==b, -1 if a<b, +1 if a>b. Inputs must be normalised */
    BIG.comp = function(a, b) {
        var i;

        for (i = BIG.NLEN - 1; i >= 0; i--) {
            if (a.w[i] == b.w[i]) {
                continue;
            }

            if (a.w[i] > b.w[i]) {
                return 1;
            } else {
                return -1;
            }
        }

        return 0;
    };

    /* get 8*MODBYTES size random number */
    BIG.random = function(rng) {
        var m = new BIG(0),
            j = 0,
            r = 0,
            i, b;

        /* generate random BIG */
        for (i = 0; i < 8 * BIG.MODBYTES; i++) {
            if (j === 0) {
                r = rng.getByte();
            } else {
                r >>= 1;
            }

            b = r & 1;
            m.shl(1);
            m.w[0] += b;
            j++;
            j &= 7;
        }
        return m;
    };

    /* Create random BIG in portable way, one bit at a time */
    BIG.randomnum = function(q, rng) {
        var d = new ctx.DBIG(0),
            j = 0,
            r = 0,
            i, b, m;

        for (i = 0; i < 2 * q.nbits(); i++) {
            if (j === 0) {
                r = rng.getByte();
            } else {
                r >>= 1;
            }

            b = r & 1;
            d.shl(1);
            d.w[0] += b;
            j++;
            j &= 7;
        }

        m = d.mod(q);

        return m;
    };

    /* return a*b as ctx.DBIG */
    BIG.mul = function(a, b) {
        var c = new ctx.DBIG(0),
            d = [],
            n, s, t, i, k, co;

        for (i = 0; i < BIG.NLEN; i++) {
            d[i] = a.w[i] * b.w[i];
        }

        s = d[0];
        t = s;
        c.w[0] = t;

        for (k = 1; k < BIG.NLEN; k++) {
            s += d[k];
            t = s;
            for (i = k; i >= 1 + Math.floor(k / 2); i--) {
                t += (a.w[i] - a.w[k - i]) * (b.w[k - i] - b.w[i]);
            }
            c.w[k] = t;
        }
        for (k = BIG.NLEN; k < 2 * BIG.NLEN - 1; k++) {
            s -= d[k - BIG.NLEN];
            t = s;
            for (i = BIG.NLEN - 1; i >= 1 + Math.floor(k / 2); i--) {
                t += (a.w[i] - a.w[k - i]) * (b.w[k - i] - b.w[i]);
            }
            c.w[k] = t;
        }

        co = 0;
        for (i = 0; i < BIG.DNLEN - 1; i++) {
            n = c.w[i] + co;
            c.w[i] = n & BIG.BMASK;
            co = (n - c.w[i]) * BIG.MODINV;
        }
        c.w[BIG.DNLEN - 1] = co;

        return c;
    };

    /* return a^2 as ctx.DBIG */
    BIG.sqr = function(a) {
        var c = new ctx.DBIG(0),
            n, t, j, i, co;

        c.w[0] = a.w[0] * a.w[0];

        for (j = 1; j < BIG.NLEN - 1;) {
            t = a.w[j] * a.w[0];
            for (i = 1; i < (j + 1) >> 1; i++) {
                t += a.w[j - i] * a.w[i];
            }
            t += t;
            c.w[j] = t;
            j++;
            t = a.w[j] * a.w[0];
            for (i = 1; i < (j + 1) >> 1; i++) {
                t += a.w[j - i] * a.w[i];
            }
            t += t;
            t += a.w[j >> 1] * a.w[j >> 1];
            c.w[j] = t;
            j++;
        }

        for (j = BIG.NLEN - 1 + BIG.NLEN % 2; j < BIG.DNLEN - 3;) {
            t = a.w[BIG.NLEN - 1] * a.w[j - BIG.NLEN + 1];
            for (i = j - BIG.NLEN + 2; i < (j + 1) >> 1; i++) {
                t += a.w[j - i] * a.w[i];
            }
            t += t;
            c.w[j] = t;
            j++;
            t = a.w[BIG.NLEN - 1] * a.w[j - BIG.NLEN + 1];
            for (i = j - BIG.NLEN + 2; i < (j + 1) >> 1; i++) {
                t += a.w[j - i] * a.w[i];
            }
            t += t;
            t += a.w[j >> 1] * a.w[j >> 1];
            c.w[j] = t;
            j++;
        }

        t = a.w[BIG.NLEN - 2] * a.w[BIG.NLEN - 1];
        t += t;
        c.w[BIG.DNLEN - 3] = t;

        t = a.w[BIG.NLEN - 1] * a.w[BIG.NLEN - 1];
        c.w[BIG.DNLEN - 2] = t;

        co = 0;
        for (i = 0; i < BIG.DNLEN - 1; i++) {
            n = c.w[i] + co;
            c.w[i] = n & BIG.BMASK;
            co = (n - c.w[i]) * BIG.MODINV;
        }
        c.w[BIG.DNLEN - 1] = co;

        return c;
    };

    BIG.monty = function(m, nd, d) {
        var b = new BIG(0),
            v = [],
            dd = [],
            s, c, t, i, k;

        t = d.w[0];
        v[0] = ((t & BIG.BMASK) * nd) & BIG.BMASK;
        t += v[0] * m.w[0];
        c = d.w[1] + (t * BIG.MODINV);
        s = 0;

        for (k = 1; k < BIG.NLEN; k++) {
            t = c + s + v[0] * m.w[k];
            for (i = k - 1; i > Math.floor(k / 2); i--) {
                t += (v[k - i] - v[i]) * (m.w[i] - m.w[k - i]);
            }
            v[k] = ((t & BIG.BMASK) * nd) & BIG.BMASK;
            t += v[k] * m.w[0];
            c = (t * BIG.MODINV) + d.w[k + 1];

            dd[k] = v[k] * m.w[k];
            s += dd[k];
        }

        for (k = BIG.NLEN; k < 2 * BIG.NLEN - 1; k++) {
            t = c + s;
            for (i = BIG.NLEN - 1; i >= 1 + Math.floor(k / 2); i--) {
                t += (v[k - i] - v[i]) * (m.w[i] - m.w[k - i]);
            }
            b.w[k - BIG.NLEN] = t & BIG.BMASK;
            c = ((t - b.w[k - BIG.NLEN]) * BIG.MODINV) + d.w[k + 1];

            s -= dd[k - BIG.NLEN + 1];
        }

        b.w[BIG.NLEN - 1] = c & BIG.BMASK;

        return b;
    };

    /* return a*b mod m */
    BIG.modmul = function(a, b, m) {
        var d;

        a.mod(m);
        b.mod(m);
        d = BIG.mul(a, b);

        return d.mod(m);
    };

    /* return a^2 mod m */
    BIG.modsqr = function(a, m) {
        var d;

        a.mod(m);
        d = BIG.sqr(a);

        return d.mod(m);
    };

    /* return -a mod m */
    BIG.modneg = function(a, m) {
        a.mod(m);
        return m.minus(a);
    };

    /* Arazi and Qi inversion mod 256 */
    BIG.invmod256 = function(a) {
        var U, t1, t2, b, c;

        t1 = 0;
        c = (a >> 1) & 1;
        t1 += c;
        t1 &= 1;
        t1 = 2 - t1;
        t1 <<= 1;
        U = t1 + 1;

        // i=2
        b = a & 3;
        t1 = U * b;
        t1 >>= 2;
        c = (a >> 2) & 3;
        t2 = (U * c) & 3;
        t1 += t2;
        t1 *= U;
        t1 &= 3;
        t1 = 4 - t1;
        t1 <<= 2;
        U += t1;

        // i=4
        b = a & 15;
        t1 = U * b;
        t1 >>= 4;
        c = (a >> 4) & 15;
        t2 = (U * c) & 15;
        t1 += t2;
        t1 *= U;
        t1 &= 15;
        t1 = 16 - t1;
        t1 <<= 4;
        U += t1;

        return U;
    };
    return BIG;
}

/* AMCL double length DBIG number class */
function DBIG(ctx) {

    /* constructor */
    var DBIG = function(x) {
        this.w = [];
        this.zero();
        this.w[0] = x;
    };

    DBIG.prototype = {

        /* set this=0 */
        zero: function() {
            for (var i = 0; i < ctx.BIG.DNLEN; i++) {
                this.w[i] = 0;
            }
            return this;
        },

        /* set this=b */
        copy: function(b) {
            for (var i = 0; i < ctx.BIG.DNLEN; i++) {
                this.w[i] = b.w[i];
            }
            return this;
        },


        /* copy from ctx.BIG */
        hcopy: function(b) {
            var i;

            for (i = 0; i < ctx.BIG.NLEN; i++) {
                this.w[i] = b.w[i];
            }

            for (i = ctx.BIG.NLEN; i < ctx.BIG.DNLEN; i++) {
                this.w[i] = 0;
            }

            return this;
        },

        ucopy: function(b) {
            var i;

            for (i = 0; i < ctx.BIG.NLEN; i++) {
                this.w[i] = 0;
            }

            for (i = ctx.BIG.NLEN; i < ctx.BIG.DNLEN; i++) {
                this.w[i] = b.w[i - ctx.BIG.NLEN];
            }

            return this;
        },

        /* normalise this */
        norm: function() {
            var carry = 0,
                d, i;

            for (i = 0; i < ctx.BIG.DNLEN - 1; i++) {
                d = this.w[i] + carry;
                this.w[i] = d & ctx.BIG.BMASK;
                carry = d >> ctx.BIG.BASEBITS;
            }
            this.w[ctx.BIG.DNLEN - 1] = (this.w[ctx.BIG.DNLEN - 1] + carry);

            return this;
        },

        /* set this[i]+=x*y+c, and return high part */
        muladd: function(x, y, c, i) {
            var prod = x * y + c + this.w[i];
            this.w[i] = prod & ctx.BIG.BMASK;
            return ((prod - this.w[i]) * ctx.BIG.MODINV);
        },

        /* shift this right by k bits */
        shr: function(k) {
            var n = k % ctx.BIG.BASEBITS,
                m = Math.floor(k / ctx.BIG.BASEBITS),
                i;

            for (i = 0; i < ctx.BIG.DNLEN - m - 1; i++) {
                this.w[i] = (this.w[m + i] >> n) | ((this.w[m + i + 1] << (ctx.BIG.BASEBITS - n)) & ctx.BIG.BMASK);
            }

            this.w[ctx.BIG.DNLEN - m - 1] = this.w[ctx.BIG.DNLEN - 1] >> n;

            for (i = ctx.BIG.DNLEN - m; i < ctx.BIG.DNLEN; i++) {
                this.w[i] = 0;
            }

            return this;
        },

        /* shift this left by k bits */
        shl: function(k) {
            var n = k % ctx.BIG.BASEBITS,
                m = Math.floor(k / ctx.BIG.BASEBITS),
                i;

            this.w[ctx.BIG.DNLEN - 1] = ((this.w[ctx.BIG.DNLEN - 1 - m] << n)) | (this.w[ctx.BIG.DNLEN - m - 2] >> (ctx.BIG.BASEBITS - n));

            for (i = ctx.BIG.DNLEN - 2; i > m; i--) {
                this.w[i] = ((this.w[i - m] << n) & ctx.BIG.BMASK) | (this.w[i - m - 1] >> (ctx.BIG.BASEBITS - n));
            }

            this.w[m] = (this.w[0] << n) & ctx.BIG.BMASK;

            for (i = 0; i < m; i++) {
                this.w[i] = 0;
            }

            return this;
        },

        /* Conditional move of ctx.BIG depending on d using XOR - no branches */
        cmove: function(b, d) {
            var c = d,
                i;

            c = ~(c - 1);

            for (i = 0; i < ctx.BIG.DNLEN; i++) {
                this.w[i] ^= (this.w[i] ^ b.w[i]) & c;
            }
        },

        /* this+=x */
        add: function(x) {
            for (var i = 0; i < ctx.BIG.DNLEN; i++) {
                this.w[i] += x.w[i];
            }
        },

        /* this-=x */
        sub: function(x) {
            for (var i = 0; i < ctx.BIG.DNLEN; i++) {
                this.w[i] -= x.w[i];
            }
        },

        rsub: function(x) {
            for (var i = 0; i < ctx.BIG.DNLEN; i++) {
                this.w[i] = x.w[i] - this.w[i];
            }
        },

        /* return number of bits in this */
        nbits: function() {
            var k = ctx.BIG.DNLEN - 1,
                bts, c;

            this.norm();

            while (k >= 0 && this.w[k] === 0) {
                k--;
            }

            if (k < 0) {
                return 0;
            }

            bts = ctx.BIG.BASEBITS * k;
            c = this.w[k];

            while (c !== 0) {
                c = Math.floor(c / 2);
                bts++;
            }

            return bts;
        },

        /* convert this to string */
        toString: function() {
            var s = "",
                len = this.nbits(),
                b, i;

            if (len % 4 === 0) {
                len = Math.floor(len / 4);
            } else {
                len = Math.floor(len / 4);
                len++;
            }

            for (i = len - 1; i >= 0; i--) {
                b = new DBIG(0);
                b.copy(this);
                b.shr(i * 4);
                s += (b.w[0] & 15).toString(16);
            }

            return s;
        },

        /* reduces this DBIG mod a ctx.BIG, and returns the ctx.BIG */
        mod: function(c) {
            var k = 0,
                m = new DBIG(0),
                dr = new DBIG(0),
                r = new ctx.BIG(0);

            this.norm();
            m.hcopy(c);
            r.hcopy(this);

            if (DBIG.comp(this, m) < 0) {
                return r;
            }

            do {
                m.shl(1);
                k++;
            } while (DBIG.comp(this, m) >= 0);

            while (k > 0) {
                m.shr(1);

                dr.copy(this);
                dr.sub(m);
                dr.norm();
                this.cmove(dr, (1 - ((dr.w[ctx.BIG.DNLEN - 1] >> (ctx.BIG.CHUNK - 1)) & 1)));

                k--;
            }

            r.hcopy(this);

            return r;
        },

        /* this/=c */
        div: function(c) {
            var d = 0,
                k = 0,
                m = new DBIG(0),
                dr = new DBIG(0),
                r = new ctx.BIG(0),
                a = new ctx.BIG(0),
                e = new ctx.BIG(1);

            m.hcopy(c);
            this.norm();

            while (DBIG.comp(this, m) >= 0) {
                e.fshl(1);
                m.shl(1);
                k++;
            }

            while (k > 0) {
                m.shr(1);
                e.shr(1);

                dr.copy(this);
                dr.sub(m);
                dr.norm();
                d = (1 - ((dr.w[ctx.BIG.DNLEN - 1] >> (ctx.BIG.CHUNK - 1)) & 1));
                this.cmove(dr, d);
                r.copy(a);
                r.add(e);
                r.norm();
                a.cmove(r, d);

                k--;
            }
            return a;
        },

        /* split this DBIG at position n, return higher half, keep lower half */
        split: function(n) {
            var t = new ctx.BIG(0),
                m = n % ctx.BIG.BASEBITS,
                carry = this.w[ctx.BIG.DNLEN - 1] << (ctx.BIG.BASEBITS - m),
                nw, i;

            for (i = ctx.BIG.DNLEN - 2; i >= ctx.BIG.NLEN - 1; i--) {
                nw = (this.w[i] >> m) | carry;
                carry = (this.w[i] << (ctx.BIG.BASEBITS - m)) & ctx.BIG.BMASK;
                t.w[i - ctx.BIG.NLEN + 1] = nw;
            }

            this.w[ctx.BIG.NLEN - 1] &= ((1 << m) - 1);

            return t;
        }

    };

    /* Compare a and b, return 0 if a==b, -1 if a<b, +1 if a>b. Inputs must be normalised */
    DBIG.comp = function(a, b) {
        var i;

        for (i = ctx.BIG.DNLEN - 1; i >= 0; i--) {
            if (a.w[i] == b.w[i]) {
                continue;
            }

            if (a.w[i] > b.w[i]) {
                return 1;
            } else {
                return -1;
            }
        }

        return 0;
    };

    return DBIG;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

function ECDH(ctx) {

    var ECDH = {

        INVALID_PUBLIC_KEY: -2,
        ERROR: -3,
        INVALID: -4,
        EFS: ctx.BIG.MODBYTES,
        EGS: ctx.BIG.MODBYTES,
        SHA256: 32,
        SHA384: 48,
        SHA512: 64,

        /* Convert Integer to n-byte array */
        inttobytes: function(n, len) {
            var b = [],
                i;

            for (i = 0; i < len; i++) {
                b[i] = 0;
            }

            i = len;
            while (n > 0 && i > 0) {
                i--;
                b[i] = (n & 0xff);
                n = Math.floor(n / 256);
            }

            return b;
        },

        bytestostring: function(b) {
            var s = "",
                len = b.length,
                ch, i;

            for (i = 0; i < len; i++) {
                ch = b[i];
                s += String.fromCharCode(ch);
            }

            return s;
        },

        stringtobytes: function(s) {
            var b = [],
                i;

            for (i = 0; i < s.length; i++) {
                b.push(s.charCodeAt(i));
            }

            return b;
        },

        hashit: function(sha, A, n, B, pad) {
            var R = [],
                H, W, i;

            if (sha == this.SHA256) {
                H = new ctx.HASH256();
            } else if (sha == this.SHA384) {
                H = new ctx.HASH384();
            } else if (sha == this.SHA512) {
                H = new ctx.HASH512();
            }

            if (n > 0) {
                H.process_num(n);
            }
            if (B != null) {
                H.process_array(B);
            }
            R = H.hash();

            if (R.length == 0) {
                return null;
            }

            if (pad == 0) {
                return R;
            }

            W = [];

            if (sha >= pad) {
                for (i = 0; i < pad; i++) {
                    W[i] = R[i];
                }
            } else {
                for (i = 0; i < sha; i++) {
                    W[i + pad - sha] = R[i];
                }

                for (i = 0; i < pad - sha; i++) {
                    W[i] = 0;
                }
            }

            return W;
        },

        KDF1: function(sha, Z, olen) {
            /* NOTE: the parameter olen is the length of the output K in bytes */
            var hlen = sha,
                K = [],
                B = [],
                k = 0,
                counter, cthreshold, i;

            for (i = 0; i < K.length; i++) {
                K[i] = 0; // redundant?
            }

            cthreshold = Math.floor(olen / hlen);
            if (olen % hlen !== 0) {
                cthreshold++;
            }

            for (counter = 0; counter < cthreshold; counter++) {
                B = this.hashit(sha, Z, counter, null, 0);

                if (k + hlen > olen) {
                    for (i = 0; i < olen % hlen; i++) {
                        K[k++] = B[i];
                    }
                } else {
                    for (i = 0; i < hlen; i++) {
                        K[k++] = B[i];
                    }
                }
            }

            return K;
        },

        KDF2: function(sha, Z, P, olen) {
            /* NOTE: the parameter olen is the length of the output k in bytes */
            var hlen = sha,
                K = [],
                B = [],
                k = 0,
                counter, cthreshold, i;

            for (i = 0; i < K.length; i++) {
                K[i] = 0; // redundant?
            }

            cthreshold = Math.floor(olen / hlen);
            if (olen % hlen !== 0) {
                cthreshold++;
            }

            for (counter = 1; counter <= cthreshold; counter++) {
                B = this.hashit(sha, Z, counter, P, 0);

                if (k + hlen > olen) {
                    for (i = 0; i < olen % hlen; i++) {
                        K[k++] = B[i];
                    }
                } else {
                    for (i = 0; i < hlen; i++) {
                        K[k++] = B[i];
                    }
                }
            }

            return K;
        },

        /* Password based Key Derivation Function */
        /* Input password p, salt s, and repeat count */
        /* Output key of length olen */

        PBKDF2: function(sha, Pass, Salt, rep, olen) {
            var F = new Array(sha),
                U = [],
                S = [],
                K = [],
                opt = 0,
                i, j, k, d, N, key;

            d = Math.floor(olen / sha);

            if (olen % sha !== 0) {
                d++;
            }

            opt = 0;

            for (i = 1; i <= d; i++) {
                for (j = 0; j < Salt.length; j++) {
                    S[j] = Salt[j];
                }

                N = this.inttobytes(i, 4);

                for (j = 0; j < 4; j++) {
                    S[Salt.length + j] = N[j];
                }

                this.HMAC(sha, S, Pass, F);

                for (j = 0; j < sha; j++) {
                    U[j] = F[j];
                }

                for (j = 2; j <= rep; j++) {
                    this.HMAC(sha, U, Pass, U);
                    for (k = 0; k < sha; k++) {
                        F[k] ^= U[k];
                    }
                }

                for (j = 0; j < sha; j++) {
                    K[opt++] = F[j];
                }
            }

            key = [];
            for (i = 0; i < olen; i++) {
                key[i] = K[i];
            }

            return key;
        },

        HMAC: function(sha, M, K, tag) {
            /* Input is from an octet m        *
             * olen is requested output length in bytes. k is the key  *
             * The output is the calculated tag */
            var olen = tag.length,
                B = [],
                b = 64,
                K0, i;

            if (sha > 32) {
                b = 128;
            }

            K0 = new Array(b);

            if (olen < 4) {
                return 0;
            }

            for (i = 0; i < b; i++) {
                K0[i] = 0;
            }

            if (K.length > b) {
                B = this.hashit(sha, K, 0, null, 0);
                for (i = 0; i < sha; i++) {
                    K0[i] = B[i];
                }
            } else {
                for (i = 0; i < K.length; i++) {
                    K0[i] = K[i];
                }
            }

            for (i = 0; i < b; i++) {
                K0[i] ^= 0x36;
            }

            B = this.hashit(sha, K0, 0, M, 0);

            for (i = 0; i < b; i++) {
                K0[i] ^= 0x6a;
            }

            B = this.hashit(sha, K0, 0, B, olen);

            for (i = 0; i < olen; i++) {
                tag[i] = B[i];
            }

            return 1;
        },

        /* ctx.AES encryption/decryption */

        AES_CBC_IV0_ENCRYPT: function(K, M) { /* ctx.AES CBC encryption, with Null IV and key K */
            /* Input is from an octet string M, output is to an octet string C */
            /* Input is padded as necessary to make up a full final block */
            var a = new ctx.AES(),
                buff = [],
                C = [],
                fin, padlen, i, j, ipt, opt;

            a.init(ctx.AES.CBC, K.length, K, null);

            ipt = opt = 0;
            fin = false;

            for (;;) {
                for (i = 0; i < 16; i++) {
                    if (ipt < M.length) {
                        buff[i] = M[ipt++];
                    } else {
                        fin = true;
                        break;
                    }
                }

                if (fin) {
                    break;
                }

                a.encrypt(buff);

                for (i = 0; i < 16; i++) {
                    C[opt++] = buff[i];
                }
            }

            /* last block, filled up to i-th index */

            padlen = 16 - i;
            for (j = i; j < 16; j++) {
                buff[j] = padlen;
            }
            a.encrypt(buff);
            for (i = 0; i < 16; i++) {
                C[opt++] = buff[i];
            }
            a.end();

            return C;
        },

        AES_CBC_IV0_DECRYPT: function(K, C) { /* padding is removed */
            var a = new ctx.AES(),
                buff = [],
                MM = [],
                ipt = 0,
                opt = 0,
                M, ch, fin, bad, padlen, i;

            a.init(ctx.AES.CBC, K.length, K, null);

            if (C.length === 0) {
                return [];
            }
            ch = C[ipt++];

            fin = false;

            for (;;) {
                for (i = 0; i < 16; i++) {
                    buff[i] = ch;
                    if (ipt >= C.length) {
                        fin = true;
                        break;
                    } else {
                        ch = C[ipt++];
                    }
                }
                a.decrypt(buff);
                if (fin) {
                    break;
                }

                for (i = 0; i < 16; i++) {
                    MM[opt++] = buff[i];
                }
            }

            a.end();
            bad = false;
            padlen = buff[15];

            if (i != 15 || padlen < 1 || padlen > 16) {
                bad = true;
            }

            if (padlen >= 2 && padlen <= 16) {
                for (i = 16 - padlen; i < 16; i++) {
                    if (buff[i] != padlen) {
                        bad = true;
                    }
                }
            }

            if (!bad) {
                for (i = 0; i < 16 - padlen; i++) {
                    MM[opt++] = buff[i];
                }
            }

            M = [];
            if (bad) {
                return M;
            }

            for (i = 0; i < opt; i++) {
                M[i] = MM[i];
            }

            return M;
        },

        KEY_PAIR_GENERATE: function(RNG, S, W) {
            var res = 0,
                r, s, G, WP;

            G = ctx.ECP.generator();

            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (RNG === null) {
                s = ctx.BIG.fromBytes(S);
                s.mod(r);
            } else {
                s = ctx.BIG.randomnum(r, RNG);
            }

            s.toBytes(S);

            WP = G.mul(s);
            WP.toBytes(W,false);

            return res;
        },

        PUBLIC_KEY_VALIDATE: function(W) {
            var WP = ctx.ECP.fromBytes(W),
                res = 0,
                r, q, nb, k;

            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (WP.is_infinity()) {
                res = this.INVALID_PUBLIC_KEY;
            }

            if (res === 0) {
                q = new ctx.BIG(0);
                q.rcopy(ctx.ROM_FIELD.Modulus);
                nb = q.nbits();
                k = new ctx.BIG(1);
                k.shl(Math.floor((nb + 4) / 2));
                k.add(q);
                k.div(r);

                while (k.parity() == 0) {
                    k.shr(1);
                    WP.dbl();
                }

                if (!k.isunity()) {
                    WP = WP.mul(k);
                }

                if (WP.is_infinity()) {
                    res = this.INVALID_PUBLIC_KEY;
                }
            }

            return res;
        },

        ECPSVDP_DH: function(S, WD, Z) {
            var T = [],
                res = 0,
                r, s, i,
                W;

            s = ctx.BIG.fromBytes(S);

            W = ctx.ECP.fromBytes(WD);
            if (W.is_infinity()) {
                res = this.ERROR;
            }

            if (res === 0) {
                r = new ctx.BIG(0);
                r.rcopy(ctx.ROM_CURVE.CURVE_Order);
                s.mod(r);
                W = W.mul(s);

                if (W.is_infinity()) {
                    res = this.ERROR;
                } else {
                    W.getX().toBytes(T);
                    for (i = 0; i < this.EFS; i++) {
                        Z[i] = T[i];
                    }
                }
            }

            return res;
        },

        ECPSP_DSA: function(sha, RNG, S, F, C, D) {
            var T = [],
                i, r, s, f, c, d, u, vx, w,
                G, V, B;

            B = this.hashit(sha, F, 0, null, ctx.BIG.MODBYTES);

            G = ctx.ECP.generator();

            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            s = ctx.BIG.fromBytes(S);
            f = ctx.BIG.fromBytes(B);

            c = new ctx.BIG(0);
            d = new ctx.BIG(0);
            V = new ctx.ECP();

            do {
                u = ctx.BIG.randomnum(r, RNG);
                w = ctx.BIG.randomnum(r, RNG);
                V.copy(G);
                V = V.mul(u);
                vx = V.getX();
                c.copy(vx);
                c.mod(r);
                if (c.iszilch()) {
                    continue;
                }
                u = ctx.BIG.modmul(u, w, r);
                u.invmodp(r);
                d = ctx.BIG.modmul(s, c, r);
                d.add(f);
                d = ctx.BIG.modmul(d, w, r);
                d = ctx.BIG.modmul(u, d, r);
            } while (d.iszilch());

            c.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                C[i] = T[i];
            }
            d.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                D[i] = T[i];
            }

            return 0;
        },

        ECPVP_DSA: function(sha, W, F, C, D) {
            var B = [],
                res = 0,
                r, f, c, d, h2,
                G, WP, P;

            B = this.hashit(sha, F, 0, null, ctx.BIG.MODBYTES);

            G = ctx.ECP.generator();

            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            c = ctx.BIG.fromBytes(C);
            d = ctx.BIG.fromBytes(D);
            f = ctx.BIG.fromBytes(B);

            if (c.iszilch() || ctx.BIG.comp(c, r) >= 0 || d.iszilch() || ctx.BIG.comp(d, r) >= 0) {
                res = this.INVALID;
            }

            if (res === 0) {
                d.invmodp(r);
                f = ctx.BIG.modmul(f, d, r);
                h2 = ctx.BIG.modmul(c, d, r);

                WP = ctx.ECP.fromBytes(W);
                if (WP.is_infinity()) {
                    res = this.ERROR;
                } else {
                    P = new ctx.ECP();
                    P.copy(WP);
                    P = P.mul2(h2, G, f);

                    if (P.is_infinity()) {
                        res = this.INVALID;
                    } else {
                        d = P.getX();
                        d.mod(r);
                        if (ctx.BIG.comp(d, c) !== 0) {
                            res = this.INVALID;
                        }
                    }
                }
            }

            return res;
        },

        ECIES_ENCRYPT: function(sha, P1, P2, RNG, W, M, V, T) {
            var Z = [],
                VZ = [],
                K1 = [],
                K2 = [],
                U = [],
                C = [],
                K, L2, AC, i;

            if (this.KEY_PAIR_GENERATE(RNG, U, V) !== 0) {
                return C;
            }

            if (this.ECPSVDP_DH(U, W, Z) !== 0) {
                return C;
            }

            for (i = 0; i < 2 * this.EFS + 1; i++) {
                VZ[i] = V[i];
            }

            for (i = 0; i < this.EFS; i++) {
                VZ[2 * this.EFS + 1 + i] = Z[i];
            }

            K = this.KDF2(sha, VZ, P1, 2*ctx.ECP.AESKEY);

            for (i = 0; i < ctx.ECP.AESKEY; i++) {
                K1[i] = K[i];
                K2[i] = K[ctx.ECP.AESKEY + i];
            }

            C = this.AES_CBC_IV0_ENCRYPT(K1, M);

            L2 = this.inttobytes(P2.length, 8);

            AC = [];
            for (i = 0; i < C.length; i++) {
                AC[i] = C[i];
            }
            for (i = 0; i < P2.length; i++) {
                AC[C.length + i] = P2[i];
            }
            for (i = 0; i < 8; i++) {
                AC[C.length + P2.length + i] = L2[i];
            }

            this.HMAC(sha, AC, K2, T);

            return C;
        },

        ECIES_DECRYPT: function(sha, P1, P2, V, C, T, U) {
            var Z = [],
                VZ = [],
                K1 = [],
                K2 = [],
                TAG = new Array(T.length),
                M = [],
                K, L2, AC, same, i;

            if (this.ECPSVDP_DH(U, V, Z) !== 0) {
                return M;
            }

            for (i = 0; i < 2 * this.EFS + 1; i++) {
                VZ[i] = V[i];
            }

            for (i = 0; i < this.EFS; i++) {
                VZ[2 * this.EFS + 1 + i] = Z[i];
            }

            K = this.KDF2(sha, VZ, P1, 2*ctx.ECP.AESKEY);

            for (i = 0; i < ctx.ECP.AESKEY; i++) {
                K1[i] = K[i];
                K2[i] = K[ctx.ECP.AESKEY + i];
            }

            M = this.AES_CBC_IV0_DECRYPT(K1, C);

            if (M.length === 0) {
                return M;
            }

            L2 = this.inttobytes(P2.length, 8);

            AC = [];

            for (i = 0; i < C.length; i++) {
                AC[i] = C[i];
            }
            for (i = 0; i < P2.length; i++) {
                AC[C.length + i] = P2[i];
            }
            for (i = 0; i < 8; i++) {
                AC[C.length + P2.length + i] = L2[i];
            }

            this.HMAC(sha, AC, K2, TAG);

            same = true;
            for (i = 0; i < T.length; i++) {
                if (T[i] != TAG[i]) {
                    same = false;
                }
            }

            if (!same) {
                return [];
            }

            return M;
        }
    };

    return ECDH;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* Elliptic Curve Point class */

function ECP(ctx) {

    /* Constructor */
    var ECP = function() {
        this.x = new ctx.FP(0);
        this.y = new ctx.FP(1);
        if (ECP.CURVETYPE != ECP.EDWARDS) {
            this.z = new ctx.FP(0);
        } else {
            this.z = new ctx.FP(1);
        }
    };

    ECP.WEIERSTRASS = 0;
    ECP.EDWARDS = 1;
    ECP.MONTGOMERY = 2;
    ECP.NOT = 0;
    ECP.BN = 1;
    ECP.BLS = 2;
    ECP.D_TYPE = 0;
    ECP.M_TYPE = 1;
    ECP.POSITIVEX = 0;
    ECP.NEGATIVEX = 1;

    ECP.CURVETYPE = ctx.config["@CT"];
    ECP.CURVE_PAIRING_TYPE = ctx.config["@PF"];
    ECP.SEXTIC_TWIST = ctx.config["@ST"];
    ECP.SIGN_OF_X = ctx.config["@SX"];

    ECP.HASH_TYPE = ctx.config["@HT"];
    ECP.AESKEY = ctx.config["@AK"];

    ECP.prototype = {
        /* test this=O point-at-infinity */
        is_infinity: function() {
            this.x.reduce();
            this.z.reduce();

            if (ECP.CURVETYPE == ECP.EDWARDS) {
                this.y.reduce();
                return (this.x.iszilch() && this.y.equals(this.z));
            } else if (ECP.CURVETYPE == ECP.WEIERSTRASS) {
                this.y.reduce();
                return (this.x.iszilch() && this.z.iszilch());
            } else if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                return (this.z.iszilch());
            }

            return true;
        },

        /* conditional swap of this and Q dependant on d */
        cswap: function(Q, d) {
            this.x.cswap(Q.x, d);
            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                this.y.cswap(Q.y, d);
            }
            this.z.cswap(Q.z, d);
        },

        /* conditional move of Q to P dependant on d */
        cmove: function(Q, d) {
            this.x.cmove(Q.x, d);
            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                this.y.cmove(Q.y, d);
            }
            this.z.cmove(Q.z, d);
        },

        /* Constant time select from pre-computed table */
        select: function(W, b) {
            var MP = new ECP(),
                m = b >> 31,
                babs = (b ^ m) - m;

            babs = (babs - 1) / 2;

            this.cmove(W[0], ECP.teq(babs, 0)); // conditional move
            this.cmove(W[1], ECP.teq(babs, 1));
            this.cmove(W[2], ECP.teq(babs, 2));
            this.cmove(W[3], ECP.teq(babs, 3));
            this.cmove(W[4], ECP.teq(babs, 4));
            this.cmove(W[5], ECP.teq(babs, 5));
            this.cmove(W[6], ECP.teq(babs, 6));
            this.cmove(W[7], ECP.teq(babs, 7));

            MP.copy(this);
            MP.neg();
            this.cmove(MP, (m & 1));
        },

        /* Test P == Q */

        equals: function(Q) {
            var a, b;

            a = new ctx.FP(0);
            b = new ctx.FP(0);
            a.copy(this.x);
            a.mul(Q.z);
            a.reduce();
            b.copy(Q.x);
            b.mul(this.z);
            b.reduce();

            if (!a.equals(b)) {
                return false;
            }

            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                a.copy(this.y);
                a.mul(Q.z);
                a.reduce();
                b.copy(Q.y);
                b.mul(this.z);
                b.reduce();
                if (!a.equals(b)) {
                    return false;
                }
            }

            return true;
        },

        /* copy this=P */
        copy: function(P) {
            this.x.copy(P.x);
            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                this.y.copy(P.y);
            }
            this.z.copy(P.z);
        },

        /* this=-this */
        neg: function() {
            if (ECP.CURVETYPE == ECP.WEIERSTRASS) {
                this.y.neg();
                this.y.norm();
            } else if (ECP.CURVETYPE == ECP.EDWARDS) {
                this.x.neg();
                this.x.norm();
            }

            return;
        },

        /* set this=O */
        inf: function() {
            this.x.zero();

            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                this.y.one();
            }

            if (ECP.CURVETYPE != ECP.EDWARDS) {
                this.z.zero();
            } else {
                this.z.one();
            }
        },

        /* set this=(x,y) where x and y are BIGs */
        setxy: function(ix, iy) {
            var rhs, y2;

            this.x = new ctx.FP(0);
            this.x.bcopy(ix);

            this.y = new ctx.FP(0);
            this.y.bcopy(iy);
            this.z = new ctx.FP(1);
            rhs = ECP.RHS(this.x);

            if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                if (rhs.jacobi() != 1) {
                    this.inf();
                }
            } else {
                y2 = new ctx.FP(0);
                y2.copy(this.y);
                y2.sqr();

                if (!y2.equals(rhs)) {
                    this.inf();
                }
            }
        },

        /* set this=x, where x is ctx.BIG, y is derived from sign s */
        setxi: function(ix, s) {
            var rhs, ny;

            this.x = new ctx.FP(0);
            this.x.bcopy(ix);
            rhs = ECP.RHS(this.x);
            this.z = new ctx.FP(1);

            if (rhs.jacobi() == 1) {
                ny = rhs.sqrt();
                if (ny.redc().parity() != s) {
                    ny.neg();
                }
                this.y = ny;
            } else {
                this.inf();
            }
        },

        /* set this=x, y calculated from curve equation */
        setx: function(ix) {
            var rhs;

            this.x = new ctx.FP(0);
            this.x.bcopy(ix);
            rhs = ECP.RHS(this.x);
            this.z = new ctx.FP(1);

            if (rhs.jacobi() == 1) {
                if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                    this.y = rhs.sqrt();
                }
            } else {
                this.inf();
            }
        },

        /* set this to affine - from (x,y,z) to (x,y) */
        affine: function() {
            var one;

            if (this.is_infinity()) {
                return;
            }

            one = new ctx.FP(1);

            if (this.z.equals(one)) {
                return;
            }

            this.z.inverse();

            if (ECP.CURVETYPE == ECP.EDWARDS || ECP.CURVETYPE == ECP.WEIERSTRASS) {
                this.x.mul(this.z);
                this.x.reduce();
                this.y.mul(this.z);
                this.y.reduce();
                this.z = one;
            }
            if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                this.x.mul(this.z);
                this.x.reduce();
                this.z = one;
            }
        },

        /* extract x as ctx.BIG */
        getX: function() {
            this.affine();
            return this.x.redc();
        },

        /* extract y as ctx.BIG */
        getY: function() {
            this.affine();
            return this.y.redc();
        },

        /* get sign of Y */
        getS: function() {
            this.affine();
            var y = this.getY();
            return y.parity();
        },

        /* extract x as ctx.FP */
        getx: function() {
            return this.x;
        },

        /* extract y as ctx.FP */
        gety: function() {
            return this.y;
        },

        /* extract z as ctx.FP */
        getz: function() {
            return this.z;
        },

        /* convert to byte array */
        toBytes: function(b) {
            var t = [],
                i;

            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                b[0] = 0x04;
            } else {
                b[0] = 0x02;
            }

            this.affine();
            this.x.redc().toBytes(t);

            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 1] = t[i];
            }

            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                this.y.redc().toBytes(t);
                for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                    b[i + ctx.BIG.MODBYTES + 1] = t[i];
                }
            }
        },
        /* convert to hex string */
        toString: function() {
            if (this.is_infinity()) {
                return "infinity";
            }

            this.affine();

            if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                return "(" + this.x.redc().toString() + ")";
            } else {
                return "(" + this.x.redc().toString() + "," + this.y.redc().toString() + ")";
            }
        },

        /* this+=this */
        dbl: function() {
            var t0, t1, t2, t3, x3, y3, z3, b,
                C, D, H, J,
                A, B, AA, BB;

            if (ECP.CURVETYPE == ECP.WEIERSTRASS) {

                if (ctx.ROM_CURVE.CURVE_A == 0) {
                    t0 = new ctx.FP(0);
                    t0.copy(this.y);
                    t0.sqr();
                    t1 = new ctx.FP(0);
                    t1.copy(this.y);
                    t1.mul(this.z);
                    t2 = new ctx.FP(0);
                    t2.copy(this.z);
                    t2.sqr();

                    this.z.copy(t0);
                    this.z.add(t0);
                    this.z.norm();
                    this.z.add(this.z);
                    this.z.add(this.z);
                    this.z.norm();

                    t2.imul(3 * ctx.ROM_CURVE.CURVE_B_I);

                    x3 = new ctx.FP(0);
                    x3.copy(t2);
                    x3.mul(this.z);
                    y3 = new ctx.FP(0);
                    y3.copy(t0);
                    y3.add(t2);
                    y3.norm();
                    this.z.mul(t1);
                    t1.copy(t2);
                    t1.add(t2);
                    t2.add(t1);
                    t0.sub(t2);
                    t0.norm();
                    y3.mul(t0);
                    y3.add(x3);
                    t1.copy(this.x);
                    t1.mul(this.y);
                    this.x.copy(t0);
                    this.x.norm();
                    this.x.mul(t1);
                    this.x.add(this.x);

                    this.x.norm();
                    this.y.copy(y3);
                    this.y.norm();
                } else {
                    t0 = new ctx.FP(0);
                    t0.copy(this.x);
                    t1 = new ctx.FP(0);
                    t1.copy(this.y);
                    t2 = new ctx.FP(0);
                    t2.copy(this.z);
                    t3 = new ctx.FP(0);
                    t3.copy(this.x);
                    z3 = new ctx.FP(0);
                    z3.copy(this.z);
                    y3 = new ctx.FP(0);
                    x3 = new ctx.FP(0);
                    b = new ctx.FP(0);
                    if (ctx.ROM_CURVE.CURVE_B_I == 0) {
                        b.rcopy(ctx.ROM_CURVE.CURVE_B);
                    }
                    t0.sqr(); //1    x^2
                    t1.sqr(); //2    y^2
                    t2.sqr(); //3

                    t3.mul(this.y); //4
                    t3.add(t3);
                    t3.norm(); //5
                    z3.mul(this.x); //6
                    z3.add(z3);
                    z3.norm(); //7
                    y3.copy(t2);

                    if (ctx.ROM_CURVE.CURVE_B_I == 0) {
                        y3.mul(b); //8
                    } else {
                        y3.imul(ctx.ROM_CURVE.CURVE_B_I);
                    }

                    y3.sub(z3); //9  ***
                    x3.copy(y3);
                    x3.add(y3);
                    x3.norm(); //10

                    y3.add(x3); //11
                    x3.copy(t1);
                    x3.sub(y3);
                    x3.norm(); //12
                    y3.add(t1);
                    y3.norm(); //13
                    y3.mul(x3); //14
                    x3.mul(t3); //15
                    t3.copy(t2);
                    t3.add(t2); //16
                    t2.add(t3); //17

                    if (ctx.ROM_CURVE.CURVE_B_I == 0) {
                        z3.mul(b); //18
                    } else {
                        z3.imul(ctx.ROM_CURVE.CURVE_B_I);
                    }

                    z3.sub(t2); //19
                    z3.sub(t0);
                    z3.norm(); //20  ***
                    t3.copy(z3);
                    t3.add(z3); //21

                    z3.add(t3);
                    z3.norm(); //22
                    t3.copy(t0);
                    t3.add(t0); //23
                    t0.add(t3); //24
                    t0.sub(t2);
                    t0.norm(); //25

                    t0.mul(z3); //26
                    y3.add(t0); //27
                    t0.copy(this.y);
                    t0.mul(this.z); //28
                    t0.add(t0);
                    t0.norm(); //29
                    z3.mul(t0); //30
                    x3.sub(z3); //31
                    t0.add(t0);
                    t0.norm(); //32
                    t1.add(t1);
                    t1.norm(); //33
                    z3.copy(t0);
                    z3.mul(t1); //34
                    this.x.copy(x3);
                    this.x.norm();
                    this.y.copy(y3);
                    this.y.norm();
                    this.z.copy(z3);
                    this.z.norm();
                }
            }

            if (ECP.CURVETYPE == ECP.EDWARDS) {
                C = new ctx.FP(0);
                C.copy(this.x);
                D = new ctx.FP(0);
                D.copy(this.y);
                H = new ctx.FP(0);
                H.copy(this.z);
                J = new ctx.FP(0);
                this.x.mul(this.y);
                this.x.add(this.x);
                this.x.norm();
                C.sqr();
                D.sqr();
                if (ctx.ROM_CURVE.CURVE_A == -1) {
                    C.neg();
                }

                this.y.copy(C);
                this.y.add(D);
                this.y.norm();
                H.sqr();
                H.add(H);

                this.z.copy(this.y);
                J.copy(this.y);

                J.sub(H);
                J.norm();

                this.x.mul(J);
                C.sub(D);
                C.norm();
                this.y.mul(C);
                this.z.mul(J);
            }

            if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                A = new ctx.FP(0);
                A.copy(this.x);
                B = new ctx.FP(0);
                B.copy(this.x);
                AA = new ctx.FP(0);
                BB = new ctx.FP(0);
                C = new ctx.FP(0);

                A.add(this.z);
                A.norm();
                AA.copy(A);
                AA.sqr();
                B.sub(this.z);
                B.norm();
                BB.copy(B);
                BB.sqr();
                C.copy(AA);
                C.sub(BB);
                C.norm();
                this.x.copy(AA);
                this.x.mul(BB);

                A.copy(C);
                A.imul((ctx.ROM_CURVE.CURVE_A + 2) >> 2);

                BB.add(A);
                BB.norm();
                this.z.copy(BB);
                this.z.mul(C);
            }

            return;
        },

        /* this+=Q */
        add: function(Q) {
            var b, t0, t1, t2, t3, t4, x3, y3, z3,
                A, B, C, D, E, F, G;

            if (ECP.CURVETYPE == ECP.WEIERSTRASS) {
                if (ctx.ROM_CURVE.CURVE_A == 0) {

                    b = 3 * ctx.ROM_CURVE.CURVE_B_I;
                    t0 = new ctx.FP(0);
                    t0.copy(this.x);
                    t0.mul(Q.x);
                    t1 = new ctx.FP(0);
                    t1.copy(this.y);
                    t1.mul(Q.y);
                    t2 = new ctx.FP(0);
                    t2.copy(this.z);
                    t2.mul(Q.z);
                    t3 = new ctx.FP(0);
                    t3.copy(this.x);
                    t3.add(this.y);
                    t3.norm();
                    t4 = new ctx.FP(0);
                    t4.copy(Q.x);
                    t4.add(Q.y);
                    t4.norm();
                    t3.mul(t4);
                    t4.copy(t0);
                    t4.add(t1);

                    t3.sub(t4);
                    t3.norm();
                    t4.copy(this.y);
                    t4.add(this.z);
                    t4.norm();
                    x3 = new ctx.FP(0);
                    x3.copy(Q.y);
                    x3.add(Q.z);
                    x3.norm();

                    t4.mul(x3);
                    x3.copy(t1);
                    x3.add(t2);

                    t4.sub(x3);
                    t4.norm();
                    x3.copy(this.x);
                    x3.add(this.z);
                    x3.norm();
                    y3 = new ctx.FP(0);
                    y3.copy(Q.x);
                    y3.add(Q.z);
                    y3.norm();
                    x3.mul(y3);
                    y3.copy(t0);
                    y3.add(t2);
                    y3.rsub(x3);
                    y3.norm();
                    x3.copy(t0);
                    x3.add(t0);
                    t0.add(x3);
                    t0.norm();
                    t2.imul(b);

                    z3 = new ctx.FP(0);
                    z3.copy(t1);
                    z3.add(t2);
                    z3.norm();
                    t1.sub(t2);
                    t1.norm();
                    y3.imul(b);

                    x3.copy(y3);
                    x3.mul(t4);
                    t2.copy(t3);
                    t2.mul(t1);
                    x3.rsub(t2);
                    y3.mul(t0);
                    t1.mul(z3);
                    y3.add(t1);
                    t0.mul(t3);
                    z3.mul(t4);
                    z3.add(t0);

                    this.x.copy(x3);
                    this.x.norm();
                    this.y.copy(y3);
                    this.y.norm();
                    this.z.copy(z3);
                    this.z.norm();
                } else {
                    t0 = new ctx.FP(0);
                    t0.copy(this.x);
                    t1 = new ctx.FP(0);
                    t1.copy(this.y);
                    t2 = new ctx.FP(0);
                    t2.copy(this.z);
                    t3 = new ctx.FP(0);
                    t3.copy(this.x);
                    t4 = new ctx.FP(0);
                    t4.copy(Q.x);
                    z3 = new ctx.FP(0);
                    y3 = new ctx.FP(0);
                    y3.copy(Q.x);
                    x3 = new ctx.FP(0);
                    x3.copy(Q.y);
                    b = new ctx.FP(0);

                    if (ctx.ROM_CURVE.CURVE_B_I == 0) {
                        b.rcopy(ctx.ROM_CURVE.CURVE_B);
                    }
                    t0.mul(Q.x); //1
                    t1.mul(Q.y); //2
                    t2.mul(Q.z); //3

                    t3.add(this.y);
                    t3.norm(); //4
                    t4.add(Q.y);
                    t4.norm(); //5
                    t3.mul(t4); //6
                    t4.copy(t0);
                    t4.add(t1); //7
                    t3.sub(t4);
                    t3.norm(); //8
                    t4.copy(this.y);
                    t4.add(this.z);
                    t4.norm(); //9
                    x3.add(Q.z);
                    x3.norm(); //10
                    t4.mul(x3); //11
                    x3.copy(t1);
                    x3.add(t2); //12

                    t4.sub(x3);
                    t4.norm(); //13
                    x3.copy(this.x);
                    x3.add(this.z);
                    x3.norm(); //14
                    y3.add(Q.z);
                    y3.norm(); //15

                    x3.mul(y3); //16
                    y3.copy(t0);
                    y3.add(t2); //17

                    y3.rsub(x3);
                    y3.norm(); //18
                    z3.copy(t2);

                    if (ctx.ROM_CURVE.CURVE_B_I == 0) {
                        z3.mul(b); //18
                    } else {
                        z3.imul(ctx.ROM_CURVE.CURVE_B_I);
                    }

                    x3.copy(y3);
                    x3.sub(z3);
                    x3.norm(); //20
                    z3.copy(x3);
                    z3.add(x3); //21

                    x3.add(z3); //22
                    z3.copy(t1);
                    z3.sub(x3);
                    z3.norm(); //23
                    x3.add(t1);
                    x3.norm(); //24

                    if (ctx.ROM_CURVE.CURVE_B_I == 0) {
                        y3.mul(b); //18
                    } else {
                        y3.imul(ctx.ROM_CURVE.CURVE_B_I);
                    }

                    t1.copy(t2);
                    t1.add(t2); //26
                    t2.add(t1); //27

                    y3.sub(t2); //28

                    y3.sub(t0);
                    y3.norm(); //29
                    t1.copy(y3);
                    t1.add(y3); //30
                    y3.add(t1);
                    y3.norm(); //31

                    t1.copy(t0);
                    t1.add(t0); //32
                    t0.add(t1); //33
                    t0.sub(t2);
                    t0.norm(); //34
                    t1.copy(t4);
                    t1.mul(y3); //35
                    t2.copy(t0);
                    t2.mul(y3); //36
                    y3.copy(x3);
                    y3.mul(z3); //37
                    y3.add(t2); //38
                    x3.mul(t3); //39
                    x3.sub(t1); //40
                    z3.mul(t4); //41
                    t1.copy(t3);
                    t1.mul(t0); //42
                    z3.add(t1);
                    this.x.copy(x3);
                    this.x.norm();
                    this.y.copy(y3);
                    this.y.norm();
                    this.z.copy(z3);
                    this.z.norm();
                }
            }

            if (ECP.CURVETYPE == ECP.EDWARDS) {
                A = new ctx.FP(0);
                A.copy(this.z);
                B = new ctx.FP(0);
                C = new ctx.FP(0);
                C.copy(this.x);
                D = new ctx.FP(0);
                D.copy(this.y);
                E = new ctx.FP(0);
                F = new ctx.FP(0);
                G = new ctx.FP(0);

                A.mul(Q.z); //A=2
                B.copy(A);
                B.sqr(); //B=2
                C.mul(Q.x); //C=2
                D.mul(Q.y); //D=2

                E.copy(C);
                E.mul(D); //E=2

                if (ctx.ROM_CURVE.CURVE_B_I == 0) {
                    b = new ctx.FP(0);
                    b.rcopy(ctx.ROM_CURVE.CURVE_B);
                    E.mul(b);
                } else {
                    E.imul(ctx.ROM_CURVE.CURVE_B_I); //E=22222
                }

                F.copy(B);
                F.sub(E); //F=22224
                G.copy(B);
                G.add(E); //G=22224

                if (ctx.ROM_CURVE.CURVE_A == 1) {
                    E.copy(D);
                    E.sub(C); //E=4
                }
                C.add(D); //C=4

                B.copy(this.x);
                B.add(this.y); //B=4
                D.copy(Q.x);
                D.add(Q.y);
                B.norm();
                D.norm(); //D=4
                B.mul(D); //B=2
                B.sub(C);
                B.norm();
                F.norm(); // B=6
                B.mul(F); //B=2
                this.x.copy(A);
                this.x.mul(B);
                G.norm(); // x=2

                if (ctx.ROM_CURVE.CURVE_A == 1) {
                    E.norm();
                    C.copy(E);
                    C.mul(G); //C=2
                }

                if (ctx.ROM_CURVE.CURVE_A == -1) {
                    C.norm();
                    C.mul(G);
                }

                this.y.copy(A);
                this.y.mul(C); //y=2
                this.z.copy(F);
                this.z.mul(G);
            }

            return;
        },

        /* Differential Add for Montgomery curves. this+=Q where W is this-Q and is affine. */
        dadd: function(Q, W) {
            var A, B, C, D, DA, CB;

            A = new ctx.FP(0);
            A.copy(this.x);
            B = new ctx.FP(0);
            B.copy(this.x);
            C = new ctx.FP(0);
            C.copy(Q.x);
            D = new ctx.FP(0);
            D.copy(Q.x);
            DA = new ctx.FP(0);
            CB = new ctx.FP(0);

            A.add(this.z);
            B.sub(this.z);

            C.add(Q.z);
            D.sub(Q.z);

            D.norm();
            A.norm();
            DA.copy(D);
            DA.mul(A);
            C.norm();
            B.norm();
            CB.copy(C);
            CB.mul(B);

            A.copy(DA);
            A.add(CB);
            A.norm();
            A.sqr();
            B.copy(DA);
            B.sub(CB);
            B.norm();
            B.sqr();

            this.x.copy(A);
            this.z.copy(W.x);
            this.z.mul(B);
        },

        /* this-=Q */
        sub: function(Q) {
            Q.neg();
            this.add(Q);
            Q.neg();
        },

        /* constant time multiply by small integer of length bts - use ladder */
        pinmul: function(e, bts) {
            var i, b, P, R0, R1;

            if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                return this.mul(new ctx.BIG(e));
            } else {
                P = new ECP();
                R0 = new ECP();
                R1 = new ECP();
                R1.copy(this);

                for (i = bts - 1; i >= 0; i--) {
                    b = (e >> i) & 1;
                    P.copy(R1);
                    P.add(R0);
                    R0.cswap(R1, b);
                    R1.copy(P);
                    R0.dbl();
                    R0.cswap(R1, b);
                }

                P.copy(R0);
                P.affine();

                return P;
            }
        },

        // multiply this by the curves cofactor
        cfp: function() {
            var cf=ctx.ROM_CURVE.CURVE_Cof_I,
                c = new ctx.BIG(0);
            if (cf==1) {
                return;
            }
            if (cf==4) {
                this.dbl(); this.dbl();
                this.affine();
                return;
            }
            if (cf==8) {
                this.dbl(); this.dbl(); this.dbl();
                this.affine();
                return;
            }
            c.rcopy(ctx.ROM_CURVE.CURVE_Cof);
            this.copy(this.mul(c));
        },


        /* return e.this - SPA immune, using Ladder */
        mul: function(e) {
            var P, D, R0, R1, mt, t, Q, C, W, w,
                i, b, nb, s, ns;

            if (e.iszilch() || this.is_infinity()) {
                return new ECP();
            }

            P = new ECP();

            if (ECP.CURVETYPE == ECP.MONTGOMERY) { /* use ladder */
                D = new ECP();
                R0 = new ECP();
                R0.copy(this);
                R1 = new ECP();
                R1.copy(this);
                R1.dbl();
                D.copy(this);
                D.affine();
                nb = e.nbits();
                for (i = nb - 2; i >= 0; i--) {
                    b = e.bit(i);
                    P.copy(R1);
                    P.dadd(R0, D);

                    R0.cswap(R1, b);
                    R1.copy(P);
                    R0.dbl();
                    R0.cswap(R1, b);
                }
                P.copy(R0);
            } else {
                // fixed size windows
                mt = new ctx.BIG();
                t = new ctx.BIG();
                Q = new ECP();
                C = new ECP();
                W = [];
                w = [];

                this.affine();

                // precompute table
                Q.copy(this);
                Q.dbl();
                W[0] = new ECP();
                W[0].copy(this);

                for (i = 1; i < 8; i++) {
                    W[i] = new ECP();
                    W[i].copy(W[i - 1]);
                    W[i].add(Q);
                }

                // make exponent odd - add 2P if even, P if odd
                t.copy(e);
                s = t.parity();
                t.inc(1);
                t.norm();
                ns = t.parity();
                mt.copy(t);
                mt.inc(1);
                mt.norm();
                t.cmove(mt, s);
                Q.cmove(this, ns);
                C.copy(Q);

                nb = 1 + Math.floor((t.nbits() + 3) / 4);

                // convert exponent to signed 4-bit window
                for (i = 0; i < nb; i++) {
                    w[i] = (t.lastbits(5) - 16);
                    t.dec(w[i]);
                    t.norm();
                    t.fshr(4);
                }
                w[nb] = t.lastbits(5);

                P.copy(W[Math.floor((w[nb] - 1) / 2)]);
                for (i = nb - 1; i >= 0; i--) {
                    Q.select(W, w[i]);
                    P.dbl();
                    P.dbl();
                    P.dbl();
                    P.dbl();
                    P.add(Q);
                }
                P.sub(C);
            }

            P.affine();

            return P;
        },

        /* Return e.this+f.Q */

        mul2: function(e, Q, f) {
            var te = new ctx.BIG(),
                tf = new ctx.BIG(),
                mt = new ctx.BIG(),
                S = new ECP(),
                T = new ECP(),
                C = new ECP(),
                W = [],
                w = [],
                i, s, ns, nb,
                a, b;

            this.affine();
            Q.affine();

            te.copy(e);
            tf.copy(f);

            // precompute table
            W[1] = new ECP();
            W[1].copy(this);
            W[1].sub(Q);
            W[2] = new ECP();
            W[2].copy(this);
            W[2].add(Q);
            S.copy(Q);
            S.dbl();
            W[0] = new ECP();
            W[0].copy(W[1]);
            W[0].sub(S);
            W[3] = new ECP();
            W[3].copy(W[2]);
            W[3].add(S);
            T.copy(this);
            T.dbl();
            W[5] = new ECP();
            W[5].copy(W[1]);
            W[5].add(T);
            W[6] = new ECP();
            W[6].copy(W[2]);
            W[6].add(T);
            W[4] = new ECP();
            W[4].copy(W[5]);
            W[4].sub(S);
            W[7] = new ECP();
            W[7].copy(W[6]);
            W[7].add(S);

            // if multiplier is odd, add 2, else add 1 to multiplier, and add 2P or P to correction

            s = te.parity();
            te.inc(1);
            te.norm();
            ns = te.parity();
            mt.copy(te);
            mt.inc(1);
            mt.norm();
            te.cmove(mt, s);
            T.cmove(this, ns);
            C.copy(T);

            s = tf.parity();
            tf.inc(1);
            tf.norm();
            ns = tf.parity();
            mt.copy(tf);
            mt.inc(1);
            mt.norm();
            tf.cmove(mt, s);
            S.cmove(Q, ns);
            C.add(S);

            mt.copy(te);
            mt.add(tf);
            mt.norm();
            nb = 1 + Math.floor((mt.nbits() + 1) / 2);

            // convert exponent to signed 2-bit window
            for (i = 0; i < nb; i++) {
                a = (te.lastbits(3) - 4);
                te.dec(a);
                te.norm();
                te.fshr(2);
                b = (tf.lastbits(3) - 4);
                tf.dec(b);
                tf.norm();
                tf.fshr(2);
                w[i] = (4 * a + b);
            }
            w[nb] = (4 * te.lastbits(3) + tf.lastbits(3));
            S.copy(W[Math.floor((w[nb] - 1) / 2)]);

            for (i = nb - 1; i >= 0; i--) {
                T.select(W, w[i]);
                S.dbl();
                S.dbl();
                S.add(T);
            }
            S.sub(C); /* apply correction */
            S.affine();

            return S;
        }
    };

    // set to group generator
    ECP.generator = function() {
        var G=new ECP(),
            gx = new ctx.BIG(0),
            gy = new ctx.BIG(0);

        gx.rcopy(ctx.ROM_CURVE.CURVE_Gx);

        if (ctx.ECP.CURVETYPE != ctx.ECP.MONTGOMERY) {
            gy.rcopy(ctx.ROM_CURVE.CURVE_Gy);
            G.setxy(gx, gy);
        } else {
            G.setx(gx);
        }
        return G;
    };

    /* return 1 if b==c, no branching */
    ECP.teq = function(b, c) {
        var x = b ^ c;
        x -= 1; // if x=0, x now -1
        return ((x >> 31) & 1);
    };

    /* convert from byte array to ECP */
    ECP.fromBytes = function(b) {
        var t = [],
            P = new ECP(),
            p = new ctx.BIG(0),
            px, py, i;

        p.rcopy(ctx.ROM_FIELD.Modulus);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 1];
        }

        px = ctx.BIG.fromBytes(t);
        if (ctx.BIG.comp(px, p) >= 0) {
            return P;
        }

        if (b[0] == 0x04) {
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                t[i] = b[i + ctx.BIG.MODBYTES + 1];
            }

            py = ctx.BIG.fromBytes(t);

            if (ctx.BIG.comp(py, p) >= 0) {
                return P;
            }

            P.setxy(px, py);

            return P;
        } else {
            P.setx(px);
            return P;
        }
    };

    /* Calculate RHS of curve equation */
    ECP.RHS = function(x) {
        var r = new ctx.FP(0),
            b, cx, one, x3;

        x.norm();
        r.copy(x);
        r.sqr();

        if (ECP.CURVETYPE == ECP.WEIERSTRASS) { // x^3+Ax+B
            b = new ctx.FP(0);
            b.rcopy(ctx.ROM_CURVE.CURVE_B);
            r.mul(x);
            if (ctx.ROM_CURVE.CURVE_A == -3) {
                cx = new ctx.FP(0);
                cx.copy(x);
                cx.imul(3);
                cx.neg();
                cx.norm();
                r.add(cx);
            }
            r.add(b);
        } else if (ECP.CURVETYPE == ECP.EDWARDS) { // (Ax^2-1)/(Bx^2-1)
            b = new ctx.FP(0);
            b.rcopy(ctx.ROM_CURVE.CURVE_B);

            one = new ctx.FP(1);
            b.mul(r);
            b.sub(one);
            b.norm();
            if (ctx.ROM_CURVE.CURVE_A == -1) {
                r.neg();
            }
            r.sub(one);
            r.norm();
            b.inverse();

            r.mul(b);
        } else if (ECP.CURVETYPE == ECP.MONTGOMERY) { // x^3+Ax^2+x
            x3 = new ctx.FP(0);
            x3.copy(r);
            x3.mul(x);
            r.imul(ctx.ROM_CURVE.CURVE_A);
            r.add(x3);
            r.add(x);
        }

        r.reduce();

        return r;
    };

    ECP.mapit = function(h) {
        var q = new ctx.BIG(0),
            x = ctx.BIG.fromBytes(h),
            P = new ECP();

        q.rcopy(ctx.ROM_FIELD.Modulus);
        x.mod(q);

        for (;;) {
            for (;;) {
                if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                    P.setxi(x,0);
                } else {
                    P.setx(x);
                }
                x.inc(1); x.norm();
                if (!P.is_infinity()){
                    break;
                }

            }
            P.cfp();
            if (!P.is_infinity()) {
                break;
            }
        }
        return P;
    };

    return ECP;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* AMCL Weierstrass elliptic curve functions over ctx.FP2 */

function ECP2(ctx) {

    /* Constructor, set this=O */
    var ECP2 = function() {
        this.x = new ctx.FP2(0);
        this.y = new ctx.FP2(1);
        this.z = new ctx.FP2(0);
    };

    ECP2.prototype = {
        /* Test this=O? */
        is_infinity: function() {
            this.x.reduce();
            this.y.reduce();
            this.z.reduce();
            return (this.x.iszilch() && this.z.iszilch());
        },

        /* copy this=P */
        copy: function(P) {
            this.x.copy(P.x);
            this.y.copy(P.y);
            this.z.copy(P.z);
        },

        /* set this=O */
        inf: function() {
            this.x.zero();
            this.y.one();
            this.z.zero();
        },

        /* conditional move of Q to P dependant on d */
        cmove: function(Q, d) {
            this.x.cmove(Q.x, d);
            this.y.cmove(Q.y, d);
            this.z.cmove(Q.z, d);
        },

        /* Constant time select from pre-computed table */
        select: function(W, b) {
            var MP = new ECP2(),
                m, babs;

            m = b >> 31,
            babs = (b ^ m) - m;
            babs = (babs - 1) / 2;

            this.cmove(W[0], ECP2.teq(babs, 0)); // conditional move
            this.cmove(W[1], ECP2.teq(babs, 1));
            this.cmove(W[2], ECP2.teq(babs, 2));
            this.cmove(W[3], ECP2.teq(babs, 3));
            this.cmove(W[4], ECP2.teq(babs, 4));
            this.cmove(W[5], ECP2.teq(babs, 5));
            this.cmove(W[6], ECP2.teq(babs, 6));
            this.cmove(W[7], ECP2.teq(babs, 7));

            MP.copy(this);
            MP.neg();
            this.cmove(MP, (m & 1));
        },

        /* Test P == Q */
        equals: function(Q) {
            var a, b;

            a = new ctx.FP2(0);
            a.copy(this.x);
            b = new ctx.FP2(0);
            b.copy(Q.x);

            a.copy(this.x);
            a.mul(Q.z);
            a.reduce();
            b.copy(Q.x);
            b.mul(this.z);
            b.reduce();
            if (!a.equals(b)) {
                return false;
            }

            a.copy(this.y);
            a.mul(Q.z);
            a.reduce();
            b.copy(Q.y);
            b.mul(this.z);
            b.reduce();
            if (!a.equals(b)) {
                return false;
            }

            return true;
        },

        /* set this=-this */
        neg: function() {
            this.y.norm();
            this.y.neg();
            this.y.norm();
            return;
        },

        /* convert this to affine, from (x,y,z) to (x,y) */
        affine: function() {
            var one;

            if (this.is_infinity()) {
                return;
            }

            one = new ctx.FP2(1);

            if (this.z.equals(one)) {
                this.x.reduce();
                this.y.reduce();
                return;
            }

            this.z.inverse();

            this.x.mul(this.z);
            this.x.reduce();
            this.y.mul(this.z);
            this.y.reduce();
            this.z.copy(one);
        },

        /* extract affine x as ctx.FP2 */
        getX: function() {
            this.affine();
            return this.x;
        },

        /* extract affine y as ctx.FP2 */
        getY: function() {
            this.affine();
            return this.y;
        },

        /* extract projective x */
        getx: function() {
            return this.x;
        },

        /* extract projective y */
        gety: function() {
            return this.y;
        },

        /* extract projective z */
        getz: function() {
            return this.z;
        },

        /* convert this to byte array */
        toBytes: function(b) {
            var t = [],
                i;

            this.affine();
            this.x.getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i] = t[i];
            }
            this.x.getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + ctx.BIG.MODBYTES] = t[i];
            }

            this.y.getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 2 * ctx.BIG.MODBYTES] = t[i];
            }
            this.y.getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 3 * ctx.BIG.MODBYTES] = t[i];
            }
        },

        /* convert this to hex string */
        toString: function() {
            if (this.is_infinity()) {
                return "infinity";
            }
            this.affine();
            return "(" + this.x.toString() + "," + this.y.toString() + ")";
        },

        /* set this=(x,y) */
        setxy: function(ix, iy) {
            var rhs, y2;

            this.x.copy(ix);
            this.y.copy(iy);
            this.z.one();

            rhs = ECP2.RHS(this.x);

            y2 = new ctx.FP2(this.y);
            y2.sqr();

            if (!y2.equals(rhs)) {
                this.inf();
            }
        },

        /* set this=(x,.) */
        setx: function(ix) {
            var rhs;

            this.x.copy(ix);
            this.z.one();

            rhs = ECP2.RHS(this.x);

            if (rhs.sqrt()) {
                this.y.copy(rhs);
            } else {
                this.inf();
            }
        },

        /* set this*=q, where q is Modulus, using Frobenius */
        frob: function(X) {
            var X2;

            X2 = new ctx.FP2(X);
            X2.sqr();
            this.x.conj();
            this.y.conj();
            this.z.conj();
            this.z.reduce();
            this.x.mul(X2);
            this.y.mul(X2);
            this.y.mul(X);
        },

        /* this+=this */
        dbl: function() {
            var iy, t0, t1, t2, x3, y3;

            iy = new ctx.FP2(0);
            iy.copy(this.y);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                iy.mul_ip();
                iy.norm();
            }

            t0 = new ctx.FP2(0);
            t0.copy(this.y);
            t0.sqr();
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t0.mul_ip();
            }
            t1 = new ctx.FP2(0);
            t1.copy(iy);
            t1.mul(this.z);
            t2 = new ctx.FP2(0);
            t2.copy(this.z);
            t2.sqr();

            this.z.copy(t0);
            this.z.add(t0);
            this.z.norm();
            this.z.add(this.z);
            this.z.add(this.z);
            this.z.norm();

            t2.imul(3 * ctx.ROM_CURVE.CURVE_B_I);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                t2.mul_ip();
                t2.norm();
            }

            x3 = new ctx.FP2(0);
            x3.copy(t2);
            x3.mul(this.z);

            y3 = new ctx.FP2(0);
            y3.copy(t0);

            y3.add(t2);
            y3.norm();
            this.z.mul(t1);
            t1.copy(t2);
            t1.add(t2);
            t2.add(t1);
            t2.norm();
            t0.sub(t2);
            t0.norm(); //y^2-9bz^2
            y3.mul(t0);
            y3.add(x3); //(y^2+3z*2)(y^2-9z^2)+3b.z^2.8y^2
            t1.copy(this.x);
            t1.mul(iy);
            this.x.copy(t0);
            this.x.norm();
            this.x.mul(t1);
            this.x.add(this.x); //(y^2-9bz^2)xy2

            this.x.norm();
            this.y.copy(y3);
            this.y.norm();

            return 1;
        },

        /* this+=Q - return 0 for add, 1 for double, -1 for O */
        /* this+=Q */
        add: function(Q) {
            var b, t0, t1, t2, t3, t4, x3, y3, z3;

            b = 3 * ctx.ROM_CURVE.CURVE_B_I;
            t0 = new ctx.FP2(0);
            t0.copy(this.x);
            t0.mul(Q.x); // x.Q.x
            t1 = new ctx.FP2(0);
            t1.copy(this.y);
            t1.mul(Q.y); // y.Q.y

            t2 = new ctx.FP2(0);
            t2.copy(this.z);
            t2.mul(Q.z);
            t3 = new ctx.FP2(0);
            t3.copy(this.x);
            t3.add(this.y);
            t3.norm(); //t3=X1+Y1
            t4 = new ctx.FP2(0);
            t4.copy(Q.x);
            t4.add(Q.y);
            t4.norm(); //t4=X2+Y2
            t3.mul(t4); //t3=(X1+Y1)(X2+Y2)
            t4.copy(t0);
            t4.add(t1); //t4=X1.X2+Y1.Y2

            t3.sub(t4);
            t3.norm();
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t3.mul_ip();
                t3.norm(); //t3=(X1+Y1)(X2+Y2)-(X1.X2+Y1.Y2) = X1.Y2+X2.Y1
            }

            t4.copy(this.y);
            t4.add(this.z);
            t4.norm(); //t4=Y1+Z1
            x3 = new ctx.FP2(0);
            x3.copy(Q.y);
            x3.add(Q.z);
            x3.norm(); //x3=Y2+Z2

            t4.mul(x3); //t4=(Y1+Z1)(Y2+Z2)
            x3.copy(t1); //
            x3.add(t2); //X3=Y1.Y2+Z1.Z2

            t4.sub(x3);
            t4.norm();
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t4.mul_ip();
                t4.norm(); //t4=(Y1+Z1)(Y2+Z2) - (Y1.Y2+Z1.Z2) = Y1.Z2+Y2.Z1
            }

            x3.copy(this.x);
            x3.add(this.z);
            x3.norm(); // x3=X1+Z1
            y3 = new ctx.FP2(0);
            y3.copy(Q.x);
            y3.add(Q.z);
            y3.norm(); // y3=X2+Z2
            x3.mul(y3); // x3=(X1+Z1)(X2+Z2)
            y3.copy(t0);
            y3.add(t2); // y3=X1.X2+Z1+Z2
            y3.rsub(x3);
            y3.norm(); // y3=(X1+Z1)(X2+Z2) - (X1.X2+Z1.Z2) = X1.Z2+X2.Z1

            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t0.mul_ip();
                t0.norm(); // x.Q.x
                t1.mul_ip();
                t1.norm(); // y.Q.y
            }

            x3.copy(t0);
            x3.add(t0);
            t0.add(x3);
            t0.norm();
            t2.imul(b);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                t2.mul_ip();
            }

            z3 = new ctx.FP2(0);
            z3.copy(t1);
            z3.add(t2);
            z3.norm();
            t1.sub(t2);
            t1.norm();
            y3.imul(b);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                y3.mul_ip();
                y3.norm();
            }

            x3.copy(y3);
            x3.mul(t4);
            t2.copy(t3);
            t2.mul(t1);
            x3.rsub(t2);
            y3.mul(t0);
            t1.mul(z3);
            y3.add(t1);
            t0.mul(t3);
            z3.mul(t4);
            z3.add(t0);

            this.x.copy(x3);
            this.x.norm();
            this.y.copy(y3);
            this.y.norm();
            this.z.copy(z3);
            this.z.norm();

            return 0;
        },

        /* this-=Q */
        sub: function(Q) {
            var D;

            Q.neg();
            D = this.add(Q);
            Q.neg();

            return D;
        },

        /* P*=e */
        mul: function(e) {
            /* fixed size windows */
            var mt = new ctx.BIG(),
                t = new ctx.BIG(),
                C = new ECP2(),
                P = new ECP2(),
                Q = new ECP2(),
                W = [],
                w = [],
                i, nb, s, ns;

            if (this.is_infinity()) {
                return new ECP2();
            }

            this.affine();

            // precompute table
            Q.copy(this);
            Q.dbl();
            W[0] = new ECP2();
            W[0].copy(this);

            for (i = 1; i < 8; i++) {
                W[i] = new ECP2();
                W[i].copy(W[i - 1]);
                W[i].add(Q);
            }

            // make exponent odd - add 2P if even, P if odd
            t.copy(e);
            s = t.parity();
            t.inc(1);
            t.norm();
            ns = t.parity();
            mt.copy(t);
            mt.inc(1);
            mt.norm();
            t.cmove(mt, s);
            Q.cmove(this, ns);
            C.copy(Q);

            nb = 1 + Math.floor((t.nbits() + 3) / 4);

            // convert exponent to signed 4-bit window
            for (i = 0; i < nb; i++) {
                w[i] = (t.lastbits(5) - 16);
                t.dec(w[i]);
                t.norm();
                t.fshr(4);
            }
            w[nb] = t.lastbits(5);

            P.copy(W[Math.floor((w[nb] - 1) / 2)]);
            for (i = nb - 1; i >= 0; i--) {
                Q.select(W, w[i]);
                P.dbl();
                P.dbl();
                P.dbl();
                P.dbl();
                P.add(Q);
            }
            P.sub(C);
            P.affine();

            return P;
        }
    };

    // set to group generator
    ECP2.generator = function() {
        var G=new ECP2(),
            A = new ctx.BIG(0),
            B = new ctx.BIG(0),
            QX, QY;

        A.rcopy(ctx.ROM_CURVE.CURVE_Pxa);
        B.rcopy(ctx.ROM_CURVE.CURVE_Pxb);
        QX = new ctx.FP2(0);
        QX.bset(A, B);
        A.rcopy(ctx.ROM_CURVE.CURVE_Pya);
        B.rcopy(ctx.ROM_CURVE.CURVE_Pyb);
        QY = new ctx.FP2(0);
        QY.bset(A, B);
        G.setxy(QX, QY);
        return G;
    };

    /* convert from byte array to point */
    ECP2.fromBytes = function(b) {
        var t = [],
            ra, rb, i, rx, ry, P;

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);

        rx = new ctx.FP2(ra, rb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 2 * ctx.BIG.MODBYTES];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 3 * ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);

        ry = new ctx.FP2(ra, rb);

        P = new ECP2();
        P.setxy(rx, ry);

        return P;
    };

    /* Calculate RHS of curve equation x^3+B */
    ECP2.RHS = function(x) {
        var r, c, b;

        x.norm();
        r = new ctx.FP2(x);
        r.sqr();

        c = new ctx.BIG(0);
        c.rcopy(ctx.ROM_CURVE.CURVE_B);
        b = new ctx.FP2(c);

        if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
            b.div_ip();
        }
        if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
            b.norm();
            b.mul_ip();
            b.norm();
        }

        r.mul(x);
        r.add(b);

        r.reduce();

        return r;
    };

    /* P=u0.Q0+u1*Q1+u2*Q2+u3*Q3 */
    // Bos & Costello https://eprint.iacr.org/2013/458.pdf
    // Faz-Hernandez & Longa & Sanchez  https://eprint.iacr.org/2013/158.pdf
    // Side channel attack secure
    ECP2.mul4 = function(Q, u) {
        var W = new ECP2(),
            P = new ECP2(),
            T = [],
            mt = new ctx.BIG(),
            t = [],
            w = [],
            s = [],
            i, j, k, nb, bt, pb;

        for (i = 0; i < 4; i++) {
            t[i] = new ctx.BIG(u[i]); t[i].norm();
            Q[i].affine();
        }

        T[0] = new ECP2(); T[0].copy(Q[0]); // Q[0]
        T[1] = new ECP2(); T[1].copy(T[0]); T[1].add(Q[1]); // Q[0]+Q[1]
        T[2] = new ECP2(); T[2].copy(T[0]); T[2].add(Q[2]); // Q[0]+Q[2]
        T[3] = new ECP2(); T[3].copy(T[1]); T[3].add(Q[2]); // Q[0]+Q[1]+Q[2]
        T[4] = new ECP2(); T[4].copy(T[0]); T[4].add(Q[3]); // Q[0]+Q[3]
        T[5] = new ECP2(); T[5].copy(T[1]); T[5].add(Q[3]); // Q[0]+Q[1]+Q[3]
        T[6] = new ECP2(); T[6].copy(T[2]); T[6].add(Q[3]); // Q[0]+Q[2]+Q[3]
        T[7] = new ECP2(); T[7].copy(T[3]); T[7].add(Q[3]); // Q[0]+Q[1]+Q[2]+Q[3]

        // Make it odd
        pb=1-t[0].parity();
        t[0].inc(pb);
        t[0].norm();

        // Number of bits
        mt.zero();
        for (i=0;i<4;i++) {
            mt.or(t[i]);
        }

        nb=1+mt.nbits();

        // Sign pivot
        s[nb-1]=1;
        for (i=0;i<nb-1;i++) {
            t[0].fshr(1);
            s[i]=2*t[0].parity()-1;
        }

        // Recoded exponent
        for (i=0; i<nb; i++) {
            w[i]=0;
            k=1;
            for (j=1; j<4; j++) {
                bt=s[i]*t[j].parity();
                t[j].fshr(1);
                t[j].dec(bt>>1);
                t[j].norm();
                w[i]+=bt*k;
                k*=2;
            }
        }

        // Main loop
        P.select(T,2*w[nb-1]+1);
        for (i=nb-2;i>=0;i--) {
            P.dbl();
            W.select(T,2*w[i]+s[i]);
            P.add(W);
        }

        // apply correction
        W.copy(P);
        W.sub(Q[0]);
        P.cmove(W,pb);
        P.affine();
        return P;
    };

    /* return 1 if b==c, no branching */
    ECP2.teq = function(b, c) {
        var x = b ^ c;
        x -= 1; // if x=0, x now -1
        return ((x >> 31) & 1);
    };

    /* needed for SOK */
    ECP2.mapit = function(h) {
        var fa = new ctx.BIG(0),
            fb = new ctx.BIG(0),
            q, x, one, Q, T, K, X, xQ, x2Q;

        q = new ctx.BIG(0);
        q.rcopy(ctx.ROM_FIELD.Modulus);
        x = ctx.BIG.fromBytes(h);
        one = new ctx.BIG(1);
        x.mod(q);

        for (;;) {
            X = new ctx.FP2(one, x);
            Q = new ECP2();
            Q.setx(X);
            if (!Q.is_infinity()) {
                break;
            }
            x.inc(1);
            x.norm();
        }
        /* Fast Hashing to G2 - Fuentes-Castaneda, Knapp and Rodriguez-Henriquez */
        fa.rcopy(ctx.ROM_FIELD.Fra);
        fb.rcopy(ctx.ROM_FIELD.Frb);
        X = new ctx.FP2(fa, fb);
        if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
            X.inverse();
            X.norm();
        }

        x = new ctx.BIG(0);
        x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);

        if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
            T = new ECP2();
            T.copy(Q);
            T = T.mul(x);
            if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
                T.neg();
            }
            K = new ECP2();
            K.copy(T);
            K.dbl();
            K.add(T);

            K.frob(X);
            Q.frob(X);
            Q.frob(X);
            Q.frob(X);
            Q.add(T);
            Q.add(K);
            T.frob(X);
            T.frob(X);
            Q.add(T);
        }

        if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BLS) {
            xQ = Q.mul(x);
            x2Q = xQ.mul(x);

            if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
                xQ.neg();
            }

            x2Q.sub(xQ);
            x2Q.sub(Q);

            xQ.sub(Q);
            xQ.frob(X);

            Q.dbl();
            Q.frob(X);
            Q.frob(X);

            Q.add(x2Q);
            Q.add(xQ);
        }

        Q.affine();

        return Q;
    };

    return ECP2;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* AMCL Weierstrass elliptic curve functions over ctx.FP4 */

function ECP4(ctx) {

    /* Constructor, set this=O */
    var ECP4 = function() {
        this.x = new ctx.FP4(0);
        this.y = new ctx.FP4(1);
        this.z = new ctx.FP4(0);
    };

    ECP4.prototype = {
        /* Test this=O? */
        is_infinity: function() {
            this.x.reduce();
            this.y.reduce();
            this.z.reduce();
            return (this.x.iszilch() && this.z.iszilch());
        },

        /* copy this=P */
        copy: function(P) {
            this.x.copy(P.x);
            this.y.copy(P.y);
            this.z.copy(P.z);
        },

        /* set this=O */
        inf: function() {
            this.x.zero();
            this.y.one();
            this.z.zero();
        },

        /* conditional move of Q to P dependant on d */
        cmove: function(Q, d) {
            this.x.cmove(Q.x, d);
            this.y.cmove(Q.y, d);
            this.z.cmove(Q.z, d);
        },

        /* Constant time select from pre-computed table */
        select: function(W, b) {
            var MP = new ECP4(),
                m = b >> 31,
                babs = (b ^ m) - m;

            babs = (babs - 1) / 2;

            this.cmove(W[0], ECP4.teq(babs, 0)); // conditional move
            this.cmove(W[1], ECP4.teq(babs, 1));
            this.cmove(W[2], ECP4.teq(babs, 2));
            this.cmove(W[3], ECP4.teq(babs, 3));
            this.cmove(W[4], ECP4.teq(babs, 4));
            this.cmove(W[5], ECP4.teq(babs, 5));
            this.cmove(W[6], ECP4.teq(babs, 6));
            this.cmove(W[7], ECP4.teq(babs, 7));

            MP.copy(this);
            MP.neg();
            this.cmove(MP, (m & 1));
        },

        /* Test P == Q */
        equals: function(Q) {
            var a, b;

            a = new ctx.FP4(this.x);
            b = new ctx.FP4(Q.x);

            a.mul(Q.z);
            b.mul(this.z);
            if (!a.equals(b)) {
                return false;
            }

            a.copy(this.y);
            a.mul(Q.z);
            b.copy(Q.y);
            b.mul(this.z);
            if (!a.equals(b)) {
                return false;
            }

            return true;
        },

        /* set this=-this */
        neg: function() {
            this.y.norm();
            this.y.neg();
            this.y.norm();
            return;
        },

        /* convert this to affine, from (x,y,z) to (x,y) */
        affine: function() {
            var one;

            if (this.is_infinity()) {
                return;
            }

            one = new ctx.FP4(1);

            if (this.z.equals(one)) {
                this.x.reduce();
                this.y.reduce();
                return;
            }

            this.z.inverse();

            this.x.mul(this.z);
            this.x.reduce();
            this.y.mul(this.z);
            this.y.reduce();
            this.z.copy(one);
        },

        /* extract affine x as ctx.FP4 */
        getX: function() {
            this.affine();
            return this.x;
        },

        /* extract affine y as ctx.FP4 */
        getY: function() {
            this.affine();
            return this.y;
        },

        /* extract projective x */
        getx: function() {
            return this.x;
        },

        /* extract projective y */
        gety: function() {
            return this.y;
        },

        /* extract projective z */
        getz: function() {
            return this.z;
        },

        /* convert this to byte array */
        toBytes: function(b) {
            var t = [],
                i;

            this.affine();
            this.x.geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i] = t[i];
            }
            this.x.geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + ctx.BIG.MODBYTES] = t[i];
            }
            this.x.getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 2*ctx.BIG.MODBYTES] = t[i];
            }
            this.x.getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 3*ctx.BIG.MODBYTES] = t[i];
            }


            this.y.geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 4 * ctx.BIG.MODBYTES] = t[i];
            }
            this.y.geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 5 * ctx.BIG.MODBYTES] = t[i];
            }
            this.y.getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 6 * ctx.BIG.MODBYTES] = t[i];
            }
            this.y.getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 7 * ctx.BIG.MODBYTES] = t[i];
            }
        },

        /* convert this to hex string */
        toString: function() {
            if (this.is_infinity()) {
                return "infinity";
            }
            this.affine();
            return "(" + this.x.toString() + "," + this.y.toString() + ")";
        },

        /* set this=(x,y) */
        setxy: function(ix, iy) {
            var rhs, y2;

            this.x.copy(ix);
            this.y.copy(iy);
            this.z.one();

            rhs = ECP4.RHS(this.x);

            y2 = new ctx.FP4(this.y);
            y2.sqr();

            if (!y2.equals(rhs)) {
                this.inf();
            }
        },

        /* set this=(x,.) */
        setx: function(ix) {
            var rhs;

            this.x.copy(ix);
            this.z.one();

            rhs = ECP4.RHS(this.x);

            if (rhs.sqrt()) {
                this.y.copy(rhs);
            } else {
                this.inf();
            }
        },

        /* set this*=q, where q is Modulus, using Frobenius */
        frob: function(F,n) {
            for (var i=0;i<n;i++) {
                this.x.frob(F[2]);
                this.x.pmul(F[0]);

                this.y.frob(F[2]);
                this.y.pmul(F[1]);
                this.y.times_i();

                this.z.frob(F[2]);
            }
        },

        /* this+=this */
        dbl: function() {
            var iy, t0, t1, t2, x3, y3;

            iy = new ctx.FP4(this.y);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                iy.times_i();
                iy.norm();
            }

            t0 = new ctx.FP4(this.y);
            t0.sqr();
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t0.times_i();
            }
            t1 = new ctx.FP4(iy);
            t1.mul(this.z);
            t2 = new ctx.FP4(this.z);
            t2.sqr();

            this.z.copy(t0);
            this.z.add(t0);
            this.z.norm();
            this.z.add(this.z);
            this.z.add(this.z);
            this.z.norm();

            t2.imul(3 * ctx.ROM_CURVE.CURVE_B_I);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                t2.times_i();
            }

            x3 = new ctx.FP4(t2);
            x3.mul(this.z);

            y3 = new ctx.FP4(t0);

            y3.add(t2);
            y3.norm();
            this.z.mul(t1);
            t1.copy(t2);
            t1.add(t2);
            t2.add(t1);
            t2.norm();
            t0.sub(t2);
            t0.norm(); //y^2-9bz^2
            y3.mul(t0);
            y3.add(x3); //(y^2+3z*2)(y^2-9z^2)+3b.z^2.8y^2
            t1.copy(this.x);
            t1.mul(iy);
            this.x.copy(t0);
            this.x.norm();
            this.x.mul(t1);
            this.x.add(this.x); //(y^2-9bz^2)xy2

            this.x.norm();
            this.y.copy(y3);
            this.y.norm();

            return 1;
        },

        /* this+=Q */
        add: function(Q) {
            var b, t0, t1, t2, t3, t4, x3, y3, z3;

            b = 3 * ctx.ROM_CURVE.CURVE_B_I;
            t0 = new ctx.FP4(this.x);
            t0.mul(Q.x); // x.Q.x
            t1 = new ctx.FP4(this.y);
            t1.mul(Q.y); // y.Q.y

            t2 = new ctx.FP4(this.z);
            t2.mul(Q.z);
            t3 = new ctx.FP4(this.x);
            t3.add(this.y);
            t3.norm(); //t3=X1+Y1
            t4 = new ctx.FP4(Q.x);
            t4.add(Q.y);
            t4.norm(); //t4=X2+Y2
            t3.mul(t4); //t3=(X1+Y1)(X2+Y2)
            t4.copy(t0);
            t4.add(t1); //t4=X1.X2+Y1.Y2

            t3.sub(t4);
            t3.norm();
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t3.times_i();  //t3=(X1+Y1)(X2+Y2)-(X1.X2+Y1.Y2) = X1.Y2+X2.Y1
            }

            t4.copy(this.y);
            t4.add(this.z);
            t4.norm(); //t4=Y1+Z1
            x3 = new ctx.FP4(Q.y);
            x3.add(Q.z);
            x3.norm(); //x3=Y2+Z2

            t4.mul(x3); //t4=(Y1+Z1)(Y2+Z2)
            x3.copy(t1);
            x3.add(t2); //X3=Y1.Y2+Z1.Z2

            t4.sub(x3);
            t4.norm();
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t4.times_i();  //t4=(Y1+Z1)(Y2+Z2) - (Y1.Y2+Z1.Z2) = Y1.Z2+Y2.Z1
            }

            x3.copy(this.x);
            x3.add(this.z);
            x3.norm(); // x3=X1+Z1
            y3 = new ctx.FP4(Q.x);
            y3.add(Q.z);
            y3.norm(); // y3=X2+Z2
            x3.mul(y3); // x3=(X1+Z1)(X2+Z2)
            y3.copy(t0);
            y3.add(t2); // y3=X1.X2+Z1+Z2
            y3.rsub(x3);
            y3.norm(); // y3=(X1+Z1)(X2+Z2) - (X1.X2+Z1.Z2) = X1.Z2+X2.Z1

            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t0.times_i();
                t1.times_i();
            }

            x3.copy(t0);
            x3.add(t0);
            t0.add(x3);
            t0.norm();
            t2.imul(b);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                t2.times_i();
            }

            z3 = new ctx.FP4(t1);
            z3.add(t2);
            z3.norm();
            t1.sub(t2);
            t1.norm();
            y3.imul(b);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                y3.times_i();
            }

            x3.copy(y3);
            x3.mul(t4);
            t2.copy(t3);
            t2.mul(t1);
            x3.rsub(t2);
            y3.mul(t0);
            t1.mul(z3);
            y3.add(t1);
            t0.mul(t3);
            z3.mul(t4);
            z3.add(t0);

            this.x.copy(x3);
            this.x.norm();
            this.y.copy(y3);
            this.y.norm();
            this.z.copy(z3);
            this.z.norm();

            return 0;
        },

        /* this-=Q */
        sub: function(Q) {
            var D;

            Q.neg();
            D = this.add(Q);
            Q.neg();

            return D;
        },

        /* P*=e */
        mul: function(e) {
            /* fixed size windows */
            var mt = new ctx.BIG(),
                t = new ctx.BIG(),
                C = new ECP4(),
                P = new ECP4(),
                Q = new ECP4(),
                W = [],
                w = [],
                i, nb, s, ns;

            if (this.is_infinity()) {
                return new ECP4();
            }

            this.affine();

            // precompute table
            Q.copy(this);
            Q.dbl();
            W[0] = new ECP4();
            W[0].copy(this);

            for (i = 1; i < 8; i++) {
                W[i] = new ECP4();
                W[i].copy(W[i - 1]);
                W[i].add(Q);
            }

            // make exponent odd - add 2P if even, P if odd
            t.copy(e);
            s = t.parity();
            t.inc(1);
            t.norm();
            ns = t.parity();
            mt.copy(t);
            mt.inc(1);
            mt.norm();
            t.cmove(mt, s);
            Q.cmove(this, ns);
            C.copy(Q);

            nb = 1 + Math.floor((t.nbits() + 3) / 4);

            // convert exponent to signed 4-bit window
            for (i = 0; i < nb; i++) {
                w[i] = (t.lastbits(5) - 16);
                t.dec(w[i]);
                t.norm();
                t.fshr(4);
            }
            w[nb] = t.lastbits(5);

            P.copy(W[Math.floor((w[nb] - 1) / 2)]);
            for (i = nb - 1; i >= 0; i--) {
                Q.select(W, w[i]);
                P.dbl();
                P.dbl();
                P.dbl();
                P.dbl();
                P.add(Q);
            }
            P.sub(C);
            P.affine();

            return P;
        }
    };

    // set to group generator
    ECP4.generator = function() {
        var G=new ECP4(),
            A = new ctx.BIG(0),
            B = new ctx.BIG(0),
            XA, XB, X, YA, YB, Y;

        A.rcopy(ctx.ROM_CURVE.CURVE_Pxaa);
        B.rcopy(ctx.ROM_CURVE.CURVE_Pxab);
        XA= new ctx.FP2(A,B);

        A.rcopy(ctx.ROM_CURVE.CURVE_Pxba);
        B.rcopy(ctx.ROM_CURVE.CURVE_Pxbb);

        XB= new ctx.FP2(A,B);
        X=new ctx.FP4(XA,XB);

        A.rcopy(ctx.ROM_CURVE.CURVE_Pyaa);
        B.rcopy(ctx.ROM_CURVE.CURVE_Pyab);
        YA= new ctx.FP2(A,B);

        A.rcopy(ctx.ROM_CURVE.CURVE_Pyba);
        B.rcopy(ctx.ROM_CURVE.CURVE_Pybb);

        YB= new ctx.FP2(A,B);
        Y=new ctx.FP4(YA,YB);

        G.setxy(X,Y);

        return G;
    };

    /* convert from byte array to point */
    ECP4.fromBytes = function(b) {
        var t = [],
            ra, rb, ra4, rb4, i, rx, ry, P;

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);
        ra4=new ctx.FP2(ra,rb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i  + 2*ctx.BIG.MODBYTES];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 3*ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);
        rb4=new ctx.FP2(ra,rb);

        rx = new ctx.FP4(ra4, rb4);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 4 * ctx.BIG.MODBYTES];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 5 * ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);
        ra4=new ctx.FP2(ra,rb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 6 * ctx.BIG.MODBYTES];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 7 * ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);
        rb4=new ctx.FP2(ra,rb);


        ry = new ctx.FP4(ra4, rb4);

        P = new ECP4();
        P.setxy(rx, ry);

        return P;
    };

    /* Calculate RHS of curve equation x^3+B */
    ECP4.RHS = function(x) {
        var r, c, b;

        x.norm();
        r = new ctx.FP4(x);
        r.sqr();

        c = new ctx.BIG(0);
        c.rcopy(ctx.ROM_CURVE.CURVE_B);
        b = new ctx.FP4(c);

        if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
            b.div_i();
        }
        if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
            b.times_i();
        }

        r.mul(x);
        r.add(b);

        r.reduce();
        return r;
    };

    /* P=u0.Q0+u1*Q1+u2*Q2+u3*Q3... */
    // Bos & Costello https://eprint.iacr.org/2013/458.pdf
    // Faz-Hernandez & Longa & Sanchez  https://eprint.iacr.org/2013/158.pdf
    // Side channel attack secure
    ECP4.mul8 = function(Q, u) {
        var W = new ECP4(),
            P = new ECP4(),
            T1 = [],
            T2 = [],
            mt = new ctx.BIG(),
            t = [],
            w1 = [],
            s1 = [],
            w2 = [],
            s2 = [],
            F=ECP4.frob_constants(),
            i, j, k, nb, bt, pb1, pb2;

        for (i = 0; i < 8; i++) {
            t[i] = new ctx.BIG(u[i]); t[i].norm();
            Q[i].affine();
        }

        T1[0] = new ECP4(); T1[0].copy(Q[0]);
        T1[1] = new ECP4(); T1[1].copy(T1[0]); T1[1].add(Q[1]);
        T1[2] = new ECP4(); T1[2].copy(T1[0]); T1[2].add(Q[2]);
        T1[3] = new ECP4(); T1[3].copy(T1[1]); T1[3].add(Q[2]);
        T1[4] = new ECP4(); T1[4].copy(T1[0]); T1[4].add(Q[3]);
        T1[5] = new ECP4(); T1[5].copy(T1[1]); T1[5].add(Q[3]);
        T1[6] = new ECP4(); T1[6].copy(T1[2]); T1[6].add(Q[3]);
        T1[7] = new ECP4(); T1[7].copy(T1[3]); T1[7].add(Q[3]);

        //  Use Frobenius
        for (i=0;i<8;i++) {
            T2[i] = new ECP4(); T2[i].copy(T1[i]);
            T2[i].frob(F,4);
        }

        // Make it odd
        pb1=1-t[0].parity();
        t[0].inc(pb1);
        t[0].norm();

        pb2=1-t[4].parity();
        t[4].inc(pb2);
        t[4].norm();

        // Number of bits
        mt.zero();
        for (i=0;i<8;i++) {
            mt.or(t[i]);
        }

        nb=1+mt.nbits();

        // Sign pivot
        s1[nb-1]=1;
        s2[nb-1]=1;
        for (i=0;i<nb-1;i++) {
            t[0].fshr(1);
            s1[i]=2*t[0].parity()-1;
            t[4].fshr(1);
            s2[i]=2*t[4].parity()-1;
        }

        // Recoded exponent
        for (i=0; i<nb; i++) {
            w1[i]=0;
            k=1;
            for (j=1; j<4; j++) {
                bt=s1[i]*t[j].parity();
                t[j].fshr(1);
                t[j].dec(bt>>1);
                t[j].norm();
                w1[i]+=bt*k;
                k*=2;
            }
            w2[i]=0;
            k=1;
            for (j=5; j<8; j++) {
                bt=s2[i]*t[j].parity();
                t[j].fshr(1);
                t[j].dec(bt>>1);
                t[j].norm();
                w2[i]+=bt*k;
                k*=2;
            }
        }

        // Main loop
        P.select(T1,2*w1[nb-1]+1);
        W.select(T2,2*w2[nb-1]+1);
        P.add(W);
        for (i=nb-2;i>=0;i--) {
            P.dbl();
            W.select(T1,2*w1[i]+s1[i]);
            P.add(W);
            W.select(T2,2*w2[i]+s2[i]);
            P.add(W);
        }

        // apply correction
        W.copy(P);
        W.sub(Q[0]);
        P.cmove(W,pb1);

        W.copy(P);
        W.sub(Q[4]);
        P.cmove(W,pb2);

        P.affine();
        return P;
    };

    /* return 1 if b==c, no branching */
    ECP4.teq = function(b, c) {
        var x = b ^ c;
        x -= 1; // if x=0, x now -1
        return ((x >> 31) & 1);
    };

    /* needed for SOK */
    ECP4.mapit = function(h) {
        var F=ECP4.frob_constants(),
            q, x, one, Q, X, X2, xQ, x2Q, x3Q, x4Q;

        q = new ctx.BIG(0);
        q.rcopy(ctx.ROM_FIELD.Modulus);
        x = ctx.BIG.fromBytes(h);
        one = new ctx.BIG(1);
        x.mod(q);

        for (;;) {
            X2 = new ctx.FP2(one, x);
            X = new ctx.FP4(X2);
            Q = new ECP4();
            Q.setx(X);
            if (!Q.is_infinity()) {
                break;
            }
            x.inc(1);
            x.norm();
        }

        /* Fast Hashing to G2 - Fuentes-Castaneda, Knapp and Rodriguez-Henriquez */
        x = new ctx.BIG(0);
        x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);


        xQ = Q.mul(x);
        x2Q = xQ.mul(x);
        x3Q = x2Q.mul(x);
        x4Q = x3Q.mul(x);

        if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
            xQ.neg();
            x3Q.neg();
        }

        x4Q.sub(x3Q);
        x4Q.sub(Q);

        x3Q.sub(x2Q);
        x3Q.frob(F,1);

        x2Q.sub(xQ);
        x2Q.frob(F,2);

        xQ.sub(Q);
        xQ.frob(F,3);

        Q.dbl();
        Q.frob(F,4);

        Q.add(x4Q);
        Q.add(x3Q);
        Q.add(x2Q);
        Q.add(xQ);

        Q.affine();
        return Q;
    };

    ECP4.frob_constants = function() {
        var fa = new ctx.BIG(0),
            fb = new ctx.BIG(0),
            F=[],
            X, F0, F1, F2;

        fa.rcopy(ctx.ROM_FIELD.Fra);
        fb.rcopy(ctx.ROM_FIELD.Frb);
        X = new ctx.FP2(fa, fb);

        F0=new ctx.FP2(X); F0.sqr();
        F2=new ctx.FP2(F0);
        F2.mul_ip(); F2.norm();
        F1=new ctx.FP2(F2); F1.sqr();
        F2.mul(F1);
        F1.copy(X);
        if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
            F1.mul_ip();
            F1.inverse();
            F0.copy(F1); F0.sqr();
        }
        F0.mul_ip(); F0.norm();
        F1.mul(F0);

        F[0]=new ctx.FP2(F0); F[1]=new ctx.FP2(F1); F[2]=new ctx.FP2(F2);
        return F;
    };

    return ECP4;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* AMCL Weierstrass elliptic curve functions over ctx.FP8 */

function ECP8(ctx) {

    /* Constructor, set this=O */
    var ECP8 = function() {
        this.x = new ctx.FP8(0);
        this.y = new ctx.FP8(1);
        this.z = new ctx.FP8(0);
        // this.INF = true;
    };

    ECP8.prototype = {
        /* Test this=O? */
        is_infinity: function() {
            this.x.reduce();
            this.y.reduce();
            this.z.reduce();
            return (this.x.iszilch() && this.z.iszilch());
        },

        /* copy this=P */
        copy: function(P) {
            this.x.copy(P.x);
            this.y.copy(P.y);
            this.z.copy(P.z);
        },

        /* set this=O */
        inf: function() {
            this.x.zero();
            this.y.one();
            this.z.zero();
        },

        /* conditional move of Q to P dependant on d */
        cmove: function(Q, d) {
            this.x.cmove(Q.x, d);
            this.y.cmove(Q.y, d);
            this.z.cmove(Q.z, d);
        },

        /* Constant time select from pre-computed table */
        select: function(W, b) {
            var MP = new ECP8(),
                m = b >> 31,
                babs = (b ^ m) - m;

            babs = (babs - 1) / 2;

            this.cmove(W[0], ECP8.teq(babs, 0)); // conditional move
            this.cmove(W[1], ECP8.teq(babs, 1));
            this.cmove(W[2], ECP8.teq(babs, 2));
            this.cmove(W[3], ECP8.teq(babs, 3));
            this.cmove(W[4], ECP8.teq(babs, 4));
            this.cmove(W[5], ECP8.teq(babs, 5));
            this.cmove(W[6], ECP8.teq(babs, 6));
            this.cmove(W[7], ECP8.teq(babs, 7));

            MP.copy(this);
            MP.neg();
            this.cmove(MP, (m & 1));
        },

        /* Test P == Q */
        equals: function(Q) {
            var a, b;

            a = new ctx.FP8(this.x);
            b = new ctx.FP8(Q.x);

            a.mul(Q.z);
            b.mul(this.z);
            if (!a.equals(b)) {
                return false;
            }

            a.copy(this.y);
            a.mul(Q.z);
            b.copy(Q.y);
            b.mul(this.z);
            if (!a.equals(b)) {
                return false;
            }

            return true;
        },

        /* set this=-this */
        neg: function() {
            this.y.norm();
            this.y.neg();
            this.y.norm();
            return;
        },

        /* convert this to affine, from (x,y,z) to (x,y) */
        affine: function() {
            var one;

            if (this.is_infinity()) {
                return;
            }

            one = new ctx.FP8(1);

            if (this.z.equals(one)) {
                this.x.reduce();
                this.y.reduce();
                return;
            }

            this.z.inverse();
            this.x.mul(this.z);
            this.x.reduce();
            this.y.mul(this.z);
            this.y.reduce();
            this.z.copy(one);
        },

        /* extract affine x as ctx.FP8 */
        getX: function() {
            this.affine();
            return this.x;
        },

        /* extract affine y as ctx.FP8 */
        getY: function() {
            this.affine();
            return this.y;
        },

        /* extract projective x */
        getx: function() {
            return this.x;
        },

        /* extract projective y */
        gety: function() {
            return this.y;
        },

        /* extract projective z */
        getz: function() {
            return this.z;
        },

        /* convert this to byte array */
        toBytes: function(b) {
            var t = [],
                i;

            this.affine();
            this.x.geta().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i] = t[i];
            }
            this.x.geta().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + ctx.BIG.MODBYTES] = t[i];
            }
            this.x.geta().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 2*ctx.BIG.MODBYTES] = t[i];
            }
            this.x.geta().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 3*ctx.BIG.MODBYTES] = t[i];
            }

            this.x.getb().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 4*ctx.BIG.MODBYTES] = t[i];
            }
            this.x.getb().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 5*ctx.BIG.MODBYTES] = t[i];
            }
            this.x.getb().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 6*ctx.BIG.MODBYTES] = t[i];
            }
            this.x.getb().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 7*ctx.BIG.MODBYTES] = t[i];
            }

            this.y.geta().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 8 * ctx.BIG.MODBYTES] = t[i];
            }
            this.y.geta().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 9 * ctx.BIG.MODBYTES] = t[i];
            }
            this.y.geta().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 10 * ctx.BIG.MODBYTES] = t[i];
            }
            this.y.geta().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 11 * ctx.BIG.MODBYTES] = t[i];
            }

            this.y.getb().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 12 * ctx.BIG.MODBYTES] = t[i];
            }
            this.y.getb().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 13 * ctx.BIG.MODBYTES] = t[i];
            }
            this.y.getb().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 14 * ctx.BIG.MODBYTES] = t[i];
            }
            this.y.getb().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 15 * ctx.BIG.MODBYTES] = t[i];
            }
        },

        /* convert this to hex string */
        toString: function() {
            if (this.is_infinity()) {
                return "infinity";
            }
            this.affine();
            return "(" + this.x.toString() + "," + this.y.toString() + ")";
        },

        /* set this=(x,y) */
        setxy: function(ix, iy) {
            var rhs, y2;

            this.x.copy(ix);
            this.y.copy(iy);
            this.z.one();

            rhs = ECP8.RHS(this.x);

            y2 = new ctx.FP8(this.y);
            y2.sqr();

            if (!y2.equals(rhs)) {
                this.inf();
            }
        },

        /* set this=(x,.) */
        setx: function(ix) {
            var rhs;

            this.x.copy(ix);
            this.z.one();

            rhs = ECP8.RHS(this.x);

            if (rhs.sqrt()) {
                this.y.copy(rhs);
            } else {
                this.inf();
            }
        },

        /* set this*=q, where q is Modulus, using Frobenius */
        frob: function(F,n) {
            for (var i=0;i<n;i++) {
                this.x.frob(F[2]);
                this.x.qmul(F[0]);
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    this.x.div_i2();
                }
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                    this.x.times_i2();
                }

                this.y.frob(F[2]);
                this.y.qmul(F[1]);

                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    this.y.div_i();
                }
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                    this.y.times_i2(); this.y.times_i2(); this.y.times_i();
                }
                this.z.frob(F[2]);
            }
        },

        /* this+=this */
        dbl: function() {
            var iy, t0, t1, t2, x3, y3;

            iy = new ctx.FP8(this.y);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                iy.times_i();
                iy.norm();
            }

            t0 = new ctx.FP8(this.y);
            t0.sqr();
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t0.times_i();
            }
            t1 = new ctx.FP8(iy);
            t1.mul(this.z);
            t2 = new ctx.FP8(this.z);
            t2.sqr();

            this.z.copy(t0);
            this.z.add(t0);
            this.z.norm();
            this.z.add(this.z);
            this.z.add(this.z);
            this.z.norm();

            t2.imul(3 * ctx.ROM_CURVE.CURVE_B_I);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                t2.times_i();
            }

            x3 = new ctx.FP8(t2);
            x3.mul(this.z);

            y3 = new ctx.FP8(t0);

            y3.add(t2);
            y3.norm();
            this.z.mul(t1);
            t1.copy(t2);
            t1.add(t2);
            t2.add(t1);
            t2.norm();
            t0.sub(t2);
            t0.norm(); //y^2-9bz^2
            y3.mul(t0);
            y3.add(x3); //(y^2+3z*2)(y^2-9z^2)+3b.z^2.8y^2
            t1.copy(this.x);
            t1.mul(iy);
            this.x.copy(t0);
            this.x.norm();
            this.x.mul(t1);
            this.x.add(this.x); //(y^2-9bz^2)xy2

            this.x.norm();
            this.y.copy(y3);
            this.y.norm();

            return 1;
        },

        /* this+=Q */
        add: function(Q) {
            var b, t0, t1, t2, t3, t4, x3, y3, z3;

            b = 3 * ctx.ROM_CURVE.CURVE_B_I;
            t0 = new ctx.FP8(this.x);
            t0.mul(Q.x); // x.Q.x
            t1 = new ctx.FP8(this.y);
            t1.mul(Q.y); // y.Q.y

            t2 = new ctx.FP8(this.z);
            t2.mul(Q.z);
            t3 = new ctx.FP8(this.x);
            t3.add(this.y);
            t3.norm(); //t3=X1+Y1
            t4 = new ctx.FP8(Q.x);
            t4.add(Q.y);
            t4.norm(); //t4=X2+Y2
            t3.mul(t4); //t3=(X1+Y1)(X2+Y2)
            t4.copy(t0);
            t4.add(t1); //t4=X1.X2+Y1.Y2

            t3.sub(t4);
            t3.norm();
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t3.times_i();  //t3=(X1+Y1)(X2+Y2)-(X1.X2+Y1.Y2) = X1.Y2+X2.Y1
            }

            t4.copy(this.y);
            t4.add(this.z);
            t4.norm(); //t4=Y1+Z1
            x3 = new ctx.FP8(Q.y);
            x3.add(Q.z);
            x3.norm(); //x3=Y2+Z2

            t4.mul(x3); //t4=(Y1+Z1)(Y2+Z2)
            x3.copy(t1);
            x3.add(t2); //X3=Y1.Y2+Z1.Z2

            t4.sub(x3);
            t4.norm();
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t4.times_i();  //t4=(Y1+Z1)(Y2+Z2) - (Y1.Y2+Z1.Z2) = Y1.Z2+Y2.Z1
            }

            x3.copy(this.x);
            x3.add(this.z);
            x3.norm(); // x3=X1+Z1
            y3 = new ctx.FP8(Q.x);
            y3.add(Q.z);
            y3.norm(); // y3=X2+Z2
            x3.mul(y3); // x3=(X1+Z1)(X2+Z2)
            y3.copy(t0);
            y3.add(t2); // y3=X1.X2+Z1+Z2
            y3.rsub(x3);
            y3.norm(); // y3=(X1+Z1)(X2+Z2) - (X1.X2+Z1.Z2) = X1.Z2+X2.Z1

            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t0.times_i();
                t1.times_i();
            }

            x3.copy(t0);
            x3.add(t0);
            t0.add(x3);
            t0.norm();
            t2.imul(b);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                t2.times_i();
            }

            z3 = new ctx.FP8(t1);
            z3.add(t2);
            z3.norm();
            t1.sub(t2);
            t1.norm();
            y3.imul(b);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                y3.times_i();
            }

            x3.copy(y3);
            x3.mul(t4);
            t2.copy(t3);
            t2.mul(t1);
            x3.rsub(t2);
            y3.mul(t0);
            t1.mul(z3);
            y3.add(t1);
            t0.mul(t3);
            z3.mul(t4);
            z3.add(t0);

            this.x.copy(x3);
            this.x.norm();
            this.y.copy(y3);
            this.y.norm();
            this.z.copy(z3);
            this.z.norm();

            return 0;
        },

        /* this-=Q */
        sub: function(Q) {
            var D;

            Q.neg();
            D = this.add(Q);
            Q.neg();

            return D;
        },

        /* P*=e */
        mul: function(e) {
            /* fixed size windows */
            var mt = new ctx.BIG(),
                t = new ctx.BIG(),
                C = new ECP8(),
                P = new ECP8(),
                Q = new ECP8(),
                W = [],
                w = [],
                i, nb, s, ns;

            if (this.is_infinity()) {
                return new ECP8();
            }

            this.affine();

            // precompute table
            Q.copy(this);
            Q.dbl();
            W[0] = new ECP8();
            W[0].copy(this);

            for (i = 1; i < 8; i++) {
                W[i] = new ECP8();
                W[i].copy(W[i - 1]);
                W[i].add(Q);
            }

            // make exponent odd - add 2P if even, P if odd
            t.copy(e);
            s = t.parity();
            t.inc(1);
            t.norm();
            ns = t.parity();
            mt.copy(t);
            mt.inc(1);
            mt.norm();
            t.cmove(mt, s);
            Q.cmove(this, ns);
            C.copy(Q);

            nb = 1 + Math.floor((t.nbits() + 3) / 4);

            // convert exponent to signed 4-bit window
            for (i = 0; i < nb; i++) {
                w[i] = (t.lastbits(5) - 16);
                t.dec(w[i]);
                t.norm();
                t.fshr(4);
            }
            w[nb] = t.lastbits(5);

            P.copy(W[Math.floor((w[nb] - 1) / 2)]);
            for (i = nb - 1; i >= 0; i--) {
                Q.select(W, w[i]);
                P.dbl();
                P.dbl();
                P.dbl();
                P.dbl();
                P.add(Q);
            }
            P.sub(C);
            P.affine();

            return P;
        }
    };

    // set to group generator
    ECP8.generator = function() {
        var G=new ECP8(),
            A = new ctx.BIG(0),
            B = new ctx.BIG(0),
            XAA, XAB, XA, XBA, XBB, XB, X,
            YAA, YAB, YA, YBA, YBB, YB, Y;

        A.rcopy(ctx.ROM_CURVE.CURVE_Pxaaa);
        B.rcopy(ctx.ROM_CURVE.CURVE_Pxaab);
        XAA= new ctx.FP2(A,B);

        A.rcopy(ctx.ROM_CURVE.CURVE_Pxaba);
        B.rcopy(ctx.ROM_CURVE.CURVE_Pxabb);

        XAB= new ctx.FP2(A,B);
        XA=new ctx.FP4(XAA,XAB);

        A.rcopy(ctx.ROM_CURVE.CURVE_Pxbaa);
        B.rcopy(ctx.ROM_CURVE.CURVE_Pxbab);
        XBA= new ctx.FP2(A,B);

        A.rcopy(ctx.ROM_CURVE.CURVE_Pxbba);
        B.rcopy(ctx.ROM_CURVE.CURVE_Pxbbb);

        XBB= new ctx.FP2(A,B);
        XB=new ctx.FP4(XBA,XBB);

        X=new ctx.FP8(XA,XB);


        A.rcopy(ctx.ROM_CURVE.CURVE_Pyaaa);
        B.rcopy(ctx.ROM_CURVE.CURVE_Pyaab);
        YAA= new ctx.FP2(A,B);

        A.rcopy(ctx.ROM_CURVE.CURVE_Pyaba);
        B.rcopy(ctx.ROM_CURVE.CURVE_Pyabb);

        YAB= new ctx.FP2(A,B);
        YA=new ctx.FP4(YAA,YAB);

        A.rcopy(ctx.ROM_CURVE.CURVE_Pybaa);
        B.rcopy(ctx.ROM_CURVE.CURVE_Pybab);
        YBA= new ctx.FP2(A,B);

        A.rcopy(ctx.ROM_CURVE.CURVE_Pybba);
        B.rcopy(ctx.ROM_CURVE.CURVE_Pybbb);

        YBB= new ctx.FP2(A,B);
        YB=new ctx.FP4(YBA,YBB);

        Y=new ctx.FP8(YA,YB);

        G.setxy(X,Y);

        return G;
    };

    /* convert from byte array to point */
    ECP8.fromBytes = function(b) {
        var t = [],
            ra, rb, ra4, rb4, ra8, rb8, i, rx, ry, P;

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);
        ra4=new ctx.FP2(ra,rb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i  + 2*ctx.BIG.MODBYTES];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 3*ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);
        rb4=new ctx.FP2(ra,rb);

        ra8=new ctx.FP4(ra4,rb4);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 4*ctx.BIG.MODBYTES];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 5*ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);
        ra4=new ctx.FP2(ra,rb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i  + 6*ctx.BIG.MODBYTES];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 7*ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);
        rb4=new ctx.FP2(ra,rb);

        rb8=new ctx.FP4(ra4,rb4);

        rx = new ctx.FP8(ra8, rb8);


        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 8 * ctx.BIG.MODBYTES];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 9 * ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);
        ra4=new ctx.FP2(ra,rb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 10 * ctx.BIG.MODBYTES];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 11 * ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);
        rb4=new ctx.FP2(ra,rb);

        ra8=new ctx.FP4(ra4,rb4);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 12 * ctx.BIG.MODBYTES];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 13 * ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);
        ra4=new ctx.FP2(ra,rb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 14 * ctx.BIG.MODBYTES];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 15 * ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);
        rb4=new ctx.FP2(ra,rb);

        rb8=new ctx.FP4(ra4,rb4);

        ry = new ctx.FP8(ra8, rb8);

        P = new ECP8();
        P.setxy(rx, ry);

        return P;
    };

    /* Calculate RHS of curve equation x^3+B */
    ECP8.RHS = function(x) {
        var r, c, b;

        x.norm();
        r = new ctx.FP8(x); //r.copy(x);
        r.sqr();

        c = new ctx.BIG(0);
        c.rcopy(ctx.ROM_CURVE.CURVE_B);
        b = new ctx.FP8(c); //b.bseta(c);

        if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
            b.div_i();
        }
        if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
            b.times_i();
        }

        r.mul(x);
        r.add(b);

        r.reduce();
        return r;
    };

    /* P=u0.Q0+u1*Q1+u2*Q2+u3*Q3... */
    // Bos & Costello https://eprint.iacr.org/2013/458.pdf
    // Faz-Hernandez & Longa & Sanchez  https://eprint.iacr.org/2013/158.pdf
    // Side channel attack secure
    ECP8.mul16 = function(Q, u) {
        var W = new ECP8(),
            P = new ECP8(),
            T1 = [],
            T2 = [],
            T3 = [],
            T4 = [],
            mt = new ctx.BIG(),
            t = [],
            w1 = [],
            s1 = [],
            w2 = [],
            s2 = [],
            w3 = [],
            s3 = [],
            w4 = [],
            s4 = [],
            F=ECP8.frob_constants(),
            i, j, k, nb, bt, pb1, pb2, pb3, pb4;

        for (i = 0; i < 16; i++) {
            t[i] = new ctx.BIG(u[i]); t[i].norm();
            Q[i].affine();
        }

        T1[0] = new ECP8(); T1[0].copy(Q[0]);
        T1[1] = new ECP8(); T1[1].copy(T1[0]); T1[1].add(Q[1]);
        T1[2] = new ECP8(); T1[2].copy(T1[0]); T1[2].add(Q[2]);
        T1[3] = new ECP8(); T1[3].copy(T1[1]); T1[3].add(Q[2]);
        T1[4] = new ECP8(); T1[4].copy(T1[0]); T1[4].add(Q[3]);
        T1[5] = new ECP8(); T1[5].copy(T1[1]); T1[5].add(Q[3]);
        T1[6] = new ECP8(); T1[6].copy(T1[2]); T1[6].add(Q[3]);
        T1[7] = new ECP8(); T1[7].copy(T1[3]); T1[7].add(Q[3]);

        //  Use Frobenius
        for (i=0;i<8;i++) {
            T2[i] = new ECP8(); T2[i].copy(T1[i]);
            T2[i].frob(F,4);
            T3[i] = new ECP8(); T3[i].copy(T2[i]);
            T3[i].frob(F,4);
            T4[i] = new ECP8(); T4[i].copy(T3[i]);
            T4[i].frob(F,4);
        }

        // Make it odd
        pb1=1-t[0].parity();
        t[0].inc(pb1);
        t[0].norm();

        pb2=1-t[4].parity();
        t[4].inc(pb2);
        t[4].norm();

        pb3=1-t[8].parity();
        t[8].inc(pb3);
        t[8].norm();

        pb4=1-t[12].parity();
        t[12].inc(pb4);
        t[12].norm();

        // Number of bits
        mt.zero();
        for (i=0;i<16;i++) {
            mt.or(t[i]);
        }

        nb=1+mt.nbits();

        // Sign pivot
        s1[nb-1]=1;
        s2[nb-1]=1;
        s3[nb-1]=1;
        s4[nb-1]=1;
        for (i=0;i<nb-1;i++) {
            t[0].fshr(1);
            s1[i]=2*t[0].parity()-1;
            t[4].fshr(1);
            s2[i]=2*t[4].parity()-1;

            t[8].fshr(1);
            s3[i]=2*t[8].parity()-1;
            t[12].fshr(1);
            s4[i]=2*t[12].parity()-1;
        }

        // Recoded exponent
        for (i=0; i<nb; i++) {
            w1[i]=0;
            k=1;
            for (j=1; j<4; j++) {
                bt=s1[i]*t[j].parity();
                t[j].fshr(1);
                t[j].dec(bt>>1);
                t[j].norm();
                w1[i]+=bt*k;
                k*=2;
            }
            w2[i]=0;
            k=1;
            for (j=5; j<8; j++) {
                bt=s2[i]*t[j].parity();
                t[j].fshr(1);
                t[j].dec(bt>>1);
                t[j].norm();
                w2[i]+=bt*k;
                k*=2;
            }

            w3[i]=0;
            k=1;
            for (j=9; j<12; j++) {
                bt=s3[i]*t[j].parity();
                t[j].fshr(1);
                t[j].dec(bt>>1);
                t[j].norm();
                w3[i]+=bt*k;
                k*=2;
            }
            w4[i]=0;
            k=1;
            for (j=13; j<16; j++) {
                bt=s4[i]*t[j].parity();
                t[j].fshr(1);
                t[j].dec(bt>>1);
                t[j].norm();
                w4[i]+=bt*k;
                k*=2;
            }
        }

        // Main loop
        P.select(T1,2*w1[nb-1]+1);
        W.select(T2,2*w2[nb-1]+1);
        P.add(W);
        W.select(T3,2*w3[nb-1]+1);
        P.add(W);
        W.select(T4,2*w4[nb-1]+1);
        P.add(W);
        for (i=nb-2;i>=0;i--) {
            P.dbl();
            W.select(T1,2*w1[i]+s1[i]);
            P.add(W);
            W.select(T2,2*w2[i]+s2[i]);
            P.add(W);
            W.select(T3,2*w3[i]+s3[i]);
            P.add(W);
            W.select(T4,2*w4[i]+s4[i]);
            P.add(W);
        }

        // apply correction
        W.copy(P);
        W.sub(Q[0]);
        P.cmove(W,pb1);

        W.copy(P);
        W.sub(Q[4]);
        P.cmove(W,pb2);

        W.copy(P);
        W.sub(Q[8]);
        P.cmove(W,pb3);

        W.copy(P);
        W.sub(Q[12]);
        P.cmove(W,pb4);

        P.affine();
        return P;
    };

    /* return 1 if b==c, no branching */
    ECP8.teq = function(b, c) {
        var x = b ^ c;
        x -= 1; // if x=0, x now -1
        return ((x >> 31) & 1);
    };

    /* needed for SOK */
    ECP8.mapit = function(h) {
        var F=ECP8.frob_constants(),
            q, x, one, Q, X, X2, X4,
            xQ, x2Q, x3Q, x4Q, x5Q, x6Q, x7Q, x8Q;

        q = new ctx.BIG(0);
        q.rcopy(ctx.ROM_FIELD.Modulus);
        x = ctx.BIG.fromBytes(h);
        one = new ctx.BIG(1);
        x.mod(q);

        for (;;) {
            X2 = new ctx.FP2(one, x);
            X4 = new ctx.FP4(X2);
            X = new ctx.FP8(X4);
            Q = new ECP8();
            Q.setx(X);
            if (!Q.is_infinity()) {
                break;
            }
            x.inc(1);
            x.norm();
        }

        /* Fast Hashing to G2 - Fuentes-Castaneda, Knapp and Rodriguez-Henriquez */
        x = new ctx.BIG(0);
        x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);


        xQ = Q.mul(x);
        x2Q = xQ.mul(x);
        x3Q = x2Q.mul(x);
        x4Q = x3Q.mul(x);
        x5Q = x4Q.mul(x);
        x6Q = x5Q.mul(x);
        x7Q = x6Q.mul(x);
        x8Q = x7Q.mul(x);

        if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
            xQ.neg();
            x3Q.neg();
            x5Q.neg();
            x7Q.neg();
        }

        x8Q.sub(x7Q);
        x8Q.sub(Q);

        x7Q.sub(x6Q);
        x7Q.frob(F,1);

        x6Q.sub(x5Q);
        x6Q.frob(F,2);

        x5Q.sub(x4Q);
        x5Q.frob(F,3);

        x4Q.sub(x3Q);
        x4Q.frob(F,4);

        x3Q.sub(x2Q);
        x3Q.frob(F,5);

        x2Q.sub(xQ);
        x2Q.frob(F,6);

        xQ.sub(Q);
        xQ.frob(F,7);

        Q.dbl();
        Q.frob(F,8);

        Q.add(x8Q);
        Q.add(x7Q);
        Q.add(x6Q);
        Q.add(x5Q);

        Q.add(x4Q);
        Q.add(x3Q);
        Q.add(x2Q);
        Q.add(xQ);

        Q.affine();
        return Q;
    };

    ECP8.frob_constants = function() {
        var fa = new ctx.BIG(0),
            fb = new ctx.BIG(0),
            F=[],
            X, F0, F1, F2;

        fa.rcopy(ctx.ROM_FIELD.Fra);
        fb.rcopy(ctx.ROM_FIELD.Frb);
        X = new ctx.FP2(fa, fb);

        F0=new ctx.FP2(X); F0.sqr();
        F2=new ctx.FP2(F0);
        F2.mul_ip(); F2.norm();
        F1=new ctx.FP2(F2); F1.sqr();
        F2.mul(F1);

        F2.mul_ip(); F2.norm();

        F1.copy(X);
        if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
            F1.mul_ip();
            F1.inverse();
            F0.copy(F1); F0.sqr();
        }
        F0.mul_ip(); F0.norm();
        F1.mul(F0);

        F[0]=new ctx.FP2(F0); F[1]=new ctx.FP2(F1); F[2]=new ctx.FP2(F2);
        return F;
    };

    return ECP8;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* AMCL FF number class */

function FF(ctx) {

    /* General purpose Constructor */
    var FF = function(n) {
        this.v = new Array(n);
        this.length = n;
        for (var i = 0; i < n; i++) {
            this.v[i] = new ctx.BIG(0);
        }
    };

    FF.FFLEN = ctx.config["@ML"];
    FF.P_MBITS = ctx.BIG.MODBYTES * 8;
    FF.P_OMASK = ((-1) << (FF.P_MBITS % ctx.BIG.BASEBITS));
    FF.P_FEXCESS = (1 << (ctx.BIG.BASEBITS * ctx.BIG.NLEN - FF.P_MBITS - 1));
    FF.P_TBITS = (FF.P_MBITS % ctx.BIG.BASEBITS);
    FF.FF_BITS = (ctx.BIG.BIGBITS * FF.FFLEN);
    /* Useful for half-size RSA private key operations */
    FF.HFLEN = (FF.FFLEN / 2);

    FF.prototype = {
        /* set to zero */

        P_EXCESS: function() {
            return ((this.v[this.length - 1].get(ctx.BIG.NLEN - 1) & FF.P_OMASK) >> (FF.P_TBITS)) + 1;
        },

        zero: function() {
            for (var i = 0; i < this.length; i++) {
                this.v[i].zero();
            }

            return this;
        },

        getlen: function() {
            return this.length;
        },

        /* set to integer */
        set: function(m) {
            this.zero();
            this.v[0].set(0, (m & ctx.BIG.BMASK));
            this.v[0].set(1, (m >> ctx.BIG.BASEBITS));
        },
        /* copy from FF b */
        copy: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].copy(b.v[i]);
            }
        },
        /* copy from FF b */
        rcopy: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].rcopy(b[i]);
            }
        },
        /* x=y<<n */
        dsucopy: function(b) {
            for (var i = 0; i < b.length; i++) {
                this.v[b.length + i].copy(b.v[i]);
                this.v[i].zero();
            }
        },
        /* x=y */
        dscopy: function(b) {
            for (var i = 0; i < b.length; i++) {
                this.v[i].copy(b.v[i]);
                this.v[b.length + i].zero();
            }
        },

        /* x=y>>n */
        sducopy: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].copy(b.v[this.length + i]);
            }
        },
        one: function() {
            this.v[0].one();
            for (var i = 1; i < this.length; i++) {
                this.v[i].zero();
            }
        },
        /* test equals 0 */
        iszilch: function() {
            for (var i = 0; i < this.length; i++) {
                if (!this.v[i].iszilch()) {
                    return false;
                }
            }

            return true;
        },
        /* shift right by BIGBITS-bit words */
        shrw: function(n) {
            for (var i = 0; i < n; i++) {
                this.v[i].copy(this.v[i + n]);
                this.v[i + n].zero();
            }
        },

        /* shift left by BIGBITS-bit words */
        shlw: function(n) {
            for (var i = 0; i < n; i++) {
                this.v[n + i].copy(this.v[i]);
                this.v[i].zero();
            }
        },
        /* extract last bit */
        parity: function() {
            return this.v[0].parity();
        },

        lastbits: function(m) {
            return this.v[0].lastbits(m);
        },

        /* recursive add */
        radd: function(vp, x, xp, y, yp, n) {
            for (var i = 0; i < n; i++) {
                this.v[vp + i].copy(x.v[xp + i]);
                this.v[vp + i].add(y.v[yp + i]);
            }
        },

        /* recursive inc */
        rinc: function(vp, y, yp, n) {
            for (var i = 0; i < n; i++) {
                this.v[vp + i].add(y.v[yp + i]);
            }
        },

        /* recursive sub */
        rsub: function(vp, x, xp, y, yp, n) {
            for (var i = 0; i < n; i++) {
                this.v[vp + i].copy(x.v[xp + i]);
                this.v[vp + i].sub(y.v[yp + i]);
            }
        },

        /* recursive dec */
        rdec: function(vp, y, yp, n) {
            for (var i = 0; i < n; i++) {
                this.v[vp + i].sub(y.v[yp + i]);
            }
        },

        /* simple add */
        add: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].add(b.v[i]);
            }
        },

        /* simple sub */
        sub: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].sub(b.v[i]);
            }
        },

        /* reverse sub */
        revsub: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].rsub(b.v[i]);
            }
        },

        /* increment/decrement by a small integer */
        inc: function(m) {
            this.v[0].inc(m);
            this.norm();
        },

        dec: function(m) {
            this.v[0].dec(m);
            this.norm();
        },

        /* normalise - but hold any overflow in top part unless n<0 */
        rnorm: function(vp, n) {
            var trunc = false,
                i, carry;

            /* -v n signals to do truncation */
            if (n < 0) {
                n = -n;
                trunc = true;
            }

            for (i = 0; i < n - 1; i++) {
                carry = this.v[vp + i].norm();
                this.v[vp + i].xortop(carry << FF.P_TBITS);
                this.v[vp + i + 1].inc(carry);
            }
            carry = this.v[vp + n - 1].norm();

            if (trunc) {
                this.v[vp + n - 1].xortop(carry << FF.P_TBITS);
            }

            return this;
        },

        norm: function() {
            this.rnorm(0, this.length);
        },

        /* shift left by one bit */
        shl: function() {
            var delay_carry = 0,
                i, carry;

            for (i = 0; i < this.length - 1; i++) {
                carry = this.v[i].fshl(1);
                this.v[i].inc(delay_carry);
                this.v[i].xortop(carry << FF.P_TBITS);
                delay_carry = carry;
            }

            this.v[this.length - 1].fshl(1);
            this.v[this.length - 1].inc(delay_carry);
        },

        /* shift right by one bit */
        shr: function() {
            var i, carry;

            for (i = this.length - 1; i > 0; i--) {
                carry = this.v[i].fshr(1);
                this.v[i - 1].ortop(carry << FF.P_TBITS);
            }

            this.v[0].fshr(1);
        },

        /* Convert to Hex String */
        toString: function() {
            var s = "",
                i;

            this.norm();

            for (i = this.length - 1; i >= 0; i--) {
                s += this.v[i].toString();
            }

            return s;
        },
        /* Convert FFs to/from byte arrays */
        toBytes: function(b) {
            var i;

            for (i = 0; i < this.length; i++) {
                this.v[i].tobytearray(b, (this.length - i - 1) * ctx.BIG.MODBYTES);
            }
        },

        /* z=x*y, t is workspace */
        karmul: function(vp, x, xp, y, yp, t, tp, n) {
            var nd2, d;

            if (n === 1) {
                x.v[xp].norm();
                y.v[yp].norm();
                d = ctx.BIG.mul(x.v[xp], y.v[yp]);
                this.v[vp + 1] = d.split(8 * ctx.BIG.MODBYTES);
                this.v[vp].copy(d);

                return;
            }

            nd2 = n / 2;
            this.radd(vp, x, xp, x, xp + nd2, nd2);
            this.rnorm(vp, nd2); /* Important - required for 32-bit build */
            this.radd(vp + nd2, y, yp, y, yp + nd2, nd2);
            this.rnorm(vp + nd2, nd2); /* Important - required for 32-bit build */
            t.karmul(tp, this, vp, this, vp + nd2, t, tp + n, nd2);
            this.karmul(vp, x, xp, y, yp, t, tp + n, nd2);
            this.karmul(vp + n, x, xp + nd2, y, yp + nd2, t, tp + n, nd2);
            t.rdec(tp, this, vp, n);
            t.rdec(tp, this, vp + n, n);
            this.rinc(vp + nd2, t, tp, n);
            this.rnorm(vp, 2 * n);
        },

        karsqr: function(vp, x, xp, t, tp, n) {
            var nd2, d;

            if (n === 1) {
                x.v[xp].norm();
                d = ctx.BIG.sqr(x.v[xp]);
                this.v[vp + 1].copy(d.split(8 * ctx.BIG.MODBYTES));
                this.v[vp].copy(d);

                return;
            }

            nd2 = n / 2;
            this.karsqr(vp, x, xp, t, tp + n, nd2);
            this.karsqr(vp + n, x, xp + nd2, t, tp + n, nd2);
            t.karmul(tp, x, xp, x, xp + nd2, t, tp + n, nd2);
            this.rinc(vp + nd2, t, tp, n);
            this.rinc(vp + nd2, t, tp, n);
            this.rnorm(vp + nd2, n);
        },

        /* Calculates Least Significant bottom half of x*y */
        karmul_lower: function(vp, x, xp, y, yp, t, tp, n) {
            var nd2;

            /* only calculate bottom half of product */
            if (n === 1) {
                this.v[vp].copy(ctx.BIG.smul(x.v[xp], y.v[yp]));

                return;
            }

            nd2 = n / 2;

            this.karmul(vp, x, xp, y, yp, t, tp + n, nd2);
            t.karmul_lower(tp, x, xp + nd2, y, yp, t, tp + n, nd2);
            this.rinc(vp + nd2, t, tp, nd2);
            t.karmul_lower(tp, x, xp, y, yp + nd2, t, tp + n, nd2);

            this.rinc(vp + nd2, t, tp, nd2);
            this.rnorm(vp + nd2, -nd2); /* truncate it */
        },

        /* Calculates Most Significant upper half of x*y, given lower part */
        karmul_upper: function(x, y, t, n) {
            var nd2;

            nd2 = n / 2;
            this.radd(n, x, 0, x, nd2, nd2);
            this.radd(n + nd2, y, 0, y, nd2, nd2);
            this.rnorm(n, nd2);
            this.rnorm(n + nd2, nd2);

            t.karmul(0, this, n + nd2, this, n, t, n, nd2); /* t = (a0+a1)(b0+b1) */
            this.karmul(n, x, nd2, y, nd2, t, n, nd2); /* z[n]= a1*b1 */
            /* z[0-nd2]=l(a0b0) z[nd2-n]= h(a0b0)+l(t)-l(a0b0)-l(a1b1) */
            t.rdec(0, this, n, n); /* t=t-a1b1  */
            this.rinc(nd2, this, 0, nd2); /* z[nd2-n]+=l(a0b0) = h(a0b0)+l(t)-l(a1b1)  */
            this.rdec(nd2, t, 0, nd2); /* z[nd2-n]=h(a0b0)+l(t)-l(a1b1)-l(t-a1b1)=h(a0b0) */
            this.rnorm(0, -n); /* a0b0 now in z - truncate it */
            t.rdec(0, this, 0, n); /* (a0+a1)(b0+b1) - a0b0 */
            this.rinc(nd2, t, 0, n);

            this.rnorm(nd2, n);
        },

        /* return low part of product this*y */
        lmul: function(y) {
            var n = this.length,
                t = new FF(2 * n),
                x = new FF(n);

            x.copy(this);
            this.karmul_lower(0, x, 0, y, 0, t, 0, n);
        },

        /* Set b=b mod c */
        mod: function(c) {
            var k = 0;

            this.norm();
            if (FF.comp(this, c) < 0) {
                return;
            }

            do {
                c.shl();
                k++;
            } while (FF.comp(this, c) >= 0);

            while (k > 0) {
                c.shr();

                if (FF.comp(this, c) >= 0) {
                    this.sub(c);
                    this.norm();
                }

                k--;
            }
        },

        /* /Fast Karatsuba Montgomery reduction
         * return This mod modulus, N is modulus, ND is Montgomery Constant */
        reduce: function(N, ND) {
            var n = N.length,
                t = new FF(2 * n),
                r = new FF(n),
                m = new FF(n);

            r.sducopy(this);
            m.karmul_lower(0, this, 0, ND, 0, t, 0, n);
            this.karmul_upper(N, m, t, n);
            m.sducopy(this);

            r.add(N);
            r.sub(m);
            r.norm();

            return r;
        },

        /* Set r=this mod b */
        /* this is of length - 2*n */
        /* r,b is of length - n */
        dmod: function(b) {
            var n = b.length,
                m = new FF(2 * n),
                x = new FF(2 * n),
                r = new FF(n),
                k;

            x.copy(this);
            x.norm();
            m.dsucopy(b);
            k = ctx.BIG.BIGBITS * n;

            while (FF.comp(x, m) >= 0) {
                x.sub(m);
                x.norm();
            }

            while (k > 0) {
                m.shr();

                if (FF.comp(x, m) >= 0) {
                    x.sub(m);
                    x.norm();
                }

                k--;
            }

            r.copy(x);
            r.mod(b);

            return r;
        },

        /* Set return=1/this mod p. Binary method - a<p on entry */
        invmodp: function(p) {
            var n = p.length,
                u = new FF(n),
                v = new FF(n),
                x1 = new FF(n),
                x2 = new FF(n),
                t = new FF(n),
                one = new FF(n);

            one.one();
            u.copy(this);
            v.copy(p);
            x1.copy(one);
            x2.zero();

            // reduce n in here as well!
            while (FF.comp(u, one) !== 0 && FF.comp(v, one) !== 0) {
                while (u.parity() === 0) {
                    u.shr();
                    if (x1.parity() !== 0) {
                        x1.add(p);
                        x1.norm();
                    }
                    x1.shr();
                }

                while (v.parity() === 0) {
                    v.shr();
                    if (x2.parity() !== 0) {
                        x2.add(p);
                        x2.norm();
                    }
                    x2.shr();
                }

                if (FF.comp(u, v) >= 0) {
                    u.sub(v);
                    u.norm();

                    if (FF.comp(x1, x2) >= 0) {
                        x1.sub(x2);
                    } else {
                        t.copy(p);
                        t.sub(x2);
                        x1.add(t);
                    }

                    x1.norm();
                } else {
                    v.sub(u);
                    v.norm();

                    if (FF.comp(x2, x1) >= 0) {
                        x2.sub(x1);
                    } else {
                        t.copy(p);
                        t.sub(x1);
                        x2.add(t);
                    }

                    x2.norm();
                }
            }

            if (FF.comp(u, one) === 0) {
                this.copy(x1);
            } else {
                this.copy(x2);
            }
        },

        /* nresidue mod m */
        nres: function(m) {
            var n = m.length,
                d;

            if (n === 1) {
                d = new ctx.DBIG(0);
                d.hcopy(this.v[0]);
                d.shl(ctx.BIG.NLEN * ctx.BIG.BASEBITS);
                this.v[0].copy(d.mod(m.v[0]));
            } else {
                d = new FF(2 * n);
                d.dsucopy(this);
                this.copy(d.dmod(m));
            }
        },

        redc: function(m, ND) {
            var n = m.length,
                d;

            if (n === 1) {
                d = new ctx.DBIG(0);
                d.hcopy(this.v[0]);
                this.v[0].copy(ctx.BIG.monty(m.v[0], (1 << ctx.BIG.BASEBITS) - ND.v[0].w[0], d));
            } else {
                d = new FF(2 * n);
                this.mod(m);
                d.dscopy(this);
                this.copy(d.reduce(m, ND));
                this.mod(m);
            }
        },

        mod2m: function(m) {
            for (var i = m; i < this.length; i++) {
                this.v[i].zero();
            }
        },

        /* U=1/a mod 2^m - Arazi & Qi */
        invmod2m: function() {
            var n = this.length,
                b = new FF(n),
                c = new FF(n),
                U = new FF(n),
                t, i;

            U.zero();
            U.v[0].copy(this.v[0]);
            U.v[0].invmod2m();

            for (i = 1; i < n; i <<= 1) {
                b.copy(this);
                b.mod2m(i);
                t = FF.mul(U, b);
                t.shrw(i);
                b.copy(t);
                c.copy(this);
                c.shrw(i);
                c.mod2m(i);
                c.lmul(U);
                c.mod2m(i);

                b.add(c);
                b.norm();
                b.lmul(U);
                b.mod2m(i);

                c.one();
                c.shlw(i);
                b.revsub(c);
                b.norm();
                b.shlw(i);
                U.add(b);
            }
            U.norm();

            return U;
        },

        random: function(rng) {
            var n = this.length,
                i;

            for (i = 0; i < n; i++) {
                this.v[i].copy(ctx.BIG.random(rng));
            }

            /* make sure top bit is 1 */
            while (this.v[n - 1].nbits() < ctx.BIG.MODBYTES * 8) {
                this.v[n - 1].copy(ctx.BIG.random(rng));
            }
        },

        /* generate random x */
        randomnum: function(p, rng) {
            var n = this.length,
                d = new FF(2 * n),
                i;

            for (i = 0; i < 2 * n; i++) {
                d.v[i].copy(ctx.BIG.random(rng));
            }

            this.copy(d.dmod(p));
        },

        /* this*=y mod p */
        modmul: function(y, p, nd) {
            var ex = this.P_EXCESS(),
                ey = y.P_EXCESS(),
                n = p.length,
                d;

            if ((ex + 1) >= Math.floor((FF.P_FEXCESS - 1) / (ey + 1))) {
                this.mod(p);
            }

            if (n === 1) {
                d = ctx.BIG.mul(this.v[0], y.v[0]);
                this.v[0].copy(ctx.BIG.monty(p.v[0], (1 << ctx.BIG.BASEBITS) - nd.v[0].w[0], d));
            } else {
                d = FF.mul(this, y);
                this.copy(d.reduce(p, nd));
            }
        },

        /* this*=y mod p */
        modsqr: function(p, nd) {
            var ex = this.P_EXCESS(),
                n, d;

            if ((ex + 1) >= Math.floor((FF.P_FEXCESS - 1) / (ex + 1))) {
                this.mod(p);
            }
            n = p.length;

            if (n === 1) {
                d = ctx.BIG.sqr(this.v[0]);
                this.v[0].copy(ctx.BIG.monty(p.v[0], (1 << ctx.BIG.BASEBITS) - nd.v[0].w[0], d));
            } else {
                d = FF.sqr(this);
                this.copy(d.reduce(p, nd));
            }
        },

        /* this=this^e mod p using side-channel resistant Montgomery Ladder, for large e */
        skpow: function(e, p) {
            var n = p.length,
                R0 = new FF(n),
                R1 = new FF(n),
                ND = p.invmod2m(),
                i, b;

            this.mod(p);
            R0.one();
            R1.copy(this);
            R0.nres(p);
            R1.nres(p);

            for (i = 8 * ctx.BIG.MODBYTES * n - 1; i >= 0; i--) {
                b = e.v[Math.floor(i / ctx.BIG.BIGBITS)].bit(i % ctx.BIG.BIGBITS);

                this.copy(R0);
                this.modmul(R1, p, ND);

                FF.cswap(R0, R1, b);
                R0.modsqr(p, ND);

                R1.copy(this);
                FF.cswap(R0, R1, b);
            }

            this.copy(R0);
            this.redc(p, ND);
        },

        /* this =this^e mod p using side-channel resistant Montgomery Ladder, for short e */
        skspow: function(e, p) {
            var n = p.length,
                R0 = new FF(n),
                R1 = new FF(n),
                ND = p.invmod2m(),
                i, b;

            this.mod(p);
            R0.one();
            R1.copy(this);
            R0.nres(p);
            R1.nres(p);

            for (i = 8 * ctx.BIG.MODBYTES - 1; i >= 0; i--) {
                b = e.bit(i);
                this.copy(R0);
                this.modmul(R1, p, ND);

                FF.cswap(R0, R1, b);
                R0.modsqr(p, ND);

                R1.copy(this);
                FF.cswap(R0, R1, b);
            }
            this.copy(R0);
            this.redc(p, ND);
        },

        /* raise to an integer power - right-to-left method */
        power: function(e, p) {
            var n = p.length,
                f = true,
                w = new FF(n),
                ND = p.invmod2m();

            w.copy(this);
            w.nres(p);

            if (e == 2) {
                this.copy(w);
                this.modsqr(p, ND);
            } else {
                for (;;) {
                    if (e % 2 == 1) {
                        if (f) {
                            this.copy(w);
                        } else {
                            this.modmul(w, p, ND);
                        }
                        f = false;
                    }
                    e >>= 1;
                    if (e === 0) {
                        break;
                    }
                    w.modsqr(p, ND);
                }
            }

            this.redc(p, ND);
        },

        /* this=this^e mod p, faster but not side channel resistant */
        pow: function(e, p) {
            var n = p.length,
                w = new FF(n),
                ND = p.invmod2m(),
                i, b;

            w.copy(this);
            this.one();
            this.nres(p);
            w.nres(p);

            for (i = 8 * ctx.BIG.MODBYTES * n - 1; i >= 0; i--) {
                this.modsqr(p, ND);
                b = e.v[Math.floor(i / ctx.BIG.BIGBITS)].bit(i % ctx.BIG.BIGBITS);
                if (b === 1) {
                    this.modmul(w, p, ND);
                }
            }

            this.redc(p, ND);
        },

        /* double exponentiation r=x^e.y^f mod p */
        pow2: function(e, y, f, p) {
            var n = p.length,
                xn = new FF(n),
                yn = new FF(n),
                xy = new FF(n),
                ND = p.invmod2m(),
                i, eb, fb;

            xn.copy(this);
            yn.copy(y);
            xn.nres(p);
            yn.nres(p);
            xy.copy(xn);
            xy.modmul(yn, p, ND);
            this.one();
            this.nres(p);

            for (i = 8 * ctx.BIG.MODBYTES - 1; i >= 0; i--) {
                eb = e.bit(i);
                fb = f.bit(i);
                this.modsqr(p, ND);

                if (eb == 1) {
                    if (fb == 1) {
                        this.modmul(xy, p, ND);
                    } else {
                        this.modmul(xn, p, ND);
                    }
                } else {
                    if (fb == 1) {
                        this.modmul(yn, p, ND);
                    }
                }
            }
            this.redc(p, ND);
        },

        /* quick and dirty check for common factor with n */
        cfactor: function(s) {
            var n = this.length,
                x = new FF(n),
                y = new FF(n),
                r, g;

            y.set(s);

            x.copy(this);
            x.norm();

            do {
                x.sub(y);
                x.norm();
                while (!x.iszilch() && x.parity() === 0) {
                    x.shr();
                }
            } while (FF.comp(x, y) > 0);

            g = x.v[0].get(0);
            r = FF.igcd(s, g);
            if (r > 1) {
                return true;
            }

            return false;
        }
    };

    /* compare x and y - must be normalised, and of same length */
    FF.comp = function(a, b) {
        var i, j;

        for (i = a.length - 1; i >= 0; i--) {
            j = ctx.BIG.comp(a.v[i], b.v[i]);
            if (j !== 0) {
                return j;
            }
        }

        return 0;
    };

    FF.fromBytes = function(x, b) {
        var i;

        for (i = 0; i < x.length; i++) {
            x.v[i] = ctx.BIG.frombytearray(b, (x.length - i - 1) * ctx.BIG.MODBYTES);
        }
    };

    /* in-place swapping using xor - side channel resistant - lengths must be the same */
    FF.cswap = function(a, b, d) {
        var i;

        for (i = 0; i < a.length; i++) {
            a.v[i].cswap(b.v[i], d);
        }
    };

    /* z=x*y. Assumes x and y are of same length. */
    FF.mul = function(x, y) {
        var n = x.length,
            z = new FF(2 * n),
            t = new FF(2 * n);

        z.karmul(0, x, 0, y, 0, t, 0, n);

        return z;
    };

    /* z=x^2 */
    FF.sqr = function(x) {
        var n = x.length,
            z = new FF(2 * n),
            t = new FF(2 * n);

        z.karsqr(0, x, 0, t, 0, n);

        return z;
    };

    FF.igcd = function(x, y) { /* integer GCD, returns GCD of x and y */
        var r;

        if (y === 0) {
            return x;
        }

        while ((r = x % y) !== 0) {
            x = y;
            y = r;
        }

        return y;
    };

    /* Miller-Rabin test for primality. Slow. */
    FF.prime = function(p, rng) {
        var n = p.length,
            s = 0,
            loop,
            d = new FF(n),
            x = new FF(n),
            unity = new FF(n),
            nm1 = new FF(n),
            sf = 4849845, /* 3*5*.. *19 */
            i, j;

        p.norm();

        if (p.cfactor(sf)) {
            return false;
        }

        unity.one();
        nm1.copy(p);
        nm1.sub(unity);
        nm1.norm();
        d.copy(nm1);

        while (d.parity() === 0) {
            d.shr();
            s++;
        }

        if (s === 0) {
            return false;
        }

        for (i = 0; i < 10; i++) {
            x.randomnum(p, rng);
            x.pow(d, p);

            if (FF.comp(x, unity) === 0 || FF.comp(x, nm1) === 0) {
                continue;
            }

            loop = false;

            for (j = 1; j < s; j++) {
                x.power(2, p);

                if (FF.comp(x, unity) === 0) {
                    return false;
                }

                if (FF.comp(x, nm1) === 0) {
                    loop = true;
                    break;
                }
            }
            if (loop) {
                continue;
            }

            return false;
        }

        return true;
    };

    return FF;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* Finite Field arithmetic */
/* AMCL mod p functions */

function FP(ctx) {

    /* General purpose Constructor */
    var FP = function(x) {
        if (x instanceof FP) {
            this.f = new ctx.BIG(x.f);
            this.XES = x.XES;
        } else {
            this.f = new ctx.BIG(x);
            this.nres();
        }
    };

    FP.NOT_SPECIAL = 0;
    FP.PSEUDO_MERSENNE = 1;
    FP.GENERALISED_MERSENNE = 2;
    FP.MONTGOMERY_FRIENDLY = 3;

    FP.MODBITS = ctx.config["@NBT"];
    FP.MOD8 = ctx.config["@M8"];
    FP.MODTYPE = ctx.config["@MT"];

    FP.FEXCESS = (1 << ctx.config["@SH"]); // 2^(BASEBITS*NLEN-MODBITS)
    FP.OMASK = (-1) << FP.TBITS;
    FP.TBITS = FP.MODBITS % ctx.BIG.BASEBITS;
    FP.TMASK = (1 << FP.TBITS) - 1;

    FP.prototype = {
        /* set this=0 */
        zero: function() {
            this.XES = 1;
            this.f.zero();
        },

        /* copy from a ctx.BIG in ROM */
        rcopy: function(y) {
            this.f.rcopy(y);
            this.nres();
        },

        /* copy from another ctx.BIG */
        bcopy: function(y) {
            this.f.copy(y);
            this.nres();
        },

        /* copy from another FP */
        copy: function(y) {
            this.XES = y.XES;
            this.f.copy(y.f);
        },

        /* conditional swap of a and b depending on d */
        cswap: function(b, d) {
            this.f.cswap(b.f, d);
            var t, c = d;
            c = ~(c - 1);
            t = c & (this.XES ^ b.XES);
            this.XES ^= t;
            b.XES ^= t;
        },

        /* conditional copy of b to a depending on d */
        cmove: function(b, d) {
            var c = d;

            c = ~(c - 1);

            this.f.cmove(b.f, d);
            this.XES ^= (this.XES ^ b.XES) & c;
        },

        /* convert to Montgomery n-residue form */
        nres: function() {
            var r, d;

            if (FP.MODTYPE != FP.PSEUDO_MERSENNE && FP.MODTYPE != FP.GENERALISED_MERSENNE) {
                r = new ctx.BIG();
                r.rcopy(ctx.ROM_FIELD.R2modp);

                d = ctx.BIG.mul(this.f, r);
                this.f.copy(FP.mod(d));
                this.XES = 2;
            } else {
                this.XES = 1;
            }

            return this;
        },

        /* convert back to regular form */
        redc: function() {
            var r = new ctx.BIG(0),
                d, w;

            r.copy(this.f);

            if (FP.MODTYPE != FP.PSEUDO_MERSENNE && FP.MODTYPE != FP.GENERALISED_MERSENNE) {
                d = new ctx.DBIG(0);
                d.hcopy(this.f);
                w = FP.mod(d);
                r.copy(w);
            }

            return r;
        },

        /* convert this to string */
        toString: function() {
            var s = this.redc().toString();
            return s;
        },

        /* test this=0 */
        iszilch: function() {
            this.reduce();
            return this.f.iszilch();
        },

        /* reduce this mod Modulus */
        reduce: function() {
            var p = new ctx.BIG(0);
            p.rcopy(ctx.ROM_FIELD.Modulus);
            this.f.mod(p);
            this.XES = 1;
        },

        /* set this=1 */
        one: function() {
            this.f.one();
            return this.nres();
        },

        /* normalise this */
        norm: function() {
            return this.f.norm();
        },

        /* this*=b mod Modulus */
        mul: function(b) {
            var d;

            if (this.XES * b.XES > FP.FEXCESS) {
                this.reduce();
            }

            d = ctx.BIG.mul(this.f, b.f);
            this.f.copy(FP.mod(d));
            this.XES = 2;

            return this;
        },

        /* this*=c mod Modulus where c is an int */
        imul: function(c) {
            var s = false,
                d, n;

            if (c < 0) {
                c = -c;
                s = true;
            }

            if (FP.MODTYPE == FP.PSEUDO_MERSENNE || FP.MODTYPE == FP.GENERALISED_MERSENNE) {
                d = this.f.pxmul(c);
                this.f.copy(FP.mod(d));
                this.XES = 2;
            } else {
                if (this.XES * c <= FP.FEXCESS) {
                    this.f.pmul(c);
                    this.XES *= c;
                } else {
                    n = new FP(c);
                    this.mul(n);
                }
            }

            if (s) {
                this.neg();
                this.norm();
            }
            return this;
        },

        /* this*=this mod Modulus */
        sqr: function() {
            var d, t;

            if (this.XES * this.XES > FP.FEXCESS) {
                this.reduce();
            }

            d = ctx.BIG.sqr(this.f);
            t = FP.mod(d);
            this.f.copy(t);
            this.XES = 2;

            return this;
        },

        /* this+=b */
        add: function(b) {
            this.f.add(b.f);
            this.XES += b.XES;

            if (this.XES > FP.FEXCESS) {
                this.reduce();
            }

            return this;
        },
        /* this=-this mod Modulus */
        neg: function() {
            var m = new ctx.BIG(0),
                sb;

            m.rcopy(ctx.ROM_FIELD.Modulus);

            sb = FP.logb2(this.XES - 1);

            m.fshl(sb);
            this.XES = (1 << sb);
            this.f.rsub(m);

            if (this.XES > FP.FEXCESS) {
                this.reduce();
            }

            return this;
        },

        /* this-=b */
        sub: function(b) {
            var n = new FP(0);

            n.copy(b);
            n.neg();
            this.add(n);

            return this;
        },

        rsub: function(b) {
            var n = new FP(0);

            n.copy(this);
            n.neg();
            this.copy(b);
            this.add(n);
        },

        /* this/=2 mod Modulus */
        div2: function() {
            var p;

            if (this.f.parity() === 0) {
                this.f.fshr(1);
            } else {
                p = new ctx.BIG(0);
                p.rcopy(ctx.ROM_FIELD.Modulus);

                this.f.add(p);
                this.f.norm();
                this.f.fshr(1);
            }

            return this;
        },

        /* this=1/this mod Modulus */
        inverse: function() {
            var m2=new ctx.BIG(0);

            m2.rcopy(ctx.ROM_FIELD.Modulus);
            m2.dec(2); m2.norm();
            this.copy(this.pow(m2));
            return this;

        },

        /* return TRUE if this==a */
        equals: function(a) {
            a.reduce();
            this.reduce();

            if (ctx.BIG.comp(a.f, this.f) === 0) {
                return true;
            }

            return false;
        },

        /* return this^e mod Modulus */
        pow: function(e) {
            var i,w=[],
                tb=[],
                t=new ctx.BIG(e),
                nb, lsbs, r;

            t.norm();
            nb= 1 + Math.floor((t.nbits() + 3) / 4);

            for (i=0;i<nb;i++) {
                lsbs=t.lastbits(4);
                t.dec(lsbs);
                t.norm();
                w[i]=lsbs;
                t.fshr(4);
            }
            tb[0]=new FP(1);
            tb[1]=new FP(this);
            for (i=2;i<16;i++) {
                tb[i]=new FP(tb[i-1]);
                tb[i].mul(this);
            }
            r=new FP(tb[w[nb-1]]);
            for (i=nb-2;i>=0;i--) {
                r.sqr();
                r.sqr();
                r.sqr();
                r.sqr();
                r.mul(tb[w[i]]);
            }
            r.reduce();
            return r;
        },

        /* return jacobi symbol (this/Modulus) */
        jacobi: function() {
            var p = new ctx.BIG(0),
                w = this.redc();

            p.rcopy(ctx.ROM_FIELD.Modulus);

            return w.jacobi(p);
        },

        /* return sqrt(this) mod Modulus */
        sqrt: function() {
            var b = new ctx.BIG(0),
                i, v, r;

            this.reduce();

            b.rcopy(ctx.ROM_FIELD.Modulus);

            if (FP.MOD8 == 5) {
                b.dec(5);
                b.norm();
                b.shr(3);
                i = new FP(0);
                i.copy(this);
                i.f.shl(1);
                v = i.pow(b);
                i.mul(v);
                i.mul(v);
                i.f.dec(1);
                r = new FP(0);
                r.copy(this);
                r.mul(v);
                r.mul(i);
                r.reduce();

                return r;
            } else {
                b.inc(1);
                b.norm();
                b.shr(2);

                return this.pow(b);
            }
        }

    };

    FP.logb2 = function(v) {
        var r;

        v |= v >>> 1;
        v |= v >>> 2;
        v |= v >>> 4;
        v |= v >>> 8;
        v |= v >>> 16;

        v = v - ((v >>> 1) & 0x55555555);
        v = (v & 0x33333333) + ((v >>> 2) & 0x33333333);
        r = ((v + (v >>> 4) & 0xF0F0F0F) * 0x1010101) >>> 24;

        return r;
    };

    /* reduce a ctx.DBIG to a ctx.BIG using a "special" modulus */
    FP.mod = function(d) {
        var b = new ctx.BIG(0),
            i, t, v, tw, tt, lo, carry, m, dd;

        if (FP.MODTYPE == FP.PSEUDO_MERSENNE) {
            t = d.split(FP.MODBITS);
            b.hcopy(d);

            if (ctx.ROM_FIELD.MConst != 1) {
                v = t.pmul(ctx.ROM_FIELD.MConst);
            } else {
                v = 0;
            }

            t.add(b);
            t.norm();

            tw = t.w[ctx.BIG.NLEN - 1];
            t.w[ctx.BIG.NLEN - 1] &= FP.TMASK;
            t.inc(ctx.ROM_FIELD.MConst * ((tw >> FP.TBITS) + (v << (ctx.BIG.BASEBITS - FP.TBITS))));
            t.norm();

            return t;
        }

        if (FP.MODTYPE == FP.MONTGOMERY_FRIENDLY) {
            for (i = 0; i < ctx.BIG.NLEN; i++) {
                d.w[ctx.BIG.NLEN + i] += d.muladd(d.w[i], ctx.ROM_FIELD.MConst - 1, d.w[i], ctx.BIG.NLEN + i - 1);
            }

            for (i = 0; i < ctx.BIG.NLEN; i++) {
                b.w[i] = d.w[ctx.BIG.NLEN + i];
            }

            b.norm();
        }

        // GoldiLocks Only
        if (FP.MODTYPE == FP.GENERALISED_MERSENNE) {
            t = d.split(FP.MODBITS);
            b.hcopy(d);
            b.add(t);
            dd = new ctx.DBIG(0);
            dd.hcopy(t);
            dd.shl(FP.MODBITS / 2);

            tt = dd.split(FP.MODBITS);
            lo = new ctx.BIG();
            lo.hcopy(dd);

            b.add(tt);
            b.add(lo);
            tt.shl(FP.MODBITS / 2);
            b.add(tt);

            carry = b.w[ctx.BIG.NLEN - 1] >> FP.TBITS;
            b.w[ctx.BIG.NLEN - 1] &= FP.TMASK;
            b.w[0] += carry;

            b.w[Math.floor(224 / ctx.BIG.BASEBITS)] += carry << (224 % ctx.BIG.BASEBITS);
            b.norm();
        }

        if (FP.MODTYPE == FP.NOT_SPECIAL) {
            m = new ctx.BIG(0);
            m.rcopy(ctx.ROM_FIELD.Modulus);

            b.copy(ctx.BIG.monty(m, ctx.ROM_FIELD.MConst, d));
        }

        return b;
    };

    return FP;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* AMCL Fp^12 functions */

/* FP12 elements are of the form a+i.b+i^2.c */

function FP12(ctx) {

    /* general purpose constructor */
    var FP12 = function(d, e, f) {
        if (d instanceof FP12) {
            this.a = new ctx.FP4(d.a);
            this.b = new ctx.FP4(d.b);
            this.c = new ctx.FP4(d.c);
        } else {
            this.a = new ctx.FP4(d);
            this.b = new ctx.FP4(e);
            this.c = new ctx.FP4(f);
        }
    };

    FP12.prototype = {
        /* reduce all components of this mod Modulus */
        reduce: function() {
            this.a.reduce();
            this.b.reduce();
            this.c.reduce();
        },

        /* normalize all components of this mod Modulus */
        norm: function() {
            this.a.norm();
            this.b.norm();
            this.c.norm();
        },

        /* test x==0 ? */
        iszilch: function() {
            this.reduce();
            return (this.a.iszilch() && this.b.iszilch() && this.c.iszilch());
        },

        /* test x==1 ? */
        isunity: function() {
            var one = new ctx.FP4(1);
            return (this.a.equals(one) && this.b.iszilch() && this.c.iszilch());
        },


        /* conditional copy of g to this depending on d */
        cmove: function(g, d) {
            this.a.cmove(g.a, d);
            this.b.cmove(g.b, d);
            this.c.cmove(g.c, d);
        },


        /* Constant time select from pre-computed table */
        select: function(g, b) {
            var invf = new FP12(0),
                m, babs;

            m = b >> 31;
            babs = (b ^ m) - m;
            babs = (babs - 1) / 2;

            this.cmove(g[0], FP12.teq(babs, 0));
            this.cmove(g[1], FP12.teq(babs, 1));
            this.cmove(g[2], FP12.teq(babs, 2));
            this.cmove(g[3], FP12.teq(babs, 3));
            this.cmove(g[4], FP12.teq(babs, 4));
            this.cmove(g[5], FP12.teq(babs, 5));
            this.cmove(g[6], FP12.teq(babs, 6));
            this.cmove(g[7], FP12.teq(babs, 7));

            invf.copy(this);
            invf.conj();
            this.cmove(invf, (m & 1));
        },

        /* extract a from this */
        geta: function() {
            return this.a;
        },

        /* extract b */
        getb: function() {
            return this.b;
        },

        /* extract c */
        getc: function() {
            return this.c;
        },

        /* return 1 if x==y, else 0 */
        equals: function(x) {
            return (this.a.equals(x.a) && this.b.equals(x.b) && this.c.equals(x.c));
        },

        /* copy this=x */
        copy: function(x) {
            this.a.copy(x.a);
            this.b.copy(x.b);
            this.c.copy(x.c);
        },

        /* set this=1 */
        one: function() {
            this.a.one();
            this.b.zero();
            this.c.zero();
        },

        /* this=conj(this) */
        conj: function() {
            this.a.conj();
            this.b.nconj();
            this.c.conj();
        },

        /* set this from 3 FP4s */
        set: function(d, e, f) {
            this.a.copy(d);
            this.b.copy(e);
            this.c.copy(f);
        },

        /* set this from one ctx.FP4 */
        seta: function(d) {
            this.a.copy(d);
            this.b.zero();
            this.c.zero();
        },

        /* Granger-Scott Unitary Squaring */
        usqr: function() {
            var A = new ctx.FP4(this.a),
                B = new ctx.FP4(this.c),
                C = new ctx.FP4(this.b),
                D = new ctx.FP4(0);

            this.a.sqr();
            D.copy(this.a);
            D.add(this.a);
            this.a.add(D);

            A.nconj();

            A.add(A);
            this.a.add(A);
            B.sqr();
            B.times_i();

            D.copy(B);
            D.add(B);
            B.add(D);

            C.sqr();
            D.copy(C);
            D.add(C);
            C.add(D);

            this.b.conj();
            this.b.add(this.b);
            this.c.nconj();

            this.c.add(this.c);
            this.b.add(B);
            this.c.add(C);
            this.reduce();
        },

        /* Chung-Hasan SQR2 method from http://cacr.uwaterloo.ca/techreports/2006/cacr2006-24.pdf */
        sqr: function() {
            var A = new ctx.FP4(this.a),
                B = new ctx.FP4(this.b),
                C = new ctx.FP4(this.c),
                D = new ctx.FP4(this.a);

            A.sqr();
            B.mul(this.c);
            B.add(B);
            C.sqr();
            D.mul(this.b);
            D.add(D);

            this.c.add(this.a);
            this.c.add(this.b);
            this.c.norm();
            this.c.sqr();

            this.a.copy(A);

            A.add(B);
            A.add(C);
            A.add(D);
            A.neg();
            B.times_i();
            C.times_i();

            this.a.add(B);
            this.b.copy(C);
            this.b.add(D);
            this.c.add(A);

            this.norm();
        },

        /* FP12 full multiplication this=this*y */
        mul: function(y) {
            var z0 = new ctx.FP4(this.a),
                z1 = new ctx.FP4(0),
                z2 = new ctx.FP4(this.b),
                z3 = new ctx.FP4(0),
                t0 = new ctx.FP4(this.a),
                t1 = new ctx.FP4(y.a);

            z0.mul(y.a);
            z2.mul(y.b);

            t0.add(this.b);
            t1.add(y.b);

            t0.norm();
            t1.norm();

            z1.copy(t0);
            z1.mul(t1);
            t0.copy(this.b);
            t0.add(this.c);

            t1.copy(y.b);
            t1.add(y.c);

            t0.norm();
            t1.norm();
            z3.copy(t0);
            z3.mul(t1);

            t0.copy(z0);
            t0.neg();
            t1.copy(z2);
            t1.neg();

            z1.add(t0);
            this.b.copy(z1);
            this.b.add(t1);

            z3.add(t1);
            z2.add(t0);

            t0.copy(this.a);
            t0.add(this.c);
            t1.copy(y.a);
            t1.add(y.c);

            t0.norm();
            t1.norm();

            t0.mul(t1);
            z2.add(t0);

            t0.copy(this.c);
            t0.mul(y.c);
            t1.copy(t0);
            t1.neg();

            this.c.copy(z2);
            this.c.add(t1);
            z3.add(t1);
            t0.times_i();
            this.b.add(t0);
            z3.times_i();
            this.a.copy(z0);
            this.a.add(z3);

            this.norm();
        },

        /* Special case this*=y that arises from special form of ATE pairing line function */
        smul: function(y, twist) {
            var z0, z1, z2, z3, t0, t1;

            if (twist == ctx.ECP.D_TYPE) {

                z0 = new ctx.FP4(this.a);
                z2 = new ctx.FP4(this.b);
                z3 = new ctx.FP4(this.b);
                t0 = new ctx.FP4(0);
                t1 = new ctx.FP4(y.a);

                z0.mul(y.a);
                z2.pmul(y.b.real());
                this.b.add(this.a);
                t1.real().add(y.b.real());

                this.b.norm();
                t1.norm();

                this.b.mul(t1);
                z3.add(this.c);
                z3.norm();
                z3.pmul(y.b.real());

                t0.copy(z0);
                t0.neg();
                t1.copy(z2);
                t1.neg();

                this.b.add(t0);

                this.b.add(t1);
                z3.add(t1);
                z2.add(t0);

                t0.copy(this.a);
                t0.add(this.c);
                t0.norm();
                t0.mul(y.a);
                this.c.copy(z2);
                this.c.add(t0);

                z3.times_i();
                this.a.copy(z0);
                this.a.add(z3);
            }

            if (twist == ctx.ECP.M_TYPE) {
                z0=new ctx.FP4(this.a);
                z1=new ctx.FP4(0);
                z2=new ctx.FP4(0);
                z3=new ctx.FP4(0);
                t0=new ctx.FP4(this.a);
                t1=new ctx.FP4(0);

                z0.mul(y.a);
                t0.add(this.b);
                t0.norm();

                z1.copy(t0); z1.mul(y.a);
                t0.copy(this.b); t0.add(this.c);
                t0.norm();

                z3.copy(t0);
                z3.pmul(y.c.getb());
                z3.times_i();

                t0.copy(z0); t0.neg();

                z1.add(t0);
                this.b.copy(z1);
                z2.copy(t0);

                t0.copy(this.a); t0.add(this.c);
                t1.copy(y.a); t1.add(y.c);

                t0.norm();
                t1.norm();

                t0.mul(t1);
                z2.add(t0);

                t0.copy(this.c);

                t0.pmul(y.c.getb());
                t0.times_i();

                t1.copy(t0); t1.neg();

                this.c.copy(z2); this.c.add(t1);
                z3.add(t1);
                t0.times_i();
                this.b.add(t0);
                z3.norm();
                z3.times_i();
                this.a.copy(z0); this.a.add(z3);
            }

            this.norm();
        },

        /* this=1/this */
        inverse: function() {
            var f0 = new ctx.FP4(this.a),
                f1 = new ctx.FP4(this.b),
                f2 = new ctx.FP4(this.a),
                f3 = new ctx.FP4(0);

            f0.sqr();
            f1.mul(this.c);
            f1.times_i();
            f0.sub(f1);
            f0.norm();

            f1.copy(this.c);
            f1.sqr();
            f1.times_i();
            f2.mul(this.b);
            f1.sub(f2);
            f1.norm();

            f2.copy(this.b);
            f2.sqr();
            f3.copy(this.a);
            f3.mul(this.c);
            f2.sub(f3);
            f2.norm();

            f3.copy(this.b);
            f3.mul(f2);
            f3.times_i();
            this.a.mul(f0);
            f3.add(this.a);
            this.c.mul(f1);
            this.c.times_i();

            f3.add(this.c);
            f3.norm();
            f3.inverse();
            this.a.copy(f0);
            this.a.mul(f3);
            this.b.copy(f1);
            this.b.mul(f3);
            this.c.copy(f2);
            this.c.mul(f3);
        },

        /* this=this^p, where p=Modulus, using Frobenius */
        frob: function(f) {
            var f2 = new ctx.FP2(f),
                f3 = new ctx.FP2(f);

            f2.sqr();
            f3.mul(f2);

            this.a.frob(f3);
            this.b.frob(f3);
            this.c.frob(f3);

            this.b.pmul(f);
            this.c.pmul(f2);
        },

        /* trace function */
        trace: function() {
            var t = new ctx.FP4(0);

            t.copy(this.a);
            t.imul(3);
            t.reduce();

            return t;
        },

        /* convert this to hex string */
        toString: function() {
            return ("[" + this.a.toString() + "," + this.b.toString() + "," + this.c.toString() + "]");
        },

        /* convert this to byte array */
        toBytes: function(w) {
            var t = [],
                i;

            this.a.geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i] = t[i];
            }
            this.a.geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + ctx.BIG.MODBYTES] = t[i];
            }
            this.a.getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 2 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 3 * ctx.BIG.MODBYTES] = t[i];
            }

            this.b.geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 4 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 5 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 6 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 7 * ctx.BIG.MODBYTES] = t[i];
            }

            this.c.geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 8 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 9 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 10 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 11 * ctx.BIG.MODBYTES] = t[i];
            }
        },

        /* set this=this^e */
        pow: function(e) {
            var e3, w, nb, i, bt;

            this.norm();
            e.norm();

            e3 = new ctx.BIG(e);
            e3.pmul(3);
            e3.norm();

            w = new FP12(this);
            nb = e3.nbits();

            for (i = nb - 2; i >= 1; i--) {
                w.usqr();
                bt = e3.bit(i) - e.bit(i);

                if (bt == 1) {
                    w.mul(this);
                }
                if (bt == -1) {
                    this.conj();
                    w.mul(this);
                    this.conj();
                }
            }
            w.reduce();

            return w;
        },

        /* constant time powering by small integer of max length bts */
        pinpow: function(e, bts) {
            var R = [],
                i, b;

            R[0] = new FP12(1);
            R[1] = new FP12(this);

            for (i = bts - 1; i >= 0; i--) {
                b = (e >> i) & 1;
                R[1 - b].mul(R[b]);
                R[b].usqr();
            }

            this.copy(R[0]);
        },

        /* Faster compressed powering for unitary elements */
        compow: function(e, r) {
            var fa, fb, f, q, m, a, b, g1, g2, c, cp, cpm1, cpm2;

            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb);

            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_FIELD.Modulus);

            m = new ctx.BIG(q);
            m.mod(r);

            a = new ctx.BIG(e);
            a.mod(m);

            b = new ctx.BIG(e);
            b.div(m);

            g1 = new FP12(0);
            g2 = new FP12(0);
            g1.copy(this);

            c = g1.trace();

            if (b.iszilch()) {
                c=c.xtr_pow(e);
                return c;
            }

            g2.copy(g1);
            g2.frob(f);
            cp = g2.trace();
            g1.conj();
            g2.mul(g1);
            cpm1 = g2.trace();
            g2.mul(g1);
            cpm2 = g2.trace();

            c = c.xtr_pow2(cp, cpm1, cpm2, a, b);
            return c;
        }
    };

    /* convert from byte array to FP12 */
    FP12.fromBytes = function(w) {
        var t = [],
            i, a, b, c, d, e, f, g, r;

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 2 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 3 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        e = new ctx.FP4(c, d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 4 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 5 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 6 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 7 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        f = new ctx.FP4(c, d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 8 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 9 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 10 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 11 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        g = new ctx.FP4(c, d);

        r = new FP12(e, f, g);

        return r;
    };


    /* return 1 if b==c, no branching */
    FP12.teq = function(b, c) {
        var x = b ^ c;
        x -= 1; // if x=0, x now -1
        return ((x >> 31) & 1);
    };

    /* p=q0^u0.q1^u1.q2^u2.q3^u3 */
    // Bos & Costello https://eprint.iacr.org/2013/458.pdf
    // Faz-Hernandez & Longa & Sanchez  https://eprint.iacr.org/2013/158.pdf
    // Side channel attack secure
    FP12.pow4 = function(q, u) {
        var g = [],
            r = new FP12(0),
            p = new FP12(0),
            t = [],
            mt = new ctx.BIG(0),
            w = [],
            s = [],
            i, j, k, nb, bt, pb;

        for (i = 0; i < 4; i++) {
            t[i] = new ctx.BIG(u[i]); t[i].norm();
        }

        g[0] = new FP12(q[0]);
        g[1] = new FP12(g[0]); g[1].mul(q[1]);
        g[2] = new FP12(g[0]); g[2].mul(q[2]);
        g[3] = new FP12(g[1]); g[3].mul(q[2]);
        g[4] = new FP12(q[0]); g[4].mul(q[3]);
        g[5] = new FP12(g[1]); g[5].mul(q[3]);
        g[6] = new FP12(g[2]); g[6].mul(q[3]);
        g[7] = new FP12(g[3]); g[7].mul(q[3]);

        // Make it odd
        pb=1-t[0].parity();
        t[0].inc(pb);
        t[0].norm();

        // Number of bits
        mt.zero();
        for (i=0;i<4;i++) {
            mt.or(t[i]);
        }

        nb=1+mt.nbits();

        // Sign pivot
        s[nb-1]=1;
        for (i=0;i<nb-1;i++) {
            t[0].fshr(1);
            s[i]=2*t[0].parity()-1;
        }

        // Recoded exponent
        for (i=0; i<nb; i++) {
            w[i]=0;
            k=1;
            for (j=1; j<4; j++) {
                bt=s[i]*t[j].parity();
                t[j].fshr(1);
                t[j].dec(bt>>1);
                t[j].norm();
                w[i]+=bt*k;
                k*=2;
            }
        }

        // Main loop
        p.select(g,2*w[nb-1]+1);
        for (i=nb-2;i>=0;i--) {
            p.usqr();
            r.select(g,2*w[i]+s[i]);
            p.mul(r);
        }

        // apply correction
        r.copy(q[0]); r.conj();
        r.mul(p);
        p.cmove(r,pb);

        p.reduce();
        return p;
    };

    return FP12;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* Finite Field arithmetic  Fp^16 functions */

/* FP16 elements are of the form a+ib, where i is sqrt(sqrt(-1+sqrt(-1)))  */

function FP16(ctx) {

    /* general purpose constructor */
    var FP16 = function(c, d) {
        if (c instanceof FP16) {
            this.a = new ctx.FP8(c.a);
            this.b = new ctx.FP8(c.b);
        } else {
            this.a = new ctx.FP8(c);
            this.b = new ctx.FP8(d);
        }
    };

    FP16.prototype = {
        /* reduce all components of this mod Modulus */
        reduce: function() {
            this.a.reduce();
            this.b.reduce();
        },

        /* normalise all components of this mod Modulus */
        norm: function() {
            this.a.norm();
            this.b.norm();
        },

        /* test this==0 ? */
        iszilch: function() {
            this.reduce();
            return (this.a.iszilch() && this.b.iszilch());
        },

        /* test this==1 ? */
        isunity: function() {
            var one = new ctx.FP8(1);
            return (this.a.equals(one) && this.b.iszilch());
        },

        /* conditional copy of g to this depending on d */
        cmove: function(g, d) {
            this.a.cmove(g.a, d);
            this.b.cmove(g.b, d);
        },

        /* test is w real? That is in a+ib test b is zero */
        isreal: function() {
            return this.b.iszilch();
        },

        /* extract real part a */
        real: function() {
            return this.a;
        },

        geta: function() {
            return this.a;
        },

        /* extract imaginary part b */
        getb: function() {
            return this.b;
        },

        /* test this=x? */
        equals: function(x) {
            return (this.a.equals(x.a) && this.b.equals(x.b));
        },

        /* copy this=x */
        copy: function(x) {
            this.a.copy(x.a);
            this.b.copy(x.b);
        },

        /* this=0 */
        zero: function() {
            this.a.zero();
            this.b.zero();
        },

        /* this=1 */
        one: function() {
            this.a.one();
            this.b.zero();
        },

        /* set from two FP8s */
        set: function(c, d) {
            this.a.copy(c);
            this.b.copy(d);
        },

        /* set a */
        seta: function(c) {
            this.a.copy(c);
            this.b.zero();
        },

        /* this=-this */
        neg: function() {
            var m = new ctx.FP8(this.a),
                t = new ctx.FP8(0);

            this.norm();

            m.add(this.b);
            m.neg();
            t.copy(m);
            t.add(this.b);
            this.b.copy(m);
            this.b.add(this.a);
            this.a.copy(t);
            this.norm();
        },

        /* this=conjugate(this) */
        conj: function() {
            this.b.neg();
            this.norm();
        },

        /* this=-conjugate(this) */
        nconj: function() {
            this.a.neg();
            this.norm();
        },

        /* this+=x */
        add: function(x) {
            this.a.add(x.a);
            this.b.add(x.b);
        },

        /* this-=x */
        sub: function(x) {
            var m = new FP16(x);
            m.neg();
            this.add(m);
        },

        /* this*=s where s is FP8 */
        pmul: function(s) {
            this.a.mul(s);
            this.b.mul(s);
        },

        /* this*=s where s is FP2 */
        qmul: function(s) {
            this.a.qmul(s);
            this.b.qmul(s);
        },

        /* this*=c where s is int */
        imul: function(c) {
            this.a.imul(c);
            this.b.imul(c);
        },

        /* this*=this */
        sqr: function() {
            var t1 = new ctx.FP8(this.a),
                t2 = new ctx.FP8(this.b),
                t3 = new ctx.FP8(this.a);

            t3.mul(this.b);
            t1.add(this.b);
            t1.norm();
            t2.times_i();

            t2.add(this.a);
            t2.norm();
            this.a.copy(t1);

            this.a.mul(t2);

            t2.copy(t3);
            t2.times_i();
            t2.add(t3);

            t2.neg();

            this.a.add(t2);

            this.b.copy(t3);
            this.b.add(t3);

            this.norm();
        },

        /* this*=y */
        mul: function(y) {

            var t1 = new ctx.FP8(this.a),
                t2 = new ctx.FP8(this.b),
                t3 = new ctx.FP8(0),
                t4 = new ctx.FP8(this.b);

            t1.mul(y.a);
            t2.mul(y.b);
            t3.copy(y.b);
            t3.add(y.a);
            t4.add(this.a);

            t3.norm();
            t4.norm();

            t4.mul(t3);

            t3.copy(t1);
            t3.neg();
            t4.add(t3);

            t3.copy(t2);
            t3.neg();
            this.b.copy(t4);
            this.b.add(t3);

            t2.times_i();
            this.a.copy(t2);
            this.a.add(t1);

            this.norm();
        },

        /* convert to hex string */
        toString: function() {
            return ("[" + this.a.toString() + "," + this.b.toString() + "]");
        },

        /* this=1/this */
        inverse: function() {
            this.norm();

            var t1 = new ctx.FP8(this.a),
                t2 = new ctx.FP8(this.b);

            t1.sqr();
            t2.sqr();
            t2.times_i();
            t2.norm(); // ??
            t1.sub(t2);
            t1.inverse();
            this.a.mul(t1);
            t1.neg();
            t1.norm();
            this.b.mul(t1);
        },

        /* this*=i where i = sqrt(-1+sqrt(-1)) */
        times_i: function() {
            var s = new ctx.FP8(this.b),
                t = new ctx.FP8(this.a);

            s.times_i();
            this.b.copy(t);

            this.a.copy(s);
            this.norm();
        },

        times_i2: function() {
            this.a.times_i();
            this.b.times_i();
        },

        times_i4: function() {
            this.a.times_i2();
            this.b.times_i2();
        },


        /* this=this^q using Frobenius, where q is Modulus */
        frob: function(f) {
            var ff=new ctx.FP2(f); ff.sqr(); ff.norm();
            this.a.frob(ff);
            this.b.frob(ff);
            this.b.qmul(f);
            this.b.times_i();
        },

        /* this=this^e */
        pow: function(e) {
            this.norm();
            e.norm();

            var w = new FP16(this),
                z = new ctx.BIG(e),
                r = new FP16(1),
                bt;

            for (;;) {
                bt = z.parity();
                z.fshr(1);

                if (bt === 1) {
                    r.mul(w);
                }

                if (z.iszilch()) {
                    break;
                }

                w.sqr();
            }
            r.reduce();

            return r;
        },

        /* XTR xtr_a function */
        xtr_A: function(w, y, z) {
            var r = new FP16(w),
                t = new FP16(w);

            r.sub(y);
            r.norm();
            r.pmul(this.a);
            t.add(y);
            t.norm();
            t.pmul(this.b);
            t.times_i();

            this.copy(r);
            this.add(t);
            this.add(z);

            this.reduce();
        },

        /* XTR xtr_d function */
        xtr_D: function() {
            var w = new FP16(this);
            this.sqr();
            w.conj();
            w.add(w);
            this.sub(w);
            this.reduce();
        },

        /* r=x^n using XTR method on traces of FP12s */
        xtr_pow: function(n) {
            var a = new FP16(3),
                b = new FP16(this),
                c = new FP16(b),
                t = new FP16(0),
                r = new FP16(0),
                par, v, nb, i;

            c.xtr_D();

            n.norm();
            par = n.parity();
            v = new ctx.BIG(n);

            v.fshr(1);

            if (par === 0) {
                v.dec(1);
                v.norm();
            }

            nb = v.nbits();
            for (i = nb - 1; i >= 0; i--) {
                if (v.bit(i) != 1) {
                    t.copy(b);
                    this.conj();
                    c.conj();
                    b.xtr_A(a, this, c);
                    this.conj();
                    c.copy(t);
                    c.xtr_D();
                    a.xtr_D();
                } else {
                    t.copy(a);
                    t.conj();
                    a.copy(b);
                    a.xtr_D();
                    b.xtr_A(c, this, t);
                    c.xtr_D();
                }
            }

            if (par === 0) {
                r.copy(c);
            } else {
                r.copy(b);
            }
            r.reduce();

            return r;
        },

        /* r=ck^a.cl^n using XTR double exponentiation method on traces of FP12s. See Stam thesis. */
        xtr_pow2: function(ck, ckml, ckm2l, a, b) {
            a.norm();
            b.norm();

            var e = new ctx.BIG(a),
                d = new ctx.BIG(b),
                w = new ctx.BIG(0),
                cu = new FP16(ck),
                cv = new FP16(this),
                cumv = new FP16(ckml),
                cum2v = new FP16(ckm2l),
                r = new FP16(0),
                t = new FP16(0),
                f2 = 0,
                i;

            while (d.parity() === 0 && e.parity() === 0) {
                d.fshr(1);
                e.fshr(1);
                f2++;
            }

            while (ctx.BIG.comp(d, e) !== 0) {
                if (ctx.BIG.comp(d, e) > 0) {
                    w.copy(e);
                    w.imul(4);
                    w.norm();

                    if (ctx.BIG.comp(d, w) <= 0) {
                        w.copy(d);
                        d.copy(e);
                        e.rsub(w);
                        e.norm();

                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cum2v.copy(cumv);
                        cum2v.conj();
                        cumv.copy(cv);
                        cv.copy(cu);
                        cu.copy(t);

                    } else if (d.parity() === 0) {
                        d.fshr(1);
                        r.copy(cum2v);
                        r.conj();
                        t.copy(cumv);
                        t.xtr_A(cu, cv, r);
                        cum2v.copy(cumv);
                        cum2v.xtr_D();
                        cumv.copy(t);
                        cu.xtr_D();
                    } else if (e.parity() == 1) {
                        d.sub(e);
                        d.norm();
                        d.fshr(1);
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cu.xtr_D();
                        cum2v.copy(cv);
                        cum2v.xtr_D();
                        cum2v.conj();
                        cv.copy(t);
                    } else {
                        w.copy(d);
                        d.copy(e);
                        d.fshr(1);
                        e.copy(w);
                        t.copy(cumv);
                        t.xtr_D();
                        cumv.copy(cum2v);
                        cumv.conj();
                        cum2v.copy(t);
                        cum2v.conj();
                        t.copy(cv);
                        t.xtr_D();
                        cv.copy(cu);
                        cu.copy(t);
                    }
                }
                if (ctx.BIG.comp(d, e) < 0) {
                    w.copy(d);
                    w.imul(4);
                    w.norm();

                    if (ctx.BIG.comp(e, w) <= 0) {
                        e.sub(d);
                        e.norm();
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cum2v.copy(cumv);
                        cumv.copy(cu);
                        cu.copy(t);
                    } else if (e.parity() === 0) {
                        w.copy(d);
                        d.copy(e);
                        d.fshr(1);
                        e.copy(w);
                        t.copy(cumv);
                        t.xtr_D();
                        cumv.copy(cum2v);
                        cumv.conj();
                        cum2v.copy(t);
                        cum2v.conj();
                        t.copy(cv);
                        t.xtr_D();
                        cv.copy(cu);
                        cu.copy(t);
                    } else if (d.parity() == 1) {
                        w.copy(e);
                        e.copy(d);
                        w.sub(d);
                        w.norm();
                        d.copy(w);
                        d.fshr(1);
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cumv.conj();
                        cum2v.copy(cu);
                        cum2v.xtr_D();
                        cum2v.conj();
                        cu.copy(cv);
                        cu.xtr_D();
                        cv.copy(t);
                    } else {
                        d.fshr(1);
                        r.copy(cum2v);
                        r.conj();
                        t.copy(cumv);
                        t.xtr_A(cu, cv, r);
                        cum2v.copy(cumv);
                        cum2v.xtr_D();
                        cumv.copy(t);
                        cu.xtr_D();
                    }
                }
            }
            r.copy(cv);
            r.xtr_A(cu, cumv, cum2v);
            for (i = 0; i < f2; i++) {
                r.xtr_D();
            }
            r = r.xtr_pow(d);
            return r;
        }

    };

    return FP16;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* Finite Field arithmetic  Fp^2 functions */

/* FP2 elements are of the form a+ib, where i is sqrt(-1) */

function FP2(ctx) {

    /* general purpose constructor */
    var FP2 = function(c, d) {
        if (c instanceof FP2) {
            this.a = new ctx.FP(c.a);
            this.b = new ctx.FP(c.b);
        } else {
            this.a = new ctx.FP(c);
            this.b = new ctx.FP(d);
        }
    };

    FP2.prototype = {
        /* reduce components mod Modulus */
        reduce: function() {
            this.a.reduce();
            this.b.reduce();
        },

        /* normalise components of w */
        norm: function() {
            this.a.norm();
            this.b.norm();
        },

        /* test this=0 ? */
        iszilch: function() {
            this.reduce();
            return (this.a.iszilch() && this.b.iszilch());
        },

        /* test this=1 ? */
        isunity: function() {
            var one = new ctx.FP(1);
            return (this.a.equals(one) && this.b.iszilch());
        },

        /* conditional copy of g to this depending on d */
        cmove: function(g, d) {
            this.a.cmove(g.a, d);
            this.b.cmove(g.b, d);
        },

        /* test this=x */
        equals: function(x) {
            return (this.a.equals(x.a) && this.b.equals(x.b));
        },

        /* extract a */
        getA: function() {
            return this.a.redc();
        },

        /* extract b */
        getB: function() {
            return this.b.redc();
        },

        /* set from pair of FPs */
        set: function(c, d) {
            this.a.copy(c);
            this.b.copy(d);
        },

        /* set a */
        seta: function(c) {
            this.a.copy(c);
            this.b.zero();
        },

        /* set from two BIGs */
        bset: function(c, d) {
            this.a.bcopy(c);
            this.b.bcopy(d);
        },

        /* set from one ctx.BIG */
        bseta: function(c) {
            this.a.bcopy(c);
            this.b.zero();
        },

        /* copy this=x */
        copy: function(x) {
            this.a.copy(x.a);
            this.b.copy(x.b);
        },

        /* set this=0 */
        zero: function() {
            this.a.zero();
            this.b.zero();
        },

        /* set this=1 */
        one: function() {
            this.a.one();
            this.b.zero();
        },

        /* negate this */
        neg: function() {
            var m = new ctx.FP(this.a),
                t = new ctx.FP(0);

            m.add(this.b);
            m.neg();
            t.copy(m);
            t.add(this.b);
            this.b.copy(m);
            this.b.add(this.a);
            this.a.copy(t);
        },

        /* conjugate this */
        conj: function() {
            this.b.neg();
            this.b.norm();
        },

        /* this+=a */
        add: function(x) {
            this.a.add(x.a);
            this.b.add(x.b);
        },

        /* this-=x */
        sub: function(x) {
            var m = new FP2(x);
            m.neg();
            this.add(m);
        },

        rsub: function(x) {
            this.neg();
            this.add(x);
        },

        /* this*=s, where s is FP */
        pmul: function(s) {
            this.a.mul(s);
            this.b.mul(s);
        },

        /* this*=c, where s is int */
        imul: function(c) {
            this.a.imul(c);
            this.b.imul(c);
        },

        /* this*=this */
        sqr: function() {
            var w1 = new ctx.FP(this.a),
                w3 = new ctx.FP(this.a),
                mb = new ctx.FP(this.b);

            w1.add(this.b);

            w3.add(this.a);
            w3.norm();
            this.b.mul(w3);

            mb.neg();
            this.a.add(mb);

            this.a.norm();
            w1.norm();

            this.a.mul(w1);
        },

        /* this*=y */
        /* Now using Lazy reduction - inputs must be normed */
        mul: function(y) {
            var p = new ctx.BIG(0),
                pR = new ctx.DBIG(0),
                A, B, C, D, E, F;

            p.rcopy(ctx.ROM_FIELD.Modulus);
            pR.ucopy(p);

            if ((this.a.XES + this.b.XES) * (y.a.XES + y.b.XES) > ctx.FP.FEXCESS) {
                if (this.a.XES > 1) {
                    this.a.reduce();
                }

                if (this.b.XES > 1) {
                    this.b.reduce();
                }
            }

            A = ctx.BIG.mul(this.a.f, y.a.f);
            B = ctx.BIG.mul(this.b.f, y.b.f);

            C = new ctx.BIG(this.a.f);
            D = new ctx.BIG(y.a.f);

            C.add(this.b.f);
            C.norm();
            D.add(y.b.f);
            D.norm();

            E = ctx.BIG.mul(C, D);
            F = new ctx.DBIG(0);
            F.copy(A);
            F.add(B);
            B.rsub(pR);

            A.add(B);
            A.norm();
            E.sub(F);
            E.norm();

            this.a.f.copy(ctx.FP.mod(A));
            this.a.XES = 3;
            this.b.f.copy(ctx.FP.mod(E));
            this.b.XES = 2;
        },

        /* sqrt(a+ib) = sqrt(a+sqrt(a*a-n*b*b)/2)+ib/(2*sqrt(a+sqrt(a*a-n*b*b)/2)) */
        /* returns true if this is QR */
        sqrt: function() {
            var w1, w2;

            if (this.iszilch()) {
                return true;
            }

            w1 = new ctx.FP(this.b);
            w2 = new ctx.FP(this.a);

            w1.sqr();
            w2.sqr();
            w1.add(w2);
            if (w1.jacobi() != 1) {
                this.zero();
                return false;
            }
            w1 = w1.sqrt();
            w2.copy(this.a);
            w2.add(w1);
            w2.norm();
            w2.div2();
            if (w2.jacobi() != 1) {
                w2.copy(this.a);
                w2.sub(w1);
                w2.norm();
                w2.div2();
                if (w2.jacobi() != 1) {
                    this.zero();
                    return false;
                }
            }
            w2 = w2.sqrt();
            this.a.copy(w2);
            w2.add(w2);
            w2.inverse();
            this.b.mul(w2);

            return true;
        },

        /* convert this to hex string */
        toString: function() {
            return ("[" + this.a.toString() + "," + this.b.toString() + "]");
        },

        /* this=1/this */
        inverse: function() {
            var w1, w2;

            this.norm();

            w1 = new ctx.FP(this.a);
            w2 = new ctx.FP(this.b);

            w1.sqr();
            w2.sqr();
            w1.add(w2);
            w1.inverse();
            this.a.mul(w1);
            w1.neg();
            w1.norm();
            this.b.mul(w1);
        },

        /* this/=2 */
        div2: function() {
            this.a.div2();
            this.b.div2();
        },

        /* this*=sqrt(-1) */
        times_i: function() {
            var z = new ctx.FP(this.a);
            this.a.copy(this.b);
            this.a.neg();
            this.b.copy(z);
        },

        /* w*=(1+sqrt(-1)) */
        /* where X*2-(1+sqrt(-1)) is irreducible for FP4, assumes p=3 mod 8 */
        mul_ip: function() {
            var t = new FP2(this),
                z = new ctx.FP(this.a);

            this.a.copy(this.b);
            this.a.neg();
            this.b.copy(z);
            this.add(t);
        },

        div_ip2: function() {
            var t = new FP2(0);
            this.norm();
            t.a.copy(this.a);
            t.a.add(this.b);
            t.b.copy(this.b);
            t.b.sub(this.a);
            this.copy(t);
            this.norm();
        },

        /* w/=(1+sqrt(-1)) */
        div_ip: function() {
            var t = new FP2(0);
            this.norm();
            t.a.copy(this.a);
            t.a.add(this.b);
            t.b.copy(this.b);
            t.b.sub(this.a);
            this.copy(t);
            this.norm();
            this.div2();
        },

        /* this=this^e */
        pow: function(e) {
            this.norm();

            var r = new FP2(1),
                x = new FP2(this),
                bt;

            e.norm();

            for (;;) {
                bt = e.parity();
                e.fshr(1);

                if (bt == 1) {
                    r.mul(x);
                }

                if (e.iszilch()) {
                    break;
                }
                x.sqr();
            }

            r.reduce();

            return r;
        }

    };

    return FP2;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* AMCL Fp^24 functions */

/* FP24 elements are of the form a+i.b+i^2.c */

function FP24(ctx) {

    /* general purpose constructor */
    var FP24 = function(d, e, f) {
        if (d instanceof FP24) {
            this.a = new ctx.FP8(d.a);
            this.b = new ctx.FP8(d.b);
            this.c = new ctx.FP8(d.c);
        } else {
            this.a = new ctx.FP8(d);
            this.b = new ctx.FP8(e);
            this.c = new ctx.FP8(f);
        }
    };

    FP24.prototype = {
        /* reduce all components of this mod Modulus */
        reduce: function() {
            this.a.reduce();
            this.b.reduce();
            this.c.reduce();
        },

        /* normalize all components of this mod Modulus */
        norm: function() {
            this.a.norm();
            this.b.norm();
            this.c.norm();
        },

        /* test x==0 ? */
        iszilch: function() {
            this.reduce();
            return (this.a.iszilch() && this.b.iszilch() && this.c.iszilch());
        },

        /* test x==1 ? */
        isunity: function() {
            var one = new ctx.FP8(1);
            return (this.a.equals(one) && this.b.iszilch() && this.c.iszilch());
        },

        /* conditional copy of g to this depending on d */
        cmove: function(g, d) {
            this.a.cmove(g.a, d);
            this.b.cmove(g.b, d);
            this.c.cmove(g.c, d);
        },

        /* Constant time select from pre-computed table */
        select: function(g, b) {
            var invf = new FP24(0),
                m, babs;

            m = b >> 31;
            babs = (b ^ m) - m;
            babs = (babs - 1) / 2;

            this.cmove(g[0], FP24.teq(babs, 0));
            this.cmove(g[1], FP24.teq(babs, 1));
            this.cmove(g[2], FP24.teq(babs, 2));
            this.cmove(g[3], FP24.teq(babs, 3));
            this.cmove(g[4], FP24.teq(babs, 4));
            this.cmove(g[5], FP24.teq(babs, 5));
            this.cmove(g[6], FP24.teq(babs, 6));
            this.cmove(g[7], FP24.teq(babs, 7));

            invf.copy(this);
            invf.conj();
            this.cmove(invf, (m & 1));
        },

        /* extract a from this */
        geta: function() {
            return this.a;
        },

        /* extract b */
        getb: function() {
            return this.b;
        },

        /* extract c */
        getc: function() {
            return this.c;
        },

        /* return 1 if x==y, else 0 */
        equals: function(x) {
            return (this.a.equals(x.a) && this.b.equals(x.b) && this.c.equals(x.c));
        },

        /* copy this=x */
        copy: function(x) {
            this.a.copy(x.a);
            this.b.copy(x.b);
            this.c.copy(x.c);
        },

        /* set this=1 */
        one: function() {
            this.a.one();
            this.b.zero();
            this.c.zero();
        },

        /* this=conj(this) */
        conj: function() {
            this.a.conj();
            this.b.nconj();
            this.c.conj();
        },

        /* set this from 3 FP8s */
        set: function(d, e, f) {
            this.a.copy(d);
            this.b.copy(e);
            this.c.copy(f);
        },

        /* set this from one ctx.FP8 */
        seta: function(d) {
            this.a.copy(d);
            this.b.zero();
            this.c.zero();
        },

        /* Granger-Scott Unitary Squaring */
        usqr: function() {
            var A = new ctx.FP8(this.a),
                B = new ctx.FP8(this.c),
                C = new ctx.FP8(this.b),
                D = new ctx.FP8(0);

            this.a.sqr();
            D.copy(this.a);
            D.add(this.a);
            this.a.add(D);

            A.nconj();

            A.add(A);
            this.a.add(A);
            B.sqr();
            B.times_i();

            D.copy(B);
            D.add(B);
            B.add(D);

            C.sqr();
            D.copy(C);
            D.add(C);
            C.add(D);

            this.b.conj();
            this.b.add(this.b);
            this.c.nconj();

            this.c.add(this.c);
            this.b.add(B);
            this.c.add(C);
            this.reduce();
        },

        /* Chung-Hasan SQR2 method from http://cacr.uwaterloo.ca/techreports/2006/cacr2006-24.pdf */
        sqr: function() {
            var A = new ctx.FP8(this.a),
                B = new ctx.FP8(this.b),
                C = new ctx.FP8(this.c),
                D = new ctx.FP8(this.a);

            A.sqr();
            B.mul(this.c);
            B.add(B);
            C.sqr();
            D.mul(this.b);
            D.add(D);

            this.c.add(this.a);
            this.c.add(this.b);
            this.c.norm();
            this.c.sqr();

            this.a.copy(A);

            A.add(B);
            A.add(C);
            A.add(D);
            A.neg();
            B.times_i();
            C.times_i();

            this.a.add(B);
            this.b.copy(C);
            this.b.add(D);
            this.c.add(A);

            this.norm();
        },

        /* FP24 full multiplication this=this*y */
        mul: function(y) {
            var z0 = new ctx.FP8(this.a),
                z1 = new ctx.FP8(0),
                z2 = new ctx.FP8(this.b),
                z3 = new ctx.FP8(0),
                t0 = new ctx.FP8(this.a),
                t1 = new ctx.FP8(y.a);

            z0.mul(y.a);
            z2.mul(y.b);

            t0.add(this.b);
            t1.add(y.b);

            t0.norm();
            t1.norm();

            z1.copy(t0);
            z1.mul(t1);
            t0.copy(this.b);
            t0.add(this.c);

            t1.copy(y.b);
            t1.add(y.c);

            t0.norm();
            t1.norm();
            z3.copy(t0);
            z3.mul(t1);

            t0.copy(z0);
            t0.neg();
            t1.copy(z2);
            t1.neg();

            z1.add(t0);
            this.b.copy(z1);
            this.b.add(t1);

            z3.add(t1);
            z2.add(t0);

            t0.copy(this.a);
            t0.add(this.c);
            t1.copy(y.a);
            t1.add(y.c);

            t0.norm();
            t1.norm();

            t0.mul(t1);
            z2.add(t0);

            t0.copy(this.c);
            t0.mul(y.c);
            t1.copy(t0);
            t1.neg();

            this.c.copy(z2);
            this.c.add(t1);
            z3.add(t1);
            t0.times_i();
            this.b.add(t0);
            z3.times_i();
            this.a.copy(z0);
            this.a.add(z3);

            this.norm();
        },

        /* Special case this*=y that arises from special form of ATE pairing line function */
        smul: function(y, twist) {
            var z0, z1, z2, z3, t0, t1;

            if (twist == ctx.ECP.D_TYPE) {
                z0 = new ctx.FP8(this.a);
                z2 = new ctx.FP8(this.b);
                z3 = new ctx.FP8(this.b);
                t0 = new ctx.FP8(0);
                t1 = new ctx.FP8(y.a);

                z0.mul(y.a);
                z2.pmul(y.b.real());
                this.b.add(this.a);
                t1.real().add(y.b.real());

                this.b.norm();
                t1.norm();

                this.b.mul(t1);
                z3.add(this.c);
                z3.norm();
                z3.pmul(y.b.real());

                t0.copy(z0);
                t0.neg();
                t1.copy(z2);
                t1.neg();

                this.b.add(t0);

                this.b.add(t1);
                z3.add(t1);
                z2.add(t0);

                t0.copy(this.a);
                t0.add(this.c);
                t0.norm();
                t0.mul(y.a);
                this.c.copy(z2);
                this.c.add(t0);

                z3.times_i();
                this.a.copy(z0);
                this.a.add(z3);
            }

            if (twist == ctx.ECP.M_TYPE) {
                z0=new ctx.FP8(this.a);
                z1=new ctx.FP8(0);
                z2=new ctx.FP8(0);
                z3=new ctx.FP8(0);
                t0=new ctx.FP8(this.a);
                t1=new ctx.FP8(0);

                z0.mul(y.a);
                t0.add(this.b);
                t0.norm();

                z1.copy(t0); z1.mul(y.a);
                t0.copy(this.b); t0.add(this.c);
                t0.norm();

                z3.copy(t0);
                z3.pmul(y.c.getb());
                z3.times_i();

                t0.copy(z0); t0.neg();

                z1.add(t0);
                this.b.copy(z1);
                z2.copy(t0);

                t0.copy(this.a); t0.add(this.c);
                t1.copy(y.a); t1.add(y.c);

                t0.norm();
                t1.norm();

                t0.mul(t1);
                z2.add(t0);

                t0.copy(this.c);

                t0.pmul(y.c.getb());
                t0.times_i();

                t1.copy(t0); t1.neg();

                this.c.copy(z2); this.c.add(t1);
                z3.add(t1);
                t0.times_i();
                this.b.add(t0);
                z3.norm();
                z3.times_i();
                this.a.copy(z0); this.a.add(z3);
            }

            this.norm();
        },

        /* this=1/this */
        inverse: function() {
            var f0 = new ctx.FP8(this.a),
                f1 = new ctx.FP8(this.b),
                f2 = new ctx.FP8(this.a),
                f3 = new ctx.FP8(0);

            f0.sqr();
            f1.mul(this.c);
            f1.times_i();
            f0.sub(f1);
            f0.norm();

            f1.copy(this.c);
            f1.sqr();
            f1.times_i();
            f2.mul(this.b);
            f1.sub(f2);
            f1.norm();

            f2.copy(this.b);
            f2.sqr();
            f3.copy(this.a);
            f3.mul(this.c);
            f2.sub(f3);
            f2.norm();

            f3.copy(this.b);
            f3.mul(f2);
            f3.times_i();
            this.a.mul(f0);
            f3.add(this.a);
            this.c.mul(f1);
            this.c.times_i();

            f3.add(this.c);
            f3.norm();
            f3.inverse();
            this.a.copy(f0);
            this.a.mul(f3);
            this.b.copy(f1);
            this.b.mul(f3);
            this.c.copy(f2);
            this.c.mul(f3);
        },

        /* this=this^p, where p=Modulus, using Frobenius */
        frob: function(f,n) {
            var f2 = new ctx.FP2(f),
                f3 = new ctx.FP2(f),
                i;

            f2.sqr();
            f3.mul(f2);

            f3.mul_ip(); f3.norm();

            for (i=0;i<n;i++) {
                this.a.frob(f3);
                this.b.frob(f3);
                this.c.frob(f3);

                this.b.qmul(f); this.b.times_i2();
                this.c.qmul(f2); this.c.times_i2(); this.c.times_i2();
            }
        },

        /* trace function */
        trace: function() {
            var t = new ctx.FP8(0);

            t.copy(this.a);
            t.imul(3);
            t.reduce();

            return t;
        },

        /* convert this to hex string */
        toString: function() {
            return ("[" + this.a.toString() + "," + this.b.toString() + "," + this.c.toString() + "]");
        },

        /* convert this to byte array */
        toBytes: function(w) {
            var t = [],
                i;

            this.a.geta().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i] = t[i];
            }
            this.a.geta().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + ctx.BIG.MODBYTES] = t[i];
            }
            this.a.geta().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 2 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.geta().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 3 * ctx.BIG.MODBYTES] = t[i];
            }

            this.a.getb().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 4 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.getb().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 5 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.getb().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 6 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.getb().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 7 * ctx.BIG.MODBYTES] = t[i];
            }

            this.b.geta().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 8 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.geta().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 9 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.geta().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 10 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.geta().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 11 * ctx.BIG.MODBYTES] = t[i];
            }

            this.b.getb().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 12 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.getb().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 13 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.getb().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 14 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.getb().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 15 * ctx.BIG.MODBYTES] = t[i];
            }

            this.c.geta().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 16 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.geta().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 17 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.geta().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 18 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.geta().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 19 * ctx.BIG.MODBYTES] = t[i];
            }

            this.c.getb().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 20 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.getb().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 21 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.getb().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 22 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.getb().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 23 * ctx.BIG.MODBYTES] = t[i];
            }
        },

        /* set this=this^e */
        pow: function(e) {
            var e3, w, nb, i, bt;

            this.norm();
            e.norm();

            e3 = new ctx.BIG(e);
            e3.pmul(3);
            e3.norm();

            w = new FP24(this);
            nb = e3.nbits();

            for (i = nb - 2; i >= 1; i--) {
                w.usqr();
                bt = e3.bit(i) - e.bit(i);

                if (bt == 1) {
                    w.mul(this);
                }
                if (bt == -1) {
                    this.conj();
                    w.mul(this);
                    this.conj();
                }
            }
            w.reduce();

            return w;
        },

        /* constant time powering by small integer of max length bts */
        pinpow: function(e, bts) {
            var R = [],
                i, b;

            R[0] = new FP24(1);
            R[1] = new FP24(this);

            for (i = bts - 1; i >= 0; i--) {
                b = (e >> i) & 1;
                R[1 - b].mul(R[b]);
                R[b].usqr();
            }

            this.copy(R[0]);
        },

        /* Faster compressed powering for unitary elements */
        compow: function(e, r) {
            var fa, fb, f, q, m, a, b, g1, g2, c, cp, cpm1, cpm2;

            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb);

            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_FIELD.Modulus);

            m = new ctx.BIG(q);
            m.mod(r);

            a = new ctx.BIG(e);
            a.mod(m);

            b = new ctx.BIG(e);
            b.div(m);

            g1 = new FP24(0);
            g2 = new FP24(0);
            g1.copy(this);

            c = g1.trace();

            if (b.iszilch()) {
                c=c.xtr_pow(e);
                return c;
            }

            g2.copy(g1);
            g2.frob(f,1);
            cp = g2.trace();
            g1.conj();
            g2.mul(g1);
            cpm1 = g2.trace();
            g2.mul(g1);
            cpm2 = g2.trace();

            c = c.xtr_pow2(cp, cpm1, cpm2, a, b);
            return c;
        }
    };

    /* convert from byte array to FP12 */
    FP24.fromBytes = function(w) {
        var t = [],
            i, a, b, c, d, e, f, g, r, ea, eb;

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 2 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 3 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        ea = new ctx.FP4(c, d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 4 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 5 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 6 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 7 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        eb = new ctx.FP4(c, d);

        e = new ctx.FP8(ea,eb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 8 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 9 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 10 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 11 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        ea = new ctx.FP4(c, d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 12 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 13 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 14 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 15 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        eb = new ctx.FP4(c, d);

        f = new ctx.FP8(ea, eb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 16 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 17 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 18 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 19 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        ea = new ctx.FP4(c, d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 20 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 21 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 22 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 23 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        eb = new ctx.FP4(c, d);

        g = new ctx.FP8(ea, eb);

        r = new FP24(e, f, g);

        return r;
    };

    /* return 1 if b==c, no branching */
    FP24.teq = function(b, c) {
        var x = b ^ c;
        x -= 1; // if x=0, x now -1
        return ((x >> 31) & 1);
    };

    /* p=q0^u0.q1^u1.q2^u2.q3^u3... */
    // Bos & Costello https://eprint.iacr.org/2013/458.pdf
    // Faz-Hernandez & Longa & Sanchez  https://eprint.iacr.org/2013/158.pdf
    // Side channel attack secure
    FP24.pow8 = function(q, u) {
        var g1 = [],
            g2 = [],
            r = new FP24(0),
            p = new FP24(0),
            t = [],
            mt = new ctx.BIG(0),
            fa = new ctx.BIG(0),
            fb = new ctx.BIG(0),
            w1 = [],
            s1 = [],
            w2 = [],
            s2 = [],
            i, j, k, nb, bt, pb1, pb2, f;

        for (i = 0; i < 8; i++) {
            t[i] = new ctx.BIG(u[i]); t[i].norm();
        }

        g1[0] = new FP24(q[0]);
        g1[1] = new FP24(g1[0]); g1[1].mul(q[1]);
        g1[2] = new FP24(g1[0]); g1[2].mul(q[2]);
        g1[3] = new FP24(g1[1]); g1[3].mul(q[2]);
        g1[4] = new FP24(q[0]);  g1[4].mul(q[3]);
        g1[5] = new FP24(g1[1]); g1[5].mul(q[3]);
        g1[6] = new FP24(g1[2]); g1[6].mul(q[3]);
        g1[7] = new FP24(g1[3]); g1[7].mul(q[3]);

        //  Use Frobenius
        fa.rcopy(ctx.ROM_FIELD.Fra);
        fb.rcopy(ctx.ROM_FIELD.Frb);
        f = new ctx.FP2(fa, fb);

        for (i=0;i<8;i++) {
            g2[i]=new FP24(g1[i]);
            g2[i].frob(f,4);
        }

        // Make it odd
        pb1=1-t[0].parity();
        t[0].inc(pb1);
        t[0].norm();

        pb2=1-t[4].parity();
        t[4].inc(pb2);
        t[4].norm();

        // Number of bits
        mt.zero();
        for (i=0;i<8;i++) {
            mt.or(t[i]);
        }

        nb=1+mt.nbits();

        // Sign pivot
        s1[nb-1]=1;
        s2[nb-1]=1;
        for (i=0;i<nb-1;i++) {
            t[0].fshr(1);
            s1[i]=2*t[0].parity()-1;
            t[4].fshr(1);
            s2[i]=2*t[4].parity()-1;

        }

        // Recoded exponent
        for (i=0; i<nb; i++) {
            w1[i]=0;
            k=1;
            for (j=1; j<4; j++) {
                bt=s1[i]*t[j].parity();
                t[j].fshr(1);
                t[j].dec(bt>>1);
                t[j].norm();
                w1[i]+=bt*k;
                k*=2;
            }
            w2[i]=0;
            k=1;
            for (j=5; j<8; j++) {
                bt=s2[i]*t[j].parity();
                t[j].fshr(1);
                t[j].dec(bt>>1);
                t[j].norm();
                w2[i]+=bt*k;
                k*=2;
            }
        }

        // Main loop
        p.select(g1,2*w1[nb-1]+1);
        r.select(g2,2*w2[nb-1]+1);
        p.mul(r);
        for (i=nb-2;i>=0;i--) {
            p.usqr();
            r.select(g1,2*w1[i]+s1[i]);
            p.mul(r);
            r.select(g2,2*w2[i]+s2[i]);
            p.mul(r);
        }

        // apply correction
        r.copy(q[0]); r.conj();
        r.mul(p);
        p.cmove(r,pb1);

        r.copy(q[4]); r.conj();
        r.mul(p);
        p.cmove(r,pb2);

        p.reduce();
        return p;
    };

    return FP24;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* Finite Field arithmetic  Fp^4 functions */

/* FP4 elements are of the form a+ib, where i is sqrt(-1+sqrt(-1))  */

function FP4(ctx) {

    /* general purpose constructor */
    var FP4 = function(c, d) {
        if (c instanceof FP4) {
            this.a = new ctx.FP2(c.a);
            this.b = new ctx.FP2(c.b);
        } else {
            this.a = new ctx.FP2(c);
            this.b = new ctx.FP2(d);
        }
    };

    FP4.prototype = {
        /* reduce all components of this mod Modulus */
        reduce: function() {
            this.a.reduce();
            this.b.reduce();
        },

        /* normalise all components of this mod Modulus */
        norm: function() {
            this.a.norm();
            this.b.norm();
        },

        /* test this==0 ? */
        iszilch: function() {
            this.reduce();
            return (this.a.iszilch() && this.b.iszilch());
        },

        /* test this==1 ? */
        isunity: function() {
            var one = new ctx.FP2(1);
            return (this.a.equals(one) && this.b.iszilch());
        },

        /* conditional copy of g to this depending on d */
        cmove: function(g, d) {
            this.a.cmove(g.a, d);
            this.b.cmove(g.b, d);
        },

        /* test is w real? That is in a+ib test b is zero */
        isreal: function() {
            return this.b.iszilch();
        },

        /* extract real part a */
        real: function() {
            return this.a;
        },

        geta: function() {
            return this.a;
        },

        /* extract imaginary part b */
        getb: function() {
            return this.b;
        },

        /* test this=x? */
        equals: function(x) {
            return (this.a.equals(x.a) && this.b.equals(x.b));
        },

        /* copy this=x */
        copy: function(x) {
            this.a.copy(x.a);
            this.b.copy(x.b);
        },

        /* this=0 */
        zero: function() {
            this.a.zero();
            this.b.zero();
        },

        /* this=1 */
        one: function() {
            this.a.one();
            this.b.zero();
        },

        /* set from two FP2s */
        set: function(c, d) {
            this.a.copy(c);
            this.b.copy(d);
        },

        /* set a */
        seta: function(c) {
            this.a.copy(c);
            this.b.zero();
        },

        /* this=-this */
        neg: function() {
            this.norm();
            var m = new ctx.FP2(this.a),
                t = new ctx.FP2(0);

            m.add(this.b);
            m.neg();
            t.copy(m);
            t.add(this.b);
            this.b.copy(m);
            this.b.add(this.a);
            this.a.copy(t);
            this.norm();
        },

        /* this=conjugate(this) */
        conj: function() {
            this.b.neg();
            this.norm();
        },

        /* this=-conjugate(this) */
        nconj: function() {
            this.a.neg();
            this.norm();
        },

        /* this+=x */
        add: function(x) {
            this.a.add(x.a);
            this.b.add(x.b);
        },

        /* this-=x */
        sub: function(x) {
            var m = new FP4(x);
            m.neg();
            this.add(m);
        },

        rsub: function(x) {
            this.neg();
            this.add(x);
        },

        /* this*=s where s is FP2 */
        pmul: function(s) {
            this.a.mul(s);
            this.b.mul(s);
        },

        /* this*=c where s is int */
        imul: function(c) {
            this.a.imul(c);
            this.b.imul(c);
        },

        /* this*=this */
        sqr: function() {
            var t1 = new ctx.FP2(this.a),
                t2 = new ctx.FP2(this.b),
                t3 = new ctx.FP2(this.a);

            t3.mul(this.b);
            t1.add(this.b);
            t1.norm();
            t2.mul_ip();

            t2.add(this.a);
            t2.norm();
            this.a.copy(t1);

            this.a.mul(t2);

            t2.copy(t3);
            t2.mul_ip();
            t2.add(t3);
            t2.norm();  // ??

            t2.neg();

            this.a.add(t2);

            this.b.copy(t3);
            this.b.add(t3);

            this.norm();
        },

        /* this*=y */
        mul: function(y) {
            var t1 = new ctx.FP2(this.a),
                t2 = new ctx.FP2(this.b),
                t3 = new ctx.FP2(0),
                t4 = new ctx.FP2(this.b);

            t1.mul(y.a);
            t2.mul(y.b);
            t3.copy(y.b);
            t3.add(y.a);
            t4.add(this.a);

            t3.norm();
            t4.norm();

            t4.mul(t3);

            t3.copy(t1);
            t3.neg();
            t4.add(t3);

            t3.copy(t2);
            t3.neg();
            this.b.copy(t4);
            this.b.add(t3);

            t2.mul_ip();
            this.a.copy(t2);
            this.a.add(t1);

            this.norm();
        },

        /* convert to hex string */
        toString: function() {
            return ("[" + this.a.toString() + "," + this.b.toString() + "]");
        },

        /* this=1/this */
        inverse: function() {
            this.norm();

            var t1 = new ctx.FP2(this.a),
                t2 = new ctx.FP2(this.b);

            t1.sqr();
            t2.sqr();
            t2.mul_ip();
            t2.norm(); // ??
            t1.sub(t2);
            t1.inverse();
            this.a.mul(t1);
            t1.neg();
            t1.norm();
            this.b.mul(t1);
        },

        /* this*=i where i = sqrt(-1+sqrt(-1)) */
        times_i: function() {
            var s = new ctx.FP2(this.b),
                t = new ctx.FP2(this.b);

            s.times_i();
            t.add(s);
            this.b.copy(this.a);
            this.a.copy(t);
            this.norm();
        },

        /* this=this^q using Frobenius, where q is Modulus */
        frob: function(f) {
            this.a.conj();
            this.b.conj();
            this.b.mul(f);
        },

        /* this=this^e */
        pow: function(e) {
            this.norm();
            e.norm();

            var w = new FP4(this),
                z = new ctx.BIG(e),
                r = new FP4(1),
                bt;

            for (;;) {
                bt = z.parity();
                z.fshr(1);

                if (bt === 1) {
                    r.mul(w);
                }

                if (z.iszilch()) {
                    break;
                }

                w.sqr();
            }
            r.reduce();

            return r;
        },

        /* XTR xtr_a function */
        xtr_A: function(w, y, z) {
            var r = new FP4(w),
                t = new FP4(w);

            r.sub(y);
            r.norm();
            r.pmul(this.a);
            t.add(y);
            t.norm();
            t.pmul(this.b);
            t.times_i();

            this.copy(r);
            this.add(t);
            this.add(z);

            this.reduce();
        },

        /* XTR xtr_d function */
        xtr_D: function() {
            var w = new FP4(this);
            this.sqr();
            w.conj();
            w.add(w);
            this.sub(w);
            this.reduce();
        },

        /* r=x^n using XTR method on traces of FP12s */
        xtr_pow: function(n) {
            var a = new FP4(3),
                b = new FP4(this),
                c = new FP4(b),
                t = new FP4(0),
                r = new FP4(0),
                par, v, nb, i;

            c.xtr_D();

            n.norm();
            par = n.parity();
            v = new ctx.BIG(n);

            v.fshr(1);

            if (par === 0) {
                v.dec(1);
                v.norm();
            }

            nb = v.nbits();
            for (i = nb - 1; i >= 0; i--) {
                if (v.bit(i) != 1) {
                    t.copy(b);
                    this.conj();
                    c.conj();
                    b.xtr_A(a, this, c);
                    this.conj();
                    c.copy(t);
                    c.xtr_D();
                    a.xtr_D();
                } else {
                    t.copy(a);
                    t.conj();
                    a.copy(b);
                    a.xtr_D();
                    b.xtr_A(c, this, t);
                    c.xtr_D();
                }
            }

            if (par === 0) {
                r.copy(c);
            } else {
                r.copy(b);
            }
            r.reduce();

            return r;
        },

        /* r=ck^a.cl^n using XTR double exponentiation method on traces of FP12s. See Stam thesis. */
        xtr_pow2: function(ck, ckml, ckm2l, a, b) {
            a.norm();
            b.norm();

            var e = new ctx.BIG(a),
                d = new ctx.BIG(b),
                w = new ctx.BIG(0),
                cu = new FP4(ck),
                cv = new FP4(this),
                cumv = new FP4(ckml),
                cum2v = new FP4(ckm2l),
                r = new FP4(0),
                t = new FP4(0),
                f2 = 0,
                i;

            while (d.parity() === 0 && e.parity() === 0) {
                d.fshr(1);
                e.fshr(1);
                f2++;
            }

            while (ctx.BIG.comp(d, e) !== 0) {
                if (ctx.BIG.comp(d, e) > 0) {
                    w.copy(e);
                    w.imul(4);
                    w.norm();

                    if (ctx.BIG.comp(d, w) <= 0) {
                        w.copy(d);
                        d.copy(e);
                        e.rsub(w);
                        e.norm();

                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cum2v.copy(cumv);
                        cum2v.conj();
                        cumv.copy(cv);
                        cv.copy(cu);
                        cu.copy(t);

                    } else if (d.parity() === 0) {
                        d.fshr(1);
                        r.copy(cum2v);
                        r.conj();
                        t.copy(cumv);
                        t.xtr_A(cu, cv, r);
                        cum2v.copy(cumv);
                        cum2v.xtr_D();
                        cumv.copy(t);
                        cu.xtr_D();
                    } else if (e.parity() == 1) {
                        d.sub(e);
                        d.norm();
                        d.fshr(1);
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cu.xtr_D();
                        cum2v.copy(cv);
                        cum2v.xtr_D();
                        cum2v.conj();
                        cv.copy(t);
                    } else {
                        w.copy(d);
                        d.copy(e);
                        d.fshr(1);
                        e.copy(w);
                        t.copy(cumv);
                        t.xtr_D();
                        cumv.copy(cum2v);
                        cumv.conj();
                        cum2v.copy(t);
                        cum2v.conj();
                        t.copy(cv);
                        t.xtr_D();
                        cv.copy(cu);
                        cu.copy(t);
                    }
                }
                if (ctx.BIG.comp(d, e) < 0) {
                    w.copy(d);
                    w.imul(4);
                    w.norm();

                    if (ctx.BIG.comp(e, w) <= 0) {
                        e.sub(d);
                        e.norm();
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cum2v.copy(cumv);
                        cumv.copy(cu);
                        cu.copy(t);
                    } else if (e.parity() === 0) {
                        w.copy(d);
                        d.copy(e);
                        d.fshr(1);
                        e.copy(w);
                        t.copy(cumv);
                        t.xtr_D();
                        cumv.copy(cum2v);
                        cumv.conj();
                        cum2v.copy(t);
                        cum2v.conj();
                        t.copy(cv);
                        t.xtr_D();
                        cv.copy(cu);
                        cu.copy(t);
                    } else if (d.parity() == 1) {
                        w.copy(e);
                        e.copy(d);
                        w.sub(d);
                        w.norm();
                        d.copy(w);
                        d.fshr(1);
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cumv.conj();
                        cum2v.copy(cu);
                        cum2v.xtr_D();
                        cum2v.conj();
                        cu.copy(cv);
                        cu.xtr_D();
                        cv.copy(t);
                    } else {
                        d.fshr(1);
                        r.copy(cum2v);
                        r.conj();
                        t.copy(cumv);
                        t.xtr_A(cu, cv, r);
                        cum2v.copy(cumv);
                        cum2v.xtr_D();
                        cumv.copy(t);
                        cu.xtr_D();
                    }
                }
            }
            r.copy(cv);
            r.xtr_A(cu, cumv, cum2v);
            for (i = 0; i < f2; i++) {
                r.xtr_D();
            }
            r = r.xtr_pow(d);
            return r;
        },

        /* New stuff for ecp4.js */

        div2: function() {
            this.a.div2();
            this.b.div2();
        },

        div_i: function() {
            var u=new ctx.FP2(this.a),
                v=new ctx.FP2(this.b);
            u.div_ip();
            this.a.copy(v);
            this.b.copy(u);
        },

        div_2i: function() {
            var u=new ctx.FP2(this.a),
                v=new ctx.FP2(this.b);
            u.div_ip2();
            v.add(v); v.norm();
            this.a.copy(v);
            this.b.copy(u);
        },

        qmul: function(s) {
            this.a.pmul(s);
            this.b.pmul(s);
        },

        sqrt: function() {
            if (this.iszilch()) {
                return true;
            }
            var wa=new ctx.FP2(this.a),
                ws=new ctx.FP2(this.b),
                wt=new ctx.FP2(this.a);
            if (ws.iszilch()) {
                if (wt.sqrt()) {
                    this.a.copy(wt);
                    this.b.zero();
                } else {
                    wt.div_ip();
                    wt.sqrt();
                    this.b.copy(wt);
                    this.a.zero();
                }
                return true;
            }

            ws.sqr();
            wa.sqr();
            ws.mul_ip();
            ws.norm();
            wa.sub(ws);

            ws.copy(wa);
            if (!ws.sqrt()) {
                return false;
            }

            wa.copy(wt); wa.add(ws); wa.norm(); wa.div2();

            if (!wa.sqrt()) {
                wa.copy(wt); wa.sub(ws); wa.norm(); wa.div2();
                if (!wa.sqrt()) {
                    return false;
                }
            }
            wt.copy(this.b);
            ws.copy(wa); ws.add(wa);
            ws.inverse();

            wt.mul(ws);
            this.a.copy(wa);
            this.b.copy(wt);

            return true;
        }

    };

    return FP4;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* AMCL Fp^48 functions */

/* FP48 elements are of the form a+i.b+i^2.c */

function FP48(ctx) {

    /* general purpose constructor */
    var FP48 = function(d, e, f) {
        if (d instanceof FP48) {
            this.a = new ctx.FP16(d.a);
            this.b = new ctx.FP16(d.b);
            this.c = new ctx.FP16(d.c);
        } else {
            this.a = new ctx.FP16(d);
            this.b = new ctx.FP16(e);
            this.c = new ctx.FP16(f);
        }
    };

    FP48.prototype = {
        /* reduce all components of this mod Modulus */
        reduce: function() {
            this.a.reduce();
            this.b.reduce();
            this.c.reduce();
        },

        /* normalize all components of this mod Modulus */
        norm: function() {
            this.a.norm();
            this.b.norm();
            this.c.norm();
        },

        /* test x==0 ? */
        iszilch: function() {
            this.reduce();
            return (this.a.iszilch() && this.b.iszilch() && this.c.iszilch());
        },

        /* test x==1 ? */
        isunity: function() {
            var one = new ctx.FP16(1);
            return (this.a.equals(one) && this.b.iszilch() && this.c.iszilch());
        },

        /* conditional copy of g to this depending on d */
        cmove: function(g, d) {
            this.a.cmove(g.a, d);
            this.b.cmove(g.b, d);
            this.c.cmove(g.c, d);
        },

        /* Constant time select from pre-computed table */
        select: function(g, b) {
            var invf = new FP48(0),
                m, babs;

            m = b >> 31;
            babs = (b ^ m) - m;
            babs = (babs - 1) / 2;

            this.cmove(g[0], FP48.teq(babs, 0)); // conditional move
            this.cmove(g[1], FP48.teq(babs, 1));
            this.cmove(g[2], FP48.teq(babs, 2));
            this.cmove(g[3], FP48.teq(babs, 3));
            this.cmove(g[4], FP48.teq(babs, 4));
            this.cmove(g[5], FP48.teq(babs, 5));
            this.cmove(g[6], FP48.teq(babs, 6));
            this.cmove(g[7], FP48.teq(babs, 7));

            invf.copy(this);
            invf.conj();
            this.cmove(invf, (m & 1));
        },

        /* extract a from this */
        geta: function() {
            return this.a;
        },

        /* extract b */
        getb: function() {
            return this.b;
        },

        /* extract c */
        getc: function() {
            return this.c;
        },

        /* return 1 if x==y, else 0 */
        equals: function(x) {
            return (this.a.equals(x.a) && this.b.equals(x.b) && this.c.equals(x.c));
        },

        /* copy this=x */
        copy: function(x) {
            this.a.copy(x.a);
            this.b.copy(x.b);
            this.c.copy(x.c);
        },

        /* set this=1 */
        one: function() {
            this.a.one();
            this.b.zero();
            this.c.zero();
        },

        /* this=conj(this) */
        conj: function() {
            this.a.conj();
            this.b.nconj();
            this.c.conj();
        },

        /* set this from 3 FP16s */
        set: function(d, e, f) {
            this.a.copy(d);
            this.b.copy(e);
            this.c.copy(f);
        },

        /* set this from one ctx.FP16 */
        seta: function(d) {
            this.a.copy(d);
            this.b.zero();
            this.c.zero();
        },

        /* Granger-Scott Unitary Squaring */
        usqr: function() {
            var A = new ctx.FP16(this.a),
                B = new ctx.FP16(this.c),
                C = new ctx.FP16(this.b),
                D = new ctx.FP16(0);

            this.a.sqr();
            D.copy(this.a);
            D.add(this.a);
            this.a.add(D);

            A.nconj();

            A.add(A);
            this.a.add(A);
            B.sqr();
            B.times_i();

            D.copy(B);
            D.add(B);
            B.add(D);

            C.sqr();
            D.copy(C);
            D.add(C);
            C.add(D);

            this.b.conj();
            this.b.add(this.b);
            this.c.nconj();

            this.c.add(this.c);
            this.b.add(B);
            this.c.add(C);
            this.reduce();
        },

        /* Chung-Hasan SQR2 method from http://cacr.uwaterloo.ca/techreports/2006/cacr2006-24.pdf */
        sqr: function() {
            var A = new ctx.FP16(this.a),
                B = new ctx.FP16(this.b),
                C = new ctx.FP16(this.c),
                D = new ctx.FP16(this.a);

            A.sqr();
            B.mul(this.c);
            B.add(B);
            C.sqr();
            D.mul(this.b);
            D.add(D);

            this.c.add(this.a);
            this.c.add(this.b);
            this.c.norm();
            this.c.sqr();

            this.a.copy(A);

            A.add(B);
            A.add(C);
            A.add(D);
            A.neg();
            B.times_i();
            C.times_i();

            this.a.add(B);
            this.b.copy(C);
            this.b.add(D);
            this.c.add(A);

            this.norm();
        },

        /* FP48 full multiplication this=this*y */
        mul: function(y) {
            var z0 = new ctx.FP16(this.a),
                z1 = new ctx.FP16(0),
                z2 = new ctx.FP16(this.b),
                z3 = new ctx.FP16(0),
                t0 = new ctx.FP16(this.a),
                t1 = new ctx.FP16(y.a);

            z0.mul(y.a);
            z2.mul(y.b);

            t0.add(this.b);
            t1.add(y.b);

            t0.norm();
            t1.norm();

            z1.copy(t0);
            z1.mul(t1);
            t0.copy(this.b);
            t0.add(this.c);

            t1.copy(y.b);
            t1.add(y.c);

            t0.norm();
            t1.norm();
            z3.copy(t0);
            z3.mul(t1);

            t0.copy(z0);
            t0.neg();
            t1.copy(z2);
            t1.neg();

            z1.add(t0);
            this.b.copy(z1);
            this.b.add(t1);

            z3.add(t1);
            z2.add(t0);

            t0.copy(this.a);
            t0.add(this.c);
            t1.copy(y.a);
            t1.add(y.c);

            t0.norm();
            t1.norm();

            t0.mul(t1);
            z2.add(t0);

            t0.copy(this.c);
            t0.mul(y.c);
            t1.copy(t0);
            t1.neg();

            this.c.copy(z2);
            this.c.add(t1);
            z3.add(t1);
            t0.times_i();
            this.b.add(t0);
            // z3.norm();
            z3.times_i();
            this.a.copy(z0);
            this.a.add(z3);

            this.norm();
        },

        /* Special case this*=y that arises from special form of ATE pairing line function */
        smul: function(y, twist) {
            var z0, z1, z2, z3, t0, t1;

            if (twist == ctx.ECP.D_TYPE) {
                z0 = new ctx.FP16(this.a),
                z2 = new ctx.FP16(this.b),
                z3 = new ctx.FP16(this.b),
                t0 = new ctx.FP16(0),
                t1 = new ctx.FP16(y.a);

                z0.mul(y.a);
                z2.pmul(y.b.real());
                this.b.add(this.a);
                t1.real().add(y.b.real());

                this.b.norm();
                t1.norm();

                this.b.mul(t1);
                z3.add(this.c);
                z3.norm();
                z3.pmul(y.b.real());

                t0.copy(z0);
                t0.neg();
                t1.copy(z2);
                t1.neg();

                this.b.add(t0);

                this.b.add(t1);
                z3.add(t1);
                z2.add(t0);

                t0.copy(this.a);
                t0.add(this.c);
                t0.norm();
                t0.mul(y.a);
                this.c.copy(z2);
                this.c.add(t0);

                z3.times_i();
                this.a.copy(z0);
                this.a.add(z3);
            }

            if (twist == ctx.ECP.M_TYPE) {
                z0=new ctx.FP16(this.a);
                z1=new ctx.FP16(0);
                z2=new ctx.FP16(0);
                z3=new ctx.FP16(0);
                t0=new ctx.FP16(this.a);
                t1=new ctx.FP16(0);

                z0.mul(y.a);
                t0.add(this.b);
                t0.norm();

                z1.copy(t0); z1.mul(y.a);
                t0.copy(this.b); t0.add(this.c);
                t0.norm();

                z3.copy(t0);
                z3.pmul(y.c.getb());
                z3.times_i();

                t0.copy(z0); t0.neg();

                z1.add(t0);
                this.b.copy(z1);
                z2.copy(t0);

                t0.copy(this.a); t0.add(this.c);
                t1.copy(y.a); t1.add(y.c);

                t0.norm();
                t1.norm();

                t0.mul(t1);
                z2.add(t0);

                t0.copy(this.c);

                t0.pmul(y.c.getb());
                t0.times_i();

                t1.copy(t0); t1.neg();

                this.c.copy(z2); this.c.add(t1);
                z3.add(t1);
                t0.times_i();
                this.b.add(t0);
                z3.norm();
                z3.times_i();
                this.a.copy(z0); this.a.add(z3);
            }

            this.norm();
        },

        /* this=1/this */
        inverse: function() {
            var f0 = new ctx.FP16(this.a),
                f1 = new ctx.FP16(this.b),
                f2 = new ctx.FP16(this.a),
                f3 = new ctx.FP16(0);

            f0.sqr();
            f1.mul(this.c);
            f1.times_i();
            f0.sub(f1);
            f0.norm();

            f1.copy(this.c);
            f1.sqr();
            f1.times_i();
            f2.mul(this.b);
            f1.sub(f2);
            f1.norm();

            f2.copy(this.b);
            f2.sqr();
            f3.copy(this.a);
            f3.mul(this.c);
            f2.sub(f3);
            f2.norm();

            f3.copy(this.b);
            f3.mul(f2);
            f3.times_i();
            this.a.mul(f0);
            f3.add(this.a);
            this.c.mul(f1);
            this.c.times_i();

            f3.add(this.c);
            f3.norm();
            f3.inverse();
            this.a.copy(f0);
            this.a.mul(f3);
            this.b.copy(f1);
            this.b.mul(f3);
            this.c.copy(f2);
            this.c.mul(f3);
        },

        /* this=this^p, where p=Modulus, using Frobenius */
        frob: function(f,n) {
            var f2 = new ctx.FP2(f),
                f3 = new ctx.FP2(f),
                i;

            f2.sqr();
            f3.mul(f2);

            f3.mul_ip(); f3.norm();
            f3.mul_ip(); f3.norm();

            for (i=0;i<n;i++) {
                this.a.frob(f3);
                this.b.frob(f3);
                this.c.frob(f3);

                this.b.qmul(f); this.b.times_i4(); this.b.times_i2();
                this.c.qmul(f2); this.c.times_i4(); this.c.times_i4(); this.c.times_i4();
            }
        },

        /* trace function */
        trace: function() {
            var t = new ctx.FP16(0);

            t.copy(this.a);
            t.imul(3);
            t.reduce();

            return t;
        },

        /* convert this to hex string */
        toString: function() {
            return ("[" + this.a.toString() + "," + this.b.toString() + "," + this.c.toString() + "]");
        },

        /* convert this to byte array */
        toBytes: function(w) {
            var t = [],
                i;

            this.a.geta().geta().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i] = t[i];
            }
            this.a.geta().geta().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + ctx.BIG.MODBYTES] = t[i];
            }
            this.a.geta().geta().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 2 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.geta().geta().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 3 * ctx.BIG.MODBYTES] = t[i];
            }

            this.a.geta().getb().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 4 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.geta().getb().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 5 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.geta().getb().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 6 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.geta().getb().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 7 * ctx.BIG.MODBYTES] = t[i];
            }

            this.a.getb().geta().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 8 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.getb().geta().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 9 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.getb().geta().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 10 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.getb().geta().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 11 * ctx.BIG.MODBYTES] = t[i];
            }

            this.a.getb().getb().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 12 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.getb().getb().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 13 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.getb().getb().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 14 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.getb().getb().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 15 * ctx.BIG.MODBYTES] = t[i];
            }

            this.b.geta().geta().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 16 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.geta().geta().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 17 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.geta().geta().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 18 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.geta().geta().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 19 * ctx.BIG.MODBYTES] = t[i];
            }

            this.b.geta().getb().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 20 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.geta().getb().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 21 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.geta().getb().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 22 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.geta().getb().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 23 * ctx.BIG.MODBYTES] = t[i];
            }

            this.b.getb().geta().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 24 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.getb().geta().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 25 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.getb().geta().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 26 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.getb().geta().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 27 * ctx.BIG.MODBYTES] = t[i];
            }

            this.b.getb().getb().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 28 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.getb().getb().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 29 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.getb().getb().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 30 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.getb().getb().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 31 * ctx.BIG.MODBYTES] = t[i];
            }

            this.c.geta().geta().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 32 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.geta().geta().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 33 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.geta().geta().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 34 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.geta().geta().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 35 * ctx.BIG.MODBYTES] = t[i];
            }

            this.c.geta().getb().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 36 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.geta().getb().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 37 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.geta().getb().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 38 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.geta().getb().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 39 * ctx.BIG.MODBYTES] = t[i];
            }

            this.c.getb().geta().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 40 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.getb().geta().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 41 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.getb().geta().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 42 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.getb().geta().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 43 * ctx.BIG.MODBYTES] = t[i];
            }

            this.c.getb().getb().geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 44 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.getb().getb().geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 45 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.getb().getb().getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 46 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.getb().getb().getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 47 * ctx.BIG.MODBYTES] = t[i];
            }
        },

        /* set this=this^e */
        pow: function(e) {
            var e3, w, nb, i, bt;

            this.norm();
            e.norm();

            e3 = new ctx.BIG(e);
            e3.pmul(3);
            e3.norm();

            w = new FP48(this);
            nb = e3.nbits();

            for (i = nb - 2; i >= 1; i--) {
                w.usqr();
                bt = e3.bit(i) - e.bit(i);

                if (bt == 1) {
                    w.mul(this);
                }
                if (bt == -1) {
                    this.conj();
                    w.mul(this);
                    this.conj();
                }
            }
            w.reduce();

            return w;
        },

        /* constant time powering by small integer of max length bts */
        pinpow: function(e, bts) {
            var R = [],
                i, b;

            R[0] = new FP48(1);
            R[1] = new FP48(this);

            for (i = bts - 1; i >= 0; i--) {
                b = (e >> i) & 1;
                R[1 - b].mul(R[b]);
                R[b].usqr();
            }

            this.copy(R[0]);
        },

        /* Faster compressed powering for unitary elements */
        compow: function(e, r) {
            var fa, fb, f, q, m, a, b, g1, g2, c, cp, cpm1, cpm2;

            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb);

            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_FIELD.Modulus);

            m = new ctx.BIG(q);
            m.mod(r);

            a = new ctx.BIG(e);
            a.mod(m);

            b = new ctx.BIG(e);
            b.div(m);

            g1 = new FP48(0);
            g2 = new FP48(0);
            g1.copy(this);

            c = g1.trace();

            if (b.iszilch()) {
                c=c.xtr_pow(e);
                return c;
            }

            g2.copy(g1);
            g2.frob(f,1);
            cp = g2.trace();
            g1.conj();
            g2.mul(g1);
            cpm1 = g2.trace();
            g2.mul(g1);
            cpm2 = g2.trace();

            c = c.xtr_pow2(cp, cpm1, cpm2, a, b);
            return c;
        }
    };

    /* convert from byte array to FP12 */
    FP48.fromBytes = function(w) {
        var t = [],
            i, a, b, c, d, e, f, g, r, ea, eb, fa, fb;

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 2 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 3 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        ea = new ctx.FP4(c, d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 4 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 5 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 6 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 7 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        eb = new ctx.FP4(c, d);

        fa = new ctx.FP8(ea,eb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 8 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 9 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 10 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 11 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        ea = new ctx.FP4(c, d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 12 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 13 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 14 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 15 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        eb = new ctx.FP4(c, d);

        fb = new ctx.FP8(ea,eb);

        e = new ctx.FP16(fa,fb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 16 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 17 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 18 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 19 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        ea = new ctx.FP4(c, d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 20 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 21 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 22 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 23 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        eb = new ctx.FP4(c, d);

        fa = new ctx.FP8(ea,eb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 24 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 25 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 26 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 27 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        ea = new ctx.FP4(c, d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 28 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 29 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 30 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 31 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        eb = new ctx.FP4(c, d);

        fb = new ctx.FP8(ea,eb);

        f = new ctx.FP16(fa, fb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 32 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 33 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 34 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 35 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        ea = new ctx.FP4(c, d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 36 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 37 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 38 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 39 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        eb = new ctx.FP4(c, d);

        fa = new ctx.FP8(ea,eb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 40 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 41 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 42 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 43 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        ea = new ctx.FP4(c, d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 44 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 45 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 46 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 47 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        eb = new ctx.FP4(c, d);

        fb = new ctx.FP8(ea,eb);

        g = new ctx.FP16(fa, fb);

        r = new FP48(e, f, g);

        return r;
    };

    /* return 1 if b==c, no branching */
    FP48.teq = function(b, c) {
        var x = b ^ c;
        x -= 1; // if x=0, x now -1
        return ((x >> 31) & 1);
    };

    /* p=q0^u0.q1^u1.q2^u2.q3^u3... */
    // Bos & Costello https://eprint.iacr.org/2013/458.pdf
    // Faz-Hernandez & Longa & Sanchez  https://eprint.iacr.org/2013/158.pdf
    // Side channel attack secure
    FP48.pow16 = function(q, u) {
        var g1 = [],
            g2 = [],
            g3 = [],
            g4 = [],
            r = new FP48(0),
            p = new FP48(0),
            t = [],
            mt = new ctx.BIG(0),
            fa = new ctx.BIG(0),
            fb = new ctx.BIG(0),
            w1 = [],
            s1 = [],
            w2 = [],
            s2 = [],
            w3 = [],
            s3 = [],
            w4 = [],
            s4 = [],
            i, j, k, nb, bt, pb1, pb2, pb3, pb4, f;

        for (i = 0; i < 16; i++) {
            t[i] = new ctx.BIG(u[i]); t[i].norm();
        }

        g1[0] = new FP48(q[0]);
        g1[1] = new FP48(g1[0]); g1[1].mul(q[1]);
        g1[2] = new FP48(g1[0]); g1[2].mul(q[2]);
        g1[3] = new FP48(g1[1]); g1[3].mul(q[2]);
        g1[4] = new FP48(q[0]);  g1[4].mul(q[3]);
        g1[5] = new FP48(g1[1]); g1[5].mul(q[3]);
        g1[6] = new FP48(g1[2]); g1[6].mul(q[3]);
        g1[7] = new FP48(g1[3]); g1[7].mul(q[3]);

        //  Use Frobenius
        fa.rcopy(ctx.ROM_FIELD.Fra);
        fb.rcopy(ctx.ROM_FIELD.Frb);
        f = new ctx.FP2(fa, fb);

        for (i=0;i<8;i++) {
            g2[i]=new FP48(g1[i]);
            g2[i].frob(f,4);
            g3[i]=new FP48(g2[i]);
            g3[i].frob(f,4);
            g4[i]=new FP48(g3[i]);
            g4[i].frob(f,4);

        }

        // Make it odd
        pb1=1-t[0].parity();
        t[0].inc(pb1);
        t[0].norm();

        pb2=1-t[4].parity();
        t[4].inc(pb2);
        t[4].norm();

        pb3=1-t[8].parity();
        t[8].inc(pb3);
        t[8].norm();

        pb4=1-t[12].parity();
        t[12].inc(pb4);
        t[12].norm();

        // Number of bits
        mt.zero();
        for (i=0;i<16;i++) {
            mt.or(t[i]);
        }

        nb=1+mt.nbits();

        // Sign pivot
        s1[nb-1]=1;
        s2[nb-1]=1;
        s3[nb-1]=1;
        s4[nb-1]=1;
        for (i=0;i<nb-1;i++) {
            t[0].fshr(1);
            s1[i]=2*t[0].parity()-1;
            t[4].fshr(1);
            s2[i]=2*t[4].parity()-1;
            t[8].fshr(1);
            s3[i]=2*t[8].parity()-1;
            t[12].fshr(1);
            s4[i]=2*t[12].parity()-1;

        }

        // Recoded exponent
        for (i=0; i<nb; i++) {
            w1[i]=0;
            k=1;
            for (j=1; j<4; j++) {
                bt=s1[i]*t[j].parity();
                t[j].fshr(1);
                t[j].dec(bt>>1);
                t[j].norm();
                w1[i]+=bt*k;
                k*=2;
            }
            w2[i]=0;
            k=1;
            for (j=5; j<8; j++) {
                bt=s2[i]*t[j].parity();
                t[j].fshr(1);
                t[j].dec(bt>>1);
                t[j].norm();
                w2[i]+=bt*k;
                k*=2;
            }
            w3[i]=0;
            k=1;
            for (j=9; j<12; j++) {
                bt=s3[i]*t[j].parity();
                t[j].fshr(1);
                t[j].dec(bt>>1);
                t[j].norm();
                w3[i]+=bt*k;
                k*=2;
            }
            w4[i]=0;
            k=1;
            for (j=13; j<16; j++) {
                bt=s4[i]*t[j].parity();
                t[j].fshr(1);
                t[j].dec(bt>>1);
                t[j].norm();
                w4[i]+=bt*k;
                k*=2;
            }
        }

        // Main loop
        p.select(g1,2*w1[nb-1]+1);
        r.select(g2,2*w2[nb-1]+1);
        p.mul(r);
        r.select(g3,2*w3[nb-1]+1);
        p.mul(r);
        r.select(g4,2*w4[nb-1]+1);
        p.mul(r);
        for (i=nb-2;i>=0;i--) {
            p.usqr();
            r.select(g1,2*w1[i]+s1[i]);
            p.mul(r);
            r.select(g2,2*w2[i]+s2[i]);
            p.mul(r);
            r.select(g3,2*w3[i]+s3[i]);
            p.mul(r);
            r.select(g4,2*w4[i]+s4[i]);
            p.mul(r);
        }

        // apply correction
        r.copy(q[0]); r.conj();
        r.mul(p);
        p.cmove(r,pb1);

        r.copy(q[4]); r.conj();
        r.mul(p);
        p.cmove(r,pb2);

        r.copy(q[8]); r.conj();
        r.mul(p);
        p.cmove(r,pb3);

        r.copy(q[12]); r.conj();
        r.mul(p);
        p.cmove(r,pb4);

        p.reduce();
        return p;
    };

    return FP48;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* Finite Field arithmetic  Fp^8 functions */

/* FP8 elements are of the form a+ib, where i is sqrt(sqrt(-1+sqrt(-1)))  */

function FP8(ctx) {

    /* general purpose constructor */
    var FP8 = function(c, d) {
        if (c instanceof FP8) {
            this.a = new ctx.FP4(c.a);
            this.b = new ctx.FP4(c.b);
        } else {
            this.a = new ctx.FP4(c);
            this.b = new ctx.FP4(d);
        }
    };

    FP8.prototype = {
        /* reduce all components of this mod Modulus */
        reduce: function() {
            this.a.reduce();
            this.b.reduce();
        },

        /* normalise all components of this mod Modulus */
        norm: function() {
            this.a.norm();
            this.b.norm();
        },

        /* test this==0 ? */
        iszilch: function() {
            this.reduce();
            return (this.a.iszilch() && this.b.iszilch());
        },

        /* test this==1 ? */
        isunity: function() {
            var one = new ctx.FP4(1);
            return (this.a.equals(one) && this.b.iszilch());
        },

        /* conditional copy of g to this depending on d */
        cmove: function(g, d) {
            this.a.cmove(g.a, d);
            this.b.cmove(g.b, d);
        },

        /* test is w real? That is in a+ib test b is zero */
        isreal: function() {
            return this.b.iszilch();
        },

        /* extract real part a */
        real: function() {
            return this.a;
        },

        geta: function() {
            return this.a;
        },

        /* extract imaginary part b */
        getb: function() {
            return this.b;
        },

        /* test this=x? */
        equals: function(x) {
            return (this.a.equals(x.a) && this.b.equals(x.b));
        },

        /* copy this=x */
        copy: function(x) {
            this.a.copy(x.a);
            this.b.copy(x.b);
        },

        /* this=0 */
        zero: function() {
            this.a.zero();
            this.b.zero();
        },

        /* this=1 */
        one: function() {
            this.a.one();
            this.b.zero();
        },

        /* set from two FP4s */
        set: function(c, d) {
            this.a.copy(c);
            this.b.copy(d);
        },

        /* set a */
        seta: function(c) {
            this.a.copy(c);
            this.b.zero();
        },

        /* this=-this */
        neg: function() {
            this.norm();
            var m = new ctx.FP4(this.a),
                t = new ctx.FP4(0);

            m.add(this.b);
            m.neg();
            t.copy(m);
            t.add(this.b);
            this.b.copy(m);
            this.b.add(this.a);
            this.a.copy(t);
            this.norm();
        },

        /* this=conjugate(this) */
        conj: function() {
            this.b.neg();
            this.norm();
        },

        /* this=-conjugate(this) */
        nconj: function() {
            this.a.neg();
            this.norm();
        },

        /* this+=x */
        add: function(x) {
            this.a.add(x.a);
            this.b.add(x.b);
        },

        /* this-=x */
        sub: function(x) {
            var m = new FP8(x);
            m.neg();
            this.add(m);
        },

        rsub: function(x) {
            this.neg();
            this.add(x);
        },

        /* this*=s where s is FP4 */
        pmul: function(s) {
            this.a.mul(s);
            this.b.mul(s);
        },

        /* this*=c where s is int */
        imul: function(c) {
            this.a.imul(c);
            this.b.imul(c);
        },

        /* this*=this */
        sqr: function() {
            var t1 = new ctx.FP4(this.a),
                t2 = new ctx.FP4(this.b),
                t3 = new ctx.FP4(this.a);

            t3.mul(this.b);
            t1.add(this.b);
            t1.norm();
            t2.times_i();

            t2.add(this.a);
            t2.norm();
            this.a.copy(t1);

            this.a.mul(t2);

            t2.copy(t3);
            t2.times_i();
            t2.add(t3);

            t2.neg();

            this.a.add(t2);

            this.b.copy(t3);
            this.b.add(t3);

            this.norm();
        },

        /* this*=y */
        mul: function(y) {
            var t1 = new ctx.FP4(this.a),
                t2 = new ctx.FP4(this.b),
                t3 = new ctx.FP4(0),
                t4 = new ctx.FP4(this.b);

            t1.mul(y.a);
            t2.mul(y.b);
            t3.copy(y.b);
            t3.add(y.a);
            t4.add(this.a);

            t3.norm();
            t4.norm();

            t4.mul(t3);

            t3.copy(t1);
            t3.neg();
            t4.add(t3);

            t3.copy(t2);
            t3.neg();
            this.b.copy(t4);
            this.b.add(t3);

            t2.times_i();
            this.a.copy(t2);
            this.a.add(t1);

            this.norm();
        },

        /* convert to hex string */
        toString: function() {
            return ("[" + this.a.toString() + "," + this.b.toString() + "]");
        },

        /* this=1/this */
        inverse: function() {
            this.norm();

            var t1 = new ctx.FP4(this.a),
                t2 = new ctx.FP4(this.b);

            t1.sqr();
            t2.sqr();
            t2.times_i();
            t2.norm(); // ??
            t1.sub(t2);
            t1.inverse();
            this.a.mul(t1);
            t1.neg();
            t1.norm();
            this.b.mul(t1);
        },

        /* this*=i where i = sqrt(-1+sqrt(-1)) */
        times_i: function() {
            var s = new ctx.FP4(this.b),
                t = new ctx.FP4(this.a);

            s.times_i();
            this.b.copy(t);

            this.a.copy(s);
            this.norm();
        },

        times_i2: function() {
            this.a.times_i();
            this.b.times_i();
        },

        /* this=this^q using Frobenius, where q is Modulus */
        frob: function(f) {
            var ff=new ctx.FP2(f); ff.sqr(); ff.mul_ip(); ff.norm();
            this.a.frob(ff);
            this.b.frob(ff);
            this.b.pmul(f);
            this.b.times_i();
        },

        /* this=this^e */
        pow: function(e) {
            this.norm();
            e.norm();

            var w = new FP8(this),
                z = new ctx.BIG(e),
                r = new FP8(1),
                bt;

            for (;;) {
                bt = z.parity();
                z.fshr(1);

                if (bt === 1) {
                    r.mul(w);
                }

                if (z.iszilch()) {
                    break;
                }

                w.sqr();
            }
            r.reduce();

            return r;
        },

        /* XTR xtr_a function */
        xtr_A: function(w, y, z) {
            var r = new FP8(w),
                t = new FP8(w);

            r.sub(y);
            r.norm();
            r.pmul(this.a);
            t.add(y);
            t.norm();
            t.pmul(this.b);
            t.times_i();

            this.copy(r);
            this.add(t);
            this.add(z);

            this.reduce();
        },

        /* XTR xtr_d function */
        xtr_D: function() {
            var w = new FP8(this);
            this.sqr();
            w.conj();
            w.add(w);
            this.sub(w);
            this.reduce();
        },

        /* r=x^n using XTR method on traces of FP12s */
        xtr_pow: function(n) {
            var a = new FP8(3),
                b = new FP8(this),
                c = new FP8(b),
                t = new FP8(0),
                r = new FP8(0),
                par, v, nb, i;

            c.xtr_D();

            n.norm();
            par = n.parity();
            v = new ctx.BIG(n);

            v.fshr(1);

            if (par === 0) {
                v.dec(1);
                v.norm();
            }

            nb = v.nbits();
            for (i = nb - 1; i >= 0; i--) {
                if (v.bit(i) != 1) {
                    t.copy(b);
                    this.conj();
                    c.conj();
                    b.xtr_A(a, this, c);
                    this.conj();
                    c.copy(t);
                    c.xtr_D();
                    a.xtr_D();
                } else {
                    t.copy(a);
                    t.conj();
                    a.copy(b);
                    a.xtr_D();
                    b.xtr_A(c, this, t);
                    c.xtr_D();
                }
            }

            if (par === 0) {
                r.copy(c);
            } else {
                r.copy(b);
            }
            r.reduce();

            return r;
        },

        /* r=ck^a.cl^n using XTR double exponentiation method on traces of FP12s. See Stam thesis. */
        xtr_pow2: function(ck, ckml, ckm2l, a, b) {
            a.norm();
            b.norm();

            var e = new ctx.BIG(a),
                d = new ctx.BIG(b),
                w = new ctx.BIG(0),
                cu = new FP8(ck),
                cv = new FP8(this),
                cumv = new FP8(ckml),
                cum2v = new FP8(ckm2l),
                r = new FP8(0),
                t = new FP8(0),
                f2 = 0,
                i;

            while (d.parity() === 0 && e.parity() === 0) {
                d.fshr(1);
                e.fshr(1);
                f2++;
            }

            while (ctx.BIG.comp(d, e) !== 0) {
                if (ctx.BIG.comp(d, e) > 0) {
                    w.copy(e);
                    w.imul(4);
                    w.norm();

                    if (ctx.BIG.comp(d, w) <= 0) {
                        w.copy(d);
                        d.copy(e);
                        e.rsub(w);
                        e.norm();

                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cum2v.copy(cumv);
                        cum2v.conj();
                        cumv.copy(cv);
                        cv.copy(cu);
                        cu.copy(t);

                    } else if (d.parity() === 0) {
                        d.fshr(1);
                        r.copy(cum2v);
                        r.conj();
                        t.copy(cumv);
                        t.xtr_A(cu, cv, r);
                        cum2v.copy(cumv);
                        cum2v.xtr_D();
                        cumv.copy(t);
                        cu.xtr_D();
                    } else if (e.parity() == 1) {
                        d.sub(e);
                        d.norm();
                        d.fshr(1);
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cu.xtr_D();
                        cum2v.copy(cv);
                        cum2v.xtr_D();
                        cum2v.conj();
                        cv.copy(t);
                    } else {
                        w.copy(d);
                        d.copy(e);
                        d.fshr(1);
                        e.copy(w);
                        t.copy(cumv);
                        t.xtr_D();
                        cumv.copy(cum2v);
                        cumv.conj();
                        cum2v.copy(t);
                        cum2v.conj();
                        t.copy(cv);
                        t.xtr_D();
                        cv.copy(cu);
                        cu.copy(t);
                    }
                }
                if (ctx.BIG.comp(d, e) < 0) {
                    w.copy(d);
                    w.imul(4);
                    w.norm();

                    if (ctx.BIG.comp(e, w) <= 0) {
                        e.sub(d);
                        e.norm();
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cum2v.copy(cumv);
                        cumv.copy(cu);
                        cu.copy(t);
                    } else if (e.parity() === 0) {
                        w.copy(d);
                        d.copy(e);
                        d.fshr(1);
                        e.copy(w);
                        t.copy(cumv);
                        t.xtr_D();
                        cumv.copy(cum2v);
                        cumv.conj();
                        cum2v.copy(t);
                        cum2v.conj();
                        t.copy(cv);
                        t.xtr_D();
                        cv.copy(cu);
                        cu.copy(t);
                    } else if (d.parity() == 1) {
                        w.copy(e);
                        e.copy(d);
                        w.sub(d);
                        w.norm();
                        d.copy(w);
                        d.fshr(1);
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cumv.conj();
                        cum2v.copy(cu);
                        cum2v.xtr_D();
                        cum2v.conj();
                        cu.copy(cv);
                        cu.xtr_D();
                        cv.copy(t);
                    } else {
                        d.fshr(1);
                        r.copy(cum2v);
                        r.conj();
                        t.copy(cumv);
                        t.xtr_A(cu, cv, r);
                        cum2v.copy(cumv);
                        cum2v.xtr_D();
                        cumv.copy(t);
                        cu.xtr_D();
                    }
                }
            }
            r.copy(cv);
            r.xtr_A(cu, cumv, cum2v);
            for (i = 0; i < f2; i++) {
                r.xtr_D();
            }
            r = r.xtr_pow(d);
            return r;
        },

        /* New stuff for ecp4.js */

        div2: function() {
            this.a.div2();
            this.b.div2();
        },

        div_i: function() {
            var u=new ctx.FP4(this.a),
                v=new ctx.FP4(this.b);
            u.div_i();
            this.a.copy(v);
            this.b.copy(u);
        },

        div_i2: function() {
            this.a.div_i();
            this.b.div_i();
        },

        div_2i: function() {
            var u=new ctx.FP4(this.a),
                v=new ctx.FP4(this.b);
            u.div_2i();
            v.add(v); v.norm();
            this.a.copy(v);
            this.b.copy(u);
        },

        qmul: function(s) {
            this.a.pmul(s);
            this.b.pmul(s);
        },

        tmul: function(s) {
            this.a.qmul(s);
            this.b.qmul(s);
        },

        sqrt: function() {
            if (this.iszilch()) {
                return true;
            }
            var wa=new ctx.FP4(this.a),
                ws=new ctx.FP4(this.b),
                wt=new ctx.FP4(this.a);
            if (ws.iszilch()) {
                if (wt.sqrt()) {
                    this.a.copy(wt);
                    this.b.zero();
                } else {
                    wt.div_i();
                    wt.sqrt();
                    this.b.copy(wt);
                    this.a.zero();
                }
                return true;
            }

            ws.sqr();
            wa.sqr();
            ws.times_i();
            ws.norm();
            wa.sub(ws);

            ws.copy(wa);
            if (!ws.sqrt()) {
                return false;
            }

            wa.copy(wt); wa.add(ws); wa.norm(); wa.div2();

            if (!wa.sqrt()) {
                wa.copy(wt); wa.sub(ws); wa.norm(); wa.div2();
                if (!wa.sqrt()) {
                    return false;
                }
            }
            wt.copy(this.b);
            ws.copy(wa); ws.add(wa);
            ws.inverse();

            wt.mul(ws);
            this.a.copy(wa);
            this.b.copy(wt);

            return true;
        }

    };

    return FP8;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/*
 * Implementation of the ctx.AES-GCM Encryption/Authentication
 *
 * Some restrictions..
 * 1. Only for use with ctx.AES
 * 2. Returned tag is always 128-bits. Truncate at your own risk.
 * 3. The order of function calls must follow some rules
 *
 * Typical sequence of calls..
 * 1. call GCM_init
 * 2. call GCM_add_header any number of times, as long as length of header is multiple of 16 bytes (block size)
 * 3. call GCM_add_header one last time with any length of header
 * 4. call GCM_add_cipher any number of times, as long as length of cipher/plaintext is multiple of 16 bytes
 * 5. call GCM_add_cipher one last time with any length of cipher/plaintext
 * 6. call GCM_finish to extract the tag.
 *
 * See http://www.mindspring.com/~dmcgrew/gcm-nist-6.pdf
 */

function GCM(ctx) {

    var GCM = function() {
        this.table = new Array(128);
        /* 2k bytes */
        for (var i = 0; i < 128; i++) {
            this.table[i] = new Array(4);
        }
        this.stateX = [];
        this.Y_0 = [];
        this.counter = 0;
        this.lenA = [];
        this.lenC = [];
        this.status = 0;
        this.a = new ctx.AES();
    };

    // GCM constants

    GCM.ACCEPTING_HEADER = 0;
    GCM.ACCEPTING_CIPHER = 1;
    GCM.NOT_ACCEPTING_MORE = 2;
    GCM.FINISHED = 3;
    GCM.ENCRYPTING = 0;
    GCM.DECRYPTING = 1;

    GCM.prototype = {
        precompute: function(H) {
            var b = [],
                i, j, c;

            for (i = j = 0; i < 4; i++, j += 4) {
                b[0] = H[j];
                b[1] = H[j + 1];
                b[2] = H[j + 2];
                b[3] = H[j + 3];
                this.table[0][i] = GCM.pack(b);
            }
            for (i = 1; i < 128; i++) {
                c = 0;
                for (j = 0; j < 4; j++) {
                    this.table[i][j] = c | (this.table[i - 1][j]) >>> 1;
                    c = this.table[i - 1][j] << 31;
                }

                if (c !== 0) {
                    /* irreducible polynomial */
                    this.table[i][0] ^= 0xE1000000;
                }
            }
        },

        /* gf2m mul - Z=H*X mod 2^128 */
        gf2mul: function() {
            var P = [],
                b = [],
                i, j, m, k, c;

            P[0] = P[1] = P[2] = P[3] = 0;
            j = 8;
            m = 0;

            for (i = 0; i < 128; i++) {
                c = (this.stateX[m] >>> (--j)) & 1;
                c = ~c + 1;
                for (k = 0; k < 4; k++) {
                    P[k] ^= (this.table[i][k] & c);
                }

                if (j === 0) {
                    j = 8;
                    m++;
                    if (m == 16) {
                        break;
                    }
                }
            }

            for (i = j = 0; i < 4; i++, j += 4) {
                b = GCM.unpack(P[i]);
                this.stateX[j] = b[0];
                this.stateX[j + 1] = b[1];
                this.stateX[j + 2] = b[2];
                this.stateX[j + 3] = b[3];
            }
        },

        /* Finish off GHASH */
        wrap: function() {
            var F = [],
                L = [],
                b = [],
                i, j;

            /* convert lengths from bytes to bits */
            F[0] = (this.lenA[0] << 3) | (this.lenA[1] & 0xE0000000) >>> 29;
            F[1] = this.lenA[1] << 3;
            F[2] = (this.lenC[0] << 3) | (this.lenC[1] & 0xE0000000) >>> 29;
            F[3] = this.lenC[1] << 3;

            for (i = j = 0; i < 4; i++, j += 4) {
                b = GCM.unpack(F[i]);
                L[j] = b[0];
                L[j + 1] = b[1];
                L[j + 2] = b[2];
                L[j + 3] = b[3];
            }

            for (i = 0; i < 16; i++) {
                this.stateX[i] ^= L[i];
            }

            this.gf2mul();
        },

        /* Initialize GCM mode */
        /* iv size niv is usually 12 bytes (96 bits). ctx.AES key size nk can be 16,24 or 32 bytes */
        init: function(nk, key, niv, iv) {
            var H = [],
                b = [],
                i;

            for (i = 0; i < 16; i++) {
                H[i] = 0;
                this.stateX[i] = 0;
            }

            this.a.init(ctx.AES.ECB, nk, key, iv);
            /* E(K,0) */
            this.a.ecb_encrypt(H);
            this.precompute(H);

            this.lenA[0] = this.lenC[0] = this.lenA[1] = this.lenC[1] = 0;

            /* initialize IV */
            if (niv == 12) {
                for (i = 0; i < 12; i++) {
                    this.a.f[i] = iv[i];
                }

                b = GCM.unpack(1);
                this.a.f[12] = b[0];
                this.a.f[13] = b[1];
                this.a.f[14] = b[2];
                this.a.f[15] = b[3];

                for (i = 0; i < 16; i++) {
                    this.Y_0[i] = this.a.f[i];
                }
            } else {
                this.status = GCM.ACCEPTING_CIPHER;
                /* GHASH(H,0,IV) */
                this.ghash(iv, niv);
                this.wrap();

                for (i = 0; i < 16; i++) {
                    this.a.f[i] = this.stateX[i];
                    this.Y_0[i] = this.a.f[i];
                    this.stateX[i] = 0;
                }

                this.lenA[0] = this.lenC[0] = this.lenA[1] = this.lenC[1] = 0;
            }

            this.status = GCM.ACCEPTING_HEADER;
        },

        /* Add Header data - included but not encrypted */
        /* len is length of header */
        add_header: function(header, len) {
            var i, j = 0;

            if (this.status != GCM.ACCEPTING_HEADER) {
                return false;
            }

            while (j < len) {
                for (i = 0; i < 16 && j < len; i++) {
                    this.stateX[i] ^= header[j++];
                    this.lenA[1]++;
                    this.lenA[1] |= 0;

                    if (this.lenA[1] === 0) {
                        this.lenA[0]++;
                    }
                }

                this.gf2mul();
            }

            if (len % 16 !== 0) {
                this.status = GCM.ACCEPTING_CIPHER;
            }

            return true;
        },

        ghash: function(plain, len) {
            var i, j = 0;

            if (this.status == GCM.ACCEPTING_HEADER) {
                this.status = GCM.ACCEPTING_CIPHER;
            }

            if (this.status != GCM.ACCEPTING_CIPHER) {
                return false;
            }

            while (j < len) {
                for (i = 0; i < 16 && j < len; i++) {
                    this.stateX[i] ^= plain[j++];
                    this.lenC[1]++;
                    this.lenC[1] |= 0;

                    if (this.lenC[1] === 0) {
                        this.lenC[0]++;
                    }
                }
                this.gf2mul();
            }

            if (len % 16 !== 0) {
                this.status = GCM.NOT_ACCEPTING_MORE;
            }

            return true;
        },

        /* Add Plaintext - included and encrypted */
        add_plain: function(plain, len) {
            var B = [],
                b = [],
                cipher = [],
                i, j = 0;

            if (this.status == GCM.ACCEPTING_HEADER) {
                this.status = GCM.ACCEPTING_CIPHER;
            }

            if (this.status != GCM.ACCEPTING_CIPHER) {
                return cipher;
            }

            while (j < len) {
                /* increment counter */
                b[0] = this.a.f[12];
                b[1] = this.a.f[13];
                b[2] = this.a.f[14];
                b[3] = this.a.f[15];
                this.counter = GCM.pack(b);
                this.counter++;
                b = GCM.unpack(this.counter);
                this.a.f[12] = b[0];
                this.a.f[13] = b[1];
                this.a.f[14] = b[2];
                this.a.f[15] = b[3];

                for (i = 0; i < 16; i++) {
                    B[i] = this.a.f[i];
                }

                /* encrypt it  */
                this.a.ecb_encrypt(B);

                for (i = 0; i < 16 && j < len; i++) {
                    cipher[j] = (plain[j] ^ B[i]);
                    this.stateX[i] ^= cipher[j++];
                    this.lenC[1]++;
                    this.lenC[1] |= 0;

                    if (this.lenC[1] === 0) {
                        this.lenC[0]++;
                    }
                }

                this.gf2mul();
            }

            if (len % 16 !== 0) {
                this.status = GCM.NOT_ACCEPTING_MORE;
            }

            return cipher;
        },

        /* Add Ciphertext - decrypts to plaintext */
        add_cipher: function(cipher, len) {
            var B = [],
                b = [],
                plain = [],
                j = 0,
                i, oc;

            if (this.status == GCM.ACCEPTING_HEADER) {
                this.status = GCM.ACCEPTING_CIPHER;
            }

            if (this.status != GCM.ACCEPTING_CIPHER) {
                return plain;
            }

            while (j < len) {
                /* increment counter */
                b[0] = this.a.f[12];
                b[1] = this.a.f[13];
                b[2] = this.a.f[14];
                b[3] = this.a.f[15];
                this.counter = GCM.pack(b);
                this.counter++;
                b = GCM.unpack(this.counter);
                this.a.f[12] = b[0];
                this.a.f[13] = b[1];
                this.a.f[14] = b[2];
                this.a.f[15] = b[3];

                for (i = 0; i < 16; i++) {
                    B[i] = this.a.f[i];
                }

                /* encrypt it  */
                this.a.ecb_encrypt(B);

                for (i = 0; i < 16 && j < len; i++) {
                    oc = cipher[j];
                    plain[j] = (cipher[j] ^ B[i]);
                    this.stateX[i] ^= oc;
                    j++;
                    this.lenC[1]++;
                    this.lenC[1] |= 0;

                    if (this.lenC[1] === 0) {
                        this.lenC[0]++;
                    }
                }

                this.gf2mul();
            }

            if (len % 16 !== 0) {
                this.status = GCM.NOT_ACCEPTING_MORE;
            }

            return plain;
        },

        /* Finish and extract Tag */
        finish: function(extract) {
            var tag = [],
                i;

            this.wrap();
            /* extract tag */
            if (extract) {
                /* E(K,Y0) */
                this.a.ecb_encrypt(this.Y_0);

                for (i = 0; i < 16; i++) {
                    this.Y_0[i] ^= this.stateX[i];
                }

                for (i = 0; i < 16; i++) {
                    tag[i] = this.Y_0[i];
                    this.Y_0[i] = this.stateX[i] = 0;
                }
            }

            this.status = GCM.FINISHED;
            this.a.end();

            return tag;
        }

    };

    /* pack 4 bytes into a 32-bit Word */
    GCM.pack = function(b) {
        return (((b[0]) & 0xff) << 24) | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff);
    };

    /* unpack bytes from a word */
    GCM.unpack = function(a) {
        var b = [];

        b[3] = (a & 0xff);
        b[2] = ((a >>> 8) & 0xff);
        b[1] = ((a >>> 16) & 0xff);
        b[0] = ((a >>> 24) & 0xff);

        return b;
    };

    GCM.hex2bytes = function(s) {
        var len = s.length,
            data = [],
            i;

        for (i = 0; i < len; i += 2) {
            data[i / 2] = parseInt(s.substr(i, 2), 16);
        }

        return data;
    };

    return GCM;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

function HASH256() {

    var HASH256 = function() {
        this.length = [];
        this.h = [];
        this.w = [];
        this.init();
    };

    HASH256.prototype = {

        /* basic transformation step */
        transform: function() {
            var a, b, c, d, e, f, g, hh, t1, t2, j;

            for (j = 16; j < 64; j++) {
                this.w[j] = (HASH256.theta1(this.w[j - 2]) + this.w[j - 7] + HASH256.theta0(this.w[j - 15]) + this.w[j - 16]) | 0;
            }

            a = this.h[0];
            b = this.h[1];
            c = this.h[2];
            d = this.h[3];
            e = this.h[4];
            f = this.h[5];
            g = this.h[6];
            hh = this.h[7];

            /* 64 times - mush it up */
            for (j = 0; j < 64; j++) {
                t1 = (hh + HASH256.Sig1(e) + HASH256.Ch(e, f, g) + HASH256.HK[j] + this.w[j]) | 0;
                t2 = (HASH256.Sig0(a) + HASH256.Maj(a, b, c)) | 0;
                hh = g;
                g = f;
                f = e;
                e = (d + t1) | 0; // Need to knock these back down to prevent 52-bit overflow
                d = c;
                c = b;
                b = a;
                a = (t1 + t2) | 0;

            }
            this.h[0] += a;
            this.h[1] += b;
            this.h[2] += c;
            this.h[3] += d;
            this.h[4] += e;
            this.h[5] += f;
            this.h[6] += g;
            this.h[7] += hh;

        },

        /* Initialize Hash function */
        init: function() {
            var i;

            for (i = 0; i < 64; i++) {
                this.w[i] = 0;
            }
            this.length[0] = this.length[1] = 0;
            this.h[0] = HASH256.H[0];
            this.h[1] = HASH256.H[1];
            this.h[2] = HASH256.H[2];
            this.h[3] = HASH256.H[3];
            this.h[4] = HASH256.H[4];
            this.h[5] = HASH256.H[5];
            this.h[6] = HASH256.H[6];
            this.h[7] = HASH256.H[7];
        },

        /* process a single byte */
        process: function(byt) {
            var cnt;

            cnt = (this.length[0] >>> 5) % 16;
            this.w[cnt] <<= 8;
            this.w[cnt] |= (byt & 0xFF);
            this.length[0] += 8;

            if ((this.length[0] & 0xffffffff) === 0) {
                this.length[1]++;
                this.length[0] = 0;
            }

            if ((this.length[0] % 512) === 0) {
                this.transform();
            }
        },

        /* process an array of bytes */
        process_array: function(b) {
            for (var i = 0; i < b.length; i++) {
                this.process(b[i]);
            }
        },

        /* process a 32-bit integer */
        process_num: function(n) {
            this.process((n >> 24) & 0xff);
            this.process((n >> 16) & 0xff);
            this.process((n >> 8) & 0xff);
            this.process(n & 0xff);
        },

        /* pad message and finish - supply digest */
        hash: function() {
            var digest = [],
                len0, len1, i;

            len0 = this.length[0];
            len1 = this.length[1];
            this.process(0x80);

            while ((this.length[0] % 512) != 448) {
                this.process(0);
            }

            this.w[14] = len1;
            this.w[15] = len0;
            this.transform();

            /* convert to bytes */
            for (i = 0; i < HASH256.len; i++) {
                digest[i] = ((this.h[i >>> 2] >> (8 * (3 - i % 4))) & 0xff);
            }
            this.init();

            return digest;
        }
    };

    /* static functions */

    HASH256.S = function(n, x) {
        return (((x) >>> n) | ((x) << (32 - n)));
    };

    HASH256.R = function(n, x) {
        return ((x) >>> n);
    };

    HASH256.Ch = function(x, y, z) {
        return ((x & y) ^ (~(x) & z));
    };

    HASH256.Maj = function(x, y, z) {
        return ((x & y) ^ (x & z) ^ (y & z));
    };

    HASH256.Sig0 = function(x) {
        return (HASH256.S(2, x) ^ HASH256.S(13, x) ^ HASH256.S(22, x));
    };

    HASH256.Sig1 = function(x) {
        return (HASH256.S(6, x) ^ HASH256.S(11, x) ^ HASH256.S(25, x));
    };

    HASH256.theta0 = function(x) {
        return (HASH256.S(7, x) ^ HASH256.S(18, x) ^ HASH256.R(3, x));
    };

    HASH256.theta1 = function(x) {
        return (HASH256.S(17, x) ^ HASH256.S(19, x) ^ HASH256.R(10, x));
    };

    /* constants */
    HASH256.len = 32;

    HASH256.H = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];

    HASH256.HK = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    return HASH256;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

function HASH384(ctx) {

    var HASH384 = function() {
        this.length = [];
        this.h = [];
        this.w = [];
        this.init();
    };

    HASH384.prototype = {

        /* basic transformation step */
        transform: function() {
            var a, b, c, d, e, f, g, hh, t1, t2, j;

            for (j = 16; j < 80; j++) {
                this.w[j] = HASH384.theta1(this.w[j - 2]).add(this.w[j - 7]).add(HASH384.theta0(this.w[j - 15])).add(this.w[j - 16]);
            }

            a = this.h[0].copy();
            b = this.h[1].copy();
            c = this.h[2].copy();
            d = this.h[3].copy();
            e = this.h[4].copy();
            f = this.h[5].copy();
            g = this.h[6].copy();
            hh = this.h[7].copy();

            /* 80 times - mush it up */
            for (j = 0; j < 80; j++) {
                t1 = hh.copy();
                t1.add(HASH384.Sig1(e)).add(HASH384.Ch(e, f, g)).add(HASH384.HK[j]).add(this.w[j]);

                t2 = HASH384.Sig0(a);
                t2.add(HASH384.Maj(a, b, c));
                hh = g;
                g = f;
                f = e;
                e = d.copy();
                e.add(t1);

                d = c;
                c = b;
                b = a;
                a = t1.copy();
                a.add(t2);
            }

            this.h[0].add(a);
            this.h[1].add(b);
            this.h[2].add(c);
            this.h[3].add(d);
            this.h[4].add(e);
            this.h[5].add(f);
            this.h[6].add(g);
            this.h[7].add(hh);
        },

        /* Initialize Hash function */
        init: function() {
            var i;

            for (i = 0; i < 80; i++) {
                this.w[i] = new ctx.UInt64(0, 0);
            }
            this.length[0] = new ctx.UInt64(0, 0);
            this.length[1] = new ctx.UInt64(0, 0);
            this.h[0] = HASH384.H[0].copy();
            this.h[1] = HASH384.H[1].copy();
            this.h[2] = HASH384.H[2].copy();
            this.h[3] = HASH384.H[3].copy();
            this.h[4] = HASH384.H[4].copy();
            this.h[5] = HASH384.H[5].copy();
            this.h[6] = HASH384.H[6].copy();
            this.h[7] = HASH384.H[7].copy();
        },

        /* process a single byte */
        process: function(byt) {
            var cnt, e;

            cnt = (this.length[0].bot >>> 6) % 16;
            this.w[cnt].shlb();
            this.w[cnt].bot |= (byt & 0xFF);

            e = new ctx.UInt64(0, 8);
            this.length[0].add(e);

            if (this.length[0].top === 0 && this.length[0].bot == 0) {
                e = new ctx.UInt64(0, 1);
                this.length[1].add(e);
            }

            if ((this.length[0].bot % 1024) === 0) {
                this.transform();
            }
        },

        /* process an array of bytes */
        process_array: function(b) {
            for (var i = 0; i < b.length; i++) {
                this.process(b[i]);
            }
        },

        /* process a 32-bit integer */
        process_num: function(n) {
            this.process((n >> 24) & 0xff);
            this.process((n >> 16) & 0xff);
            this.process((n >> 8) & 0xff);
            this.process(n & 0xff);
        },

        /* pad message and finish - supply digest */
        hash: function() {
            var digest = [],
                len0, len1,
                i;

            len0 = this.length[0].copy();
            len1 = this.length[1].copy();
            this.process(0x80);
            while ((this.length[0].bot % 1024) != 896) {
                this.process(0);
            }

            this.w[14] = len1;
            this.w[15] = len0;
            this.transform();

            /* convert to bytes */
            for (i = 0; i < HASH384.len; i++) {
                digest[i] = HASH384.R(8 * (7 - i % 8), this.h[i >>> 3]).bot & 0xff;
            }

            this.init();

            return digest;
        }
    };


    /* static  functions */
    HASH384.S = function(n, x) {
        if (n == 0) {
            return x;
        }

        if (n < 32) {
            return new ctx.UInt64((x.top >>> n) | (x.bot << (32 - n)), (x.bot >>> n) | (x.top << (32 - n)));
        } else {
            return new ctx.UInt64((x.bot >>> (n - 32)) | (x.top << (64 - n)), (x.top >>> (n - 32)) | (x.bot << (64 - n)));
        }

    };

    HASH384.R = function(n, x) {
        if (n == 0) {
            return x;
        }

        if (n < 32) {
            return new ctx.UInt64((x.top >>> n), (x.bot >>> n | (x.top << (32 - n))));
        } else {
            return new ctx.UInt64(0, x.top >>> (n - 32));
        }
    };

    HASH384.Ch = function(x, y, z) {
        return new ctx.UInt64((x.top & y.top) ^ (~(x.top) & z.top), (x.bot & y.bot) ^ (~(x.bot) & z.bot));
    };

    HASH384.Maj = function(x, y, z) {
        return new ctx.UInt64((x.top & y.top) ^ (x.top & z.top) ^ (y.top & z.top), (x.bot & y.bot) ^ (x.bot & z.bot) ^ (y.bot & z.bot));
    };

    HASH384.Sig0 = function(x) {
        var r1 = HASH384.S(28, x),
            r2 = HASH384.S(34, x),
            r3 = HASH384.S(39, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH384.Sig1 = function(x) {
        var r1 = HASH384.S(14, x),
            r2 = HASH384.S(18, x),
            r3 = HASH384.S(41, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH384.theta0 = function(x) {
        var r1 = HASH384.S(1, x),
            r2 = HASH384.S(8, x),
            r3 = HASH384.R(7, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH384.theta1 = function(x) {
        var r1 = HASH384.S(19, x),
            r2 = HASH384.S(61, x),
            r3 = HASH384.R(6, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH384.len = 48;

    HASH384.H = [new ctx.UInt64(0xcbbb9d5d, 0xc1059ed8), new ctx.UInt64(0x629a292a, 0x367cd507),
        new ctx.UInt64(0x9159015a, 0x3070dd17), new ctx.UInt64(0x152fecd8, 0xf70e5939),
        new ctx.UInt64(0x67332667, 0xffc00b31), new ctx.UInt64(0x8eb44a87, 0x68581511),
        new ctx.UInt64(0xdb0c2e0d, 0x64f98fa7), new ctx.UInt64(0x47b5481d, 0xbefa4fa4)
    ];

    HASH384.HK = [new ctx.UInt64(0x428a2f98, 0xd728ae22), new ctx.UInt64(0x71374491, 0x23ef65cd),
        new ctx.UInt64(0xb5c0fbcf, 0xec4d3b2f), new ctx.UInt64(0xe9b5dba5, 0x8189dbbc),
        new ctx.UInt64(0x3956c25b, 0xf348b538), new ctx.UInt64(0x59f111f1, 0xb605d019),
        new ctx.UInt64(0x923f82a4, 0xaf194f9b), new ctx.UInt64(0xab1c5ed5, 0xda6d8118),
        new ctx.UInt64(0xd807aa98, 0xa3030242), new ctx.UInt64(0x12835b01, 0x45706fbe),
        new ctx.UInt64(0x243185be, 0x4ee4b28c), new ctx.UInt64(0x550c7dc3, 0xd5ffb4e2),
        new ctx.UInt64(0x72be5d74, 0xf27b896f), new ctx.UInt64(0x80deb1fe, 0x3b1696b1),
        new ctx.UInt64(0x9bdc06a7, 0x25c71235), new ctx.UInt64(0xc19bf174, 0xcf692694),
        new ctx.UInt64(0xe49b69c1, 0x9ef14ad2), new ctx.UInt64(0xefbe4786, 0x384f25e3),
        new ctx.UInt64(0x0fc19dc6, 0x8b8cd5b5), new ctx.UInt64(0x240ca1cc, 0x77ac9c65),
        new ctx.UInt64(0x2de92c6f, 0x592b0275), new ctx.UInt64(0x4a7484aa, 0x6ea6e483),
        new ctx.UInt64(0x5cb0a9dc, 0xbd41fbd4), new ctx.UInt64(0x76f988da, 0x831153b5),
        new ctx.UInt64(0x983e5152, 0xee66dfab), new ctx.UInt64(0xa831c66d, 0x2db43210),
        new ctx.UInt64(0xb00327c8, 0x98fb213f), new ctx.UInt64(0xbf597fc7, 0xbeef0ee4),
        new ctx.UInt64(0xc6e00bf3, 0x3da88fc2), new ctx.UInt64(0xd5a79147, 0x930aa725),
        new ctx.UInt64(0x06ca6351, 0xe003826f), new ctx.UInt64(0x14292967, 0x0a0e6e70),
        new ctx.UInt64(0x27b70a85, 0x46d22ffc), new ctx.UInt64(0x2e1b2138, 0x5c26c926),
        new ctx.UInt64(0x4d2c6dfc, 0x5ac42aed), new ctx.UInt64(0x53380d13, 0x9d95b3df),
        new ctx.UInt64(0x650a7354, 0x8baf63de), new ctx.UInt64(0x766a0abb, 0x3c77b2a8),
        new ctx.UInt64(0x81c2c92e, 0x47edaee6), new ctx.UInt64(0x92722c85, 0x1482353b),
        new ctx.UInt64(0xa2bfe8a1, 0x4cf10364), new ctx.UInt64(0xa81a664b, 0xbc423001),
        new ctx.UInt64(0xc24b8b70, 0xd0f89791), new ctx.UInt64(0xc76c51a3, 0x0654be30),
        new ctx.UInt64(0xd192e819, 0xd6ef5218), new ctx.UInt64(0xd6990624, 0x5565a910),
        new ctx.UInt64(0xf40e3585, 0x5771202a), new ctx.UInt64(0x106aa070, 0x32bbd1b8),
        new ctx.UInt64(0x19a4c116, 0xb8d2d0c8), new ctx.UInt64(0x1e376c08, 0x5141ab53),
        new ctx.UInt64(0x2748774c, 0xdf8eeb99), new ctx.UInt64(0x34b0bcb5, 0xe19b48a8),
        new ctx.UInt64(0x391c0cb3, 0xc5c95a63), new ctx.UInt64(0x4ed8aa4a, 0xe3418acb),
        new ctx.UInt64(0x5b9cca4f, 0x7763e373), new ctx.UInt64(0x682e6ff3, 0xd6b2b8a3),
        new ctx.UInt64(0x748f82ee, 0x5defb2fc), new ctx.UInt64(0x78a5636f, 0x43172f60),
        new ctx.UInt64(0x84c87814, 0xa1f0ab72), new ctx.UInt64(0x8cc70208, 0x1a6439ec),
        new ctx.UInt64(0x90befffa, 0x23631e28), new ctx.UInt64(0xa4506ceb, 0xde82bde9),
        new ctx.UInt64(0xbef9a3f7, 0xb2c67915), new ctx.UInt64(0xc67178f2, 0xe372532b),
        new ctx.UInt64(0xca273ece, 0xea26619c), new ctx.UInt64(0xd186b8c7, 0x21c0c207),
        new ctx.UInt64(0xeada7dd6, 0xcde0eb1e), new ctx.UInt64(0xf57d4f7f, 0xee6ed178),
        new ctx.UInt64(0x06f067aa, 0x72176fba), new ctx.UInt64(0x0a637dc5, 0xa2c898a6),
        new ctx.UInt64(0x113f9804, 0xbef90dae), new ctx.UInt64(0x1b710b35, 0x131c471b),
        new ctx.UInt64(0x28db77f5, 0x23047d84), new ctx.UInt64(0x32caab7b, 0x40c72493),
        new ctx.UInt64(0x3c9ebe0a, 0x15c9bebc), new ctx.UInt64(0x431d67c4, 0x9c100d4c),
        new ctx.UInt64(0x4cc5d4be, 0xcb3e42b6), new ctx.UInt64(0x597f299c, 0xfc657e2a),
        new ctx.UInt64(0x5fcb6fab, 0x3ad6faec), new ctx.UInt64(0x6c44198c, 0x4a475817)
    ];

    return HASH384;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

function HASH512(ctx) {

    var HASH512 = function() {
        this.length = [];
        this.h = [];
        this.w = [];
        this.init();
    };

    HASH512.prototype = {

        /* basic transformation step */
        transform: function() {
            var a, b, c, d, e, f, g, hh, t1, t2, j;

            for (j = 16; j < 80; j++) {
                this.w[j] = HASH512.theta1(this.w[j - 2]).add(this.w[j - 7]).add(HASH512.theta0(this.w[j - 15])).add(this.w[j - 16]);
            }

            a = this.h[0].copy();
            b = this.h[1].copy();
            c = this.h[2].copy();
            d = this.h[3].copy();
            e = this.h[4].copy();
            f = this.h[5].copy();
            g = this.h[6].copy();
            hh = this.h[7].copy();

            /* 80 times - mush it up */
            for (j = 0; j < 80; j++) {
                t1 = hh.copy();
                t1.add(HASH512.Sig1(e)).add(HASH512.Ch(e, f, g)).add(HASH512.HK[j]).add(this.w[j]);

                t2 = HASH512.Sig0(a);
                t2.add(HASH512.Maj(a, b, c));
                hh = g;
                g = f;
                f = e;
                e = d.copy();
                e.add(t1);

                d = c;
                c = b;
                b = a;
                a = t1.copy();
                a.add(t2);
            }

            this.h[0].add(a);
            this.h[1].add(b);
            this.h[2].add(c);
            this.h[3].add(d);
            this.h[4].add(e);
            this.h[5].add(f);
            this.h[6].add(g);
            this.h[7].add(hh);
        },

        /* Initialize Hash function */
        init: function() {
            var i;

            for (i = 0; i < 80; i++) {
                this.w[i] = new ctx.UInt64(0, 0);
            }

            this.length[0] = new ctx.UInt64(0, 0);
            this.length[1] = new ctx.UInt64(0, 0);
            this.h[0] = HASH512.H[0].copy();
            this.h[1] = HASH512.H[1].copy();
            this.h[2] = HASH512.H[2].copy();
            this.h[3] = HASH512.H[3].copy();
            this.h[4] = HASH512.H[4].copy();
            this.h[5] = HASH512.H[5].copy();
            this.h[6] = HASH512.H[6].copy();
            this.h[7] = HASH512.H[7].copy();
        },

        /* process a single byte */
        process: function(byt) {
            var cnt, e;

            cnt = (this.length[0].bot >>> 6) % 16;
            this.w[cnt].shlb();
            this.w[cnt].bot |= (byt & 0xFF);

            e = new ctx.UInt64(0, 8);
            this.length[0].add(e);

            if (this.length[0].top === 0 && this.length[0].bot == 0) {
                e = new ctx.UInt64(0, 1);
                this.length[1].add(e);
            }

            if ((this.length[0].bot % 1024) === 0) {
                this.transform();
            }
        },

        /* process an array of bytes */
        process_array: function(b) {
            for (var i = 0; i < b.length; i++) {
                this.process(b[i]);
            }
        },

        /* process a 32-bit integer */
        process_num: function(n) {
            this.process((n >> 24) & 0xff);
            this.process((n >> 16) & 0xff);
            this.process((n >> 8) & 0xff);
            this.process(n & 0xff);
        },

        /* pad message and finish - supply digest */
        hash: function() {
            var digest = [],
                len0, len1, i;

            len0 = this.length[0].copy();
            len1 = this.length[1].copy();
            this.process(0x80);

            while ((this.length[0].bot % 1024) != 896) {
                this.process(0);
            }

            this.w[14] = len1;
            this.w[15] = len0;
            this.transform();

            /* convert to bytes */
            for (i = 0; i < HASH512.len; i++) {
                digest[i] = HASH512.R(8 * (7 - i % 8), this.h[i >>> 3]).bot & 0xff;
            }

            this.init();

            return digest;
        }
    };

    /* static functions */
    HASH512.S = function(n, x) {
        if (n == 0) {
            return x;
        }

        if (n < 32) {
            return new ctx.UInt64((x.top >>> n) | (x.bot << (32 - n)), (x.bot >>> n) | (x.top << (32 - n)));
        } else {
            return new ctx.UInt64((x.bot >>> (n - 32)) | (x.top << (64 - n)), (x.top >>> (n - 32)) | (x.bot << (64 - n)));
        }

    };

    HASH512.R = function(n, x) {
        if (n == 0) {
            return x;
        }

        if (n < 32) {
            return new ctx.UInt64((x.top >>> n), (x.bot >>> n | (x.top << (32 - n))));
        } else {
            return new ctx.UInt64(0, x.top >>> (n - 32));
        }
    };

    HASH512.Ch = function(x, y, z) {
        return new ctx.UInt64((x.top & y.top) ^ (~(x.top) & z.top), (x.bot & y.bot) ^ (~(x.bot) & z.bot));
    };

    HASH512.Maj = function(x, y, z) {
        return new ctx.UInt64((x.top & y.top) ^ (x.top & z.top) ^ (y.top & z.top), (x.bot & y.bot) ^ (x.bot & z.bot) ^ (y.bot & z.bot));
    };

    HASH512.Sig0 = function(x) {
        var r1 = HASH512.S(28, x),
            r2 = HASH512.S(34, x),
            r3 = HASH512.S(39, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH512.Sig1 = function(x) {
        var r1 = HASH512.S(14, x),
            r2 = HASH512.S(18, x),
            r3 = HASH512.S(41, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH512.theta0 = function(x) {
        var r1 = HASH512.S(1, x),
            r2 = HASH512.S(8, x),
            r3 = HASH512.R(7, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH512.theta1 = function(x) {
        var r1 = HASH512.S(19, x),
            r2 = HASH512.S(61, x),
            r3 = HASH512.R(6, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    /* constants */
    HASH512.len = 64;

    HASH512.H = [new ctx.UInt64(0x6a09e667, 0xf3bcc908), new ctx.UInt64(0xbb67ae85, 0x84caa73b),
        new ctx.UInt64(0x3c6ef372, 0xfe94f82b), new ctx.UInt64(0xa54ff53a, 0x5f1d36f1),
        new ctx.UInt64(0x510e527f, 0xade682d1), new ctx.UInt64(0x9b05688c, 0x2b3e6c1f),
        new ctx.UInt64(0x1f83d9ab, 0xfb41bd6b), new ctx.UInt64(0x5be0cd19, 0x137e2179)
    ];

    HASH512.HK = [new ctx.UInt64(0x428a2f98, 0xd728ae22), new ctx.UInt64(0x71374491, 0x23ef65cd),
        new ctx.UInt64(0xb5c0fbcf, 0xec4d3b2f), new ctx.UInt64(0xe9b5dba5, 0x8189dbbc),
        new ctx.UInt64(0x3956c25b, 0xf348b538), new ctx.UInt64(0x59f111f1, 0xb605d019),
        new ctx.UInt64(0x923f82a4, 0xaf194f9b), new ctx.UInt64(0xab1c5ed5, 0xda6d8118),
        new ctx.UInt64(0xd807aa98, 0xa3030242), new ctx.UInt64(0x12835b01, 0x45706fbe),
        new ctx.UInt64(0x243185be, 0x4ee4b28c), new ctx.UInt64(0x550c7dc3, 0xd5ffb4e2),
        new ctx.UInt64(0x72be5d74, 0xf27b896f), new ctx.UInt64(0x80deb1fe, 0x3b1696b1),
        new ctx.UInt64(0x9bdc06a7, 0x25c71235), new ctx.UInt64(0xc19bf174, 0xcf692694),
        new ctx.UInt64(0xe49b69c1, 0x9ef14ad2), new ctx.UInt64(0xefbe4786, 0x384f25e3),
        new ctx.UInt64(0x0fc19dc6, 0x8b8cd5b5), new ctx.UInt64(0x240ca1cc, 0x77ac9c65),
        new ctx.UInt64(0x2de92c6f, 0x592b0275), new ctx.UInt64(0x4a7484aa, 0x6ea6e483),
        new ctx.UInt64(0x5cb0a9dc, 0xbd41fbd4), new ctx.UInt64(0x76f988da, 0x831153b5),
        new ctx.UInt64(0x983e5152, 0xee66dfab), new ctx.UInt64(0xa831c66d, 0x2db43210),
        new ctx.UInt64(0xb00327c8, 0x98fb213f), new ctx.UInt64(0xbf597fc7, 0xbeef0ee4),
        new ctx.UInt64(0xc6e00bf3, 0x3da88fc2), new ctx.UInt64(0xd5a79147, 0x930aa725),
        new ctx.UInt64(0x06ca6351, 0xe003826f), new ctx.UInt64(0x14292967, 0x0a0e6e70),
        new ctx.UInt64(0x27b70a85, 0x46d22ffc), new ctx.UInt64(0x2e1b2138, 0x5c26c926),
        new ctx.UInt64(0x4d2c6dfc, 0x5ac42aed), new ctx.UInt64(0x53380d13, 0x9d95b3df),
        new ctx.UInt64(0x650a7354, 0x8baf63de), new ctx.UInt64(0x766a0abb, 0x3c77b2a8),
        new ctx.UInt64(0x81c2c92e, 0x47edaee6), new ctx.UInt64(0x92722c85, 0x1482353b),
        new ctx.UInt64(0xa2bfe8a1, 0x4cf10364), new ctx.UInt64(0xa81a664b, 0xbc423001),
        new ctx.UInt64(0xc24b8b70, 0xd0f89791), new ctx.UInt64(0xc76c51a3, 0x0654be30),
        new ctx.UInt64(0xd192e819, 0xd6ef5218), new ctx.UInt64(0xd6990624, 0x5565a910),
        new ctx.UInt64(0xf40e3585, 0x5771202a), new ctx.UInt64(0x106aa070, 0x32bbd1b8),
        new ctx.UInt64(0x19a4c116, 0xb8d2d0c8), new ctx.UInt64(0x1e376c08, 0x5141ab53),
        new ctx.UInt64(0x2748774c, 0xdf8eeb99), new ctx.UInt64(0x34b0bcb5, 0xe19b48a8),
        new ctx.UInt64(0x391c0cb3, 0xc5c95a63), new ctx.UInt64(0x4ed8aa4a, 0xe3418acb),
        new ctx.UInt64(0x5b9cca4f, 0x7763e373), new ctx.UInt64(0x682e6ff3, 0xd6b2b8a3),
        new ctx.UInt64(0x748f82ee, 0x5defb2fc), new ctx.UInt64(0x78a5636f, 0x43172f60),
        new ctx.UInt64(0x84c87814, 0xa1f0ab72), new ctx.UInt64(0x8cc70208, 0x1a6439ec),
        new ctx.UInt64(0x90befffa, 0x23631e28), new ctx.UInt64(0xa4506ceb, 0xde82bde9),
        new ctx.UInt64(0xbef9a3f7, 0xb2c67915), new ctx.UInt64(0xc67178f2, 0xe372532b),
        new ctx.UInt64(0xca273ece, 0xea26619c), new ctx.UInt64(0xd186b8c7, 0x21c0c207),
        new ctx.UInt64(0xeada7dd6, 0xcde0eb1e), new ctx.UInt64(0xf57d4f7f, 0xee6ed178),
        new ctx.UInt64(0x06f067aa, 0x72176fba), new ctx.UInt64(0x0a637dc5, 0xa2c898a6),
        new ctx.UInt64(0x113f9804, 0xbef90dae), new ctx.UInt64(0x1b710b35, 0x131c471b),
        new ctx.UInt64(0x28db77f5, 0x23047d84), new ctx.UInt64(0x32caab7b, 0x40c72493),
        new ctx.UInt64(0x3c9ebe0a, 0x15c9bebc), new ctx.UInt64(0x431d67c4, 0x9c100d4c),
        new ctx.UInt64(0x4cc5d4be, 0xcb3e42b6), new ctx.UInt64(0x597f299c, 0xfc657e2a),
        new ctx.UInt64(0x5fcb6fab, 0x3ad6faec), new ctx.UInt64(0x6c44198c, 0x4a475817)
    ];

    return HASH512;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* MPIN API Functions */

function MPIN(ctx) {

    var MPIN = {
        BAD_PARAMS: -11,
        INVALID_POINT: -14,
        WRONG_ORDER: -18,
        BAD_PIN: -19,
        /* configure PIN here */
        MAXPIN: 10000,
        /* max PIN */
        PBLEN: 14,
        /* MAXPIN length in bits */
        TS: 12,
        /* 10 for 4 digit PIN, 14 for 6-digit PIN - 2^TS/TS approx = sqrt(MAXPIN) */
        TRAP: 2000,
        /* 200 for 4 digit PIN, 2000 for 6-digit PIN  - approx 2*sqrt(MAXPIN) */
        EFS: ctx.BIG.MODBYTES,
        EGS: ctx.BIG.MODBYTES,

        SHA256: 32,
        SHA384: 48,
        SHA512: 64,

        /* return time in slots since epoch */
        today: function() {
            var now = new Date();
            return Math.floor(now.getTime() / (60000 * 1440)); // for daily tokens
        },

        bytestostring: function(b) {
            var s = "",
                len = b.length,
                ch, i;

            for (i = 0; i < len; i++) {
                ch = b[i];
                s += ((ch >>> 4) & 15).toString(16);
                s += (ch & 15).toString(16);

            }

            return s;
        },

        stringtobytes: function(s) {
            var b = [],
                i;

            for (i = 0; i < s.length; i++) {
                b.push(s.charCodeAt(i));
            }

            return b;
        },

        comparebytes: function(a, b) {
            if (a.length != b.length) {
                return false;
            }

            for (var i = 0; i < a.length; i++) {
                if (a[i] != b[i]) {
                    return false;
                }
            }

            return true;
        },

        mpin_hash: function(sha, c, U) {
            var t = [],
                w = [],
                h = [],
                H, R, i;

            c.geta().getA().toBytes(w);
            for (i = 0; i < this.EFS; i++) {
                t[i] = w[i];
            }
            c.geta().getB().toBytes(w);
            for (i = this.EFS; i < 2 * this.EFS; i++) {
                t[i] = w[i - this.EFS];
            }
            c.getb().getA().toBytes(w);
            for (i = 2 * this.EFS; i < 3 * this.EFS; i++) {
                t[i] = w[i - 2 * this.EFS];
            }
            c.getb().getB().toBytes(w);
            for (i = 3 * this.EFS; i < 4 * this.EFS; i++) {
                t[i] = w[i - 3 * this.EFS];
            }

            U.getX().toBytes(w);
            for (i = 4 * this.EFS; i < 5 * this.EFS; i++) {
                t[i] = w[i - 4 * this.EFS];
            }
            U.getY().toBytes(w);
            for (i = 5 * this.EFS; i < 6 * this.EFS; i++) {
                t[i] = w[i - 5 * this.EFS];
            }

            if (sha == this.SHA256) {
                H = new ctx.HASH256();
            } else if (sha == this.SHA384) {
                H = new ctx.HASH384();
            } else if (sha == this.SHA512) {
                H = new ctx.HASH512();
            }

            H.process_array(t);
            h = H.hash();

            if (h.length == 0) {
                return null;
            }

            R = [];
            for (i = 0; i < ctx.ECP.AESKEY; i++) {
                R[i] = h[i];
            }

            return R;
        },

        /* Hash number (optional) and string to point on curve */
        hashit: function(sha, n, B) {
            var R = [],
                H, W, i, len;

            if (sha == this.SHA256) {
                H = new ctx.HASH256();
            } else if (sha == this.SHA384) {
                H = new ctx.HASH384();
            } else if (sha == this.SHA512) {
                H = new ctx.HASH512();
            }

            if (n > 0) {
                H.process_num(n);
            }
            H.process_array(B);
            R = H.hash();

            if (R.length == 0) {
                return null;
            }

            W = [];

            len = ctx.BIG.MODBYTES;

            if (sha >= len) {
                for (i = 0; i < len; i++) {
                    W[i] = R[i];
                }
            } else {
                for (i = 0; i < sha; i++) {
                    W[i + len - sha] = R[i];
                }

                for (i = 0; i < len - sha; i++) {
                    W[i] = 0;
                }
            }

            return W;
        },

        /* these next two functions help to implement elligator squared - http://eprint.iacr.org/2014/043 */
        /* maps a random u to a point on the curve */
        map: function(u, cb) {
            var P = new ctx.ECP(),
                x = new ctx.BIG(u),
                p = new ctx.BIG(0);

            p.rcopy(ctx.ROM_FIELD.Modulus);
            x.mod(p);

            for (;;) {
                P.setxi(x, cb);
                if (!P.is_infinity()) {
                    break;
                }
                x.inc(1);
                x.norm();
            }

            return P;
        },

        /* returns u derived from P. Random value in range 1 to return value should then be added to u */
        unmap: function(u, P) {
            var s = P.getS(),
                R = new ctx.ECP(),
                r = 0,
                x = P.getX();

            u.copy(x);

            for (;;) {
                u.dec(1);
                u.norm();
                r++;
                R.setxi(u, s);
                if (!R.is_infinity()) {
                    break;
                }
            }

            return r;
        },

        /* these next two functions implement elligator squared - http://eprint.iacr.org/2014/043 */
        /* Elliptic curve point E in format (0x04,x,y} is converted to form {0x0-,u,v} */
        /* Note that u and v are indistinguishable from random strings */
        ENCODING: function(rng, E) {
            var T = [],
                i, rn, m, su, sv,
                u, v, P, p, W;

            for (i = 0; i < this.EFS; i++) {
                T[i] = E[i + 1];
            }
            u = ctx.BIG.fromBytes(T);
            for (i = 0; i < this.EFS; i++) {
                T[i] = E[i + this.EFS + 1];
            }
            v = ctx.BIG.fromBytes(T);

            P = new ctx.ECP(0);
            P.setxy(u, v);
            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            p = new ctx.BIG(0);
            p.rcopy(ctx.ROM_FIELD.Modulus);
            u = ctx.BIG.randomnum(p, rng);

            su = rng.getByte();
            if (su < 0) {
                su = -su;
            }
            su %= 2;

            W = this.map(u, su);
            P.sub(W);
            sv = P.getS();
            rn = this.unmap(v, P);
            m = rng.getByte();
            if (m < 0) {
                m = -m;
            }
            m %= rn;
            v.inc(m + 1);
            E[0] = (su + 2 * sv);
            u.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                E[i + 1] = T[i];
            }
            v.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                E[i + this.EFS + 1] = T[i];
            }

            return 0;
        },

        DECODING: function(D) {
            var T = [],
                i, su, sv, u, v, W, P;

            if ((D[0] & 0x04) !== 0) {
                return this.INVALID_POINT;
            }

            for (i = 0; i < this.EFS; i++) {
                T[i] = D[i + 1];
            }
            u = ctx.BIG.fromBytes(T);
            for (i = 0; i < this.EFS; i++) {
                T[i] = D[i + this.EFS + 1];
            }
            v = ctx.BIG.fromBytes(T);

            su = D[0] & 1;
            sv = (D[0] >> 1) & 1;
            W = this.map(u, su);
            P = this.map(v, sv);
            P.add(W);
            u = P.getX();
            v = P.getY();
            D[0] = 0x04;
            u.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                D[i + 1] = T[i];
            }
            v.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                D[i + this.EFS + 1] = T[i];
            }

            return 0;
        },

        /* R=R1+R2 in group G1 */
        RECOMBINE_G1: function(R1, R2, R) {
            var P = ctx.ECP.fromBytes(R1),
                Q = ctx.ECP.fromBytes(R2);

            if (P.is_infinity() || Q.is_infinity()) {
                return this.INVALID_POINT;
            }

            P.add(Q);

            P.toBytes(R);

            return 0;
        },

        /* W=W1+W2 in group G2 */
        RECOMBINE_G2: function(W1, W2, W) {
            var P = ctx.ECP2.fromBytes(W1),
                Q = ctx.ECP2.fromBytes(W2);

            if (P.is_infinity() || Q.is_infinity()) {
                return this.INVALID_POINT;
            }

            P.add(Q);

            P.toBytes(W);

            return 0;
        },

        HASH_ID: function(sha, ID) {
            return this.hashit(sha, 0, ID);
        },

        /* create random secret S */
        RANDOM_GENERATE: function(rng, S) {
            var r = new ctx.BIG(0),
                s;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            s = ctx.BIG.randomnum(r, rng);
            s.toBytes(S);

            return 0;
        },

        /* Extract PIN from TOKEN for identity CID */
        EXTRACT_PIN: function(sha, CID, pin, TOKEN) {
            return this.EXTRACT_FACTOR(sha,CID,pin%this.MAXPIN,this.PBLEN,TOKEN);
        },

        /* Extract factor from TOKEN for identity CID */
        EXTRACT_FACTOR: function(sha, CID, factor, facbits, TOKEN) {
            var P, R, h;

            P = ctx.ECP.fromBytes(TOKEN);

            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            h = this.hashit(sha, 0, CID);
            R = ctx.ECP.mapit(h);

            R = R.pinmul(factor, facbits);
            P.sub(R);

            P.toBytes(TOKEN);

            return 0;
        },

        /* Restore factor to TOKEN for identity CID */
        RESTORE_FACTOR: function(sha, CID, factor, facbits, TOKEN) {
            var P, R, h;

            P = ctx.ECP.fromBytes(TOKEN);

            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            h = this.hashit(sha, 0, CID),
            R = ctx.ECP.mapit(h);

            R = R.pinmul(factor, facbits);
            P.add(R);

            P.toBytes(TOKEN);

            return 0;
        },

        /* Extract Server Secret SST=S*Q where Q is fixed generator in G2 and S is master secret */
        GET_SERVER_SECRET: function(S, SST) {
            var s,Q;

            Q = ctx.ECP2.generator();

            s = ctx.BIG.fromBytes(S);
            Q = ctx.PAIR.G2mul(Q, s);
            Q.toBytes(SST);

            return 0;
        },

        /*
         W=x*H(G);
         if RNG == NULL then X is passed in
         if RNG != NULL the X is passed out
         if type=0 W=x*G where G is point on the curve, else W=x*M(G), where M(G) is mapping of octet G to point on the curve
        */
        GET_G1_MULTIPLE: function(rng, type, X, G, W) {
            var r = new ctx.BIG(0),
                x, P;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (rng != null) {
                x = ctx.BIG.randomnum(r, rng);
                x.toBytes(X);
            } else {
                x = ctx.BIG.fromBytes(X);
            }

            if (type == 0) {
                P = ctx.ECP.fromBytes(G);
                if (P.is_infinity()) {
                    return this.INVALID_POINT;
                }
            } else {
                P = ctx.ECP.mapit(G);
            }

            ctx.PAIR.G1mul(P, x).toBytes(W);

            return 0;
        },


        /* Client secret CST=S*H(CID) where CID is client ID and S is master secret */
        GET_CLIENT_SECRET: function(S, CID, CST) {
            return this.GET_G1_MULTIPLE(null, 1, S, CID, CST);
        },

        /* Time Permit CTT=S*(date|H(CID)) where S is master secret */
        GET_CLIENT_PERMIT: function(sha, date, S, CID, CTT) {
            var h = this.hashit(sha, date, CID),
                P = ctx.ECP.mapit(h),
                s = ctx.BIG.fromBytes(S);

            P = ctx.PAIR.G1mul(P, s);
            P.toBytes(CTT);

            return 0;
        },

        /* Implement step 1 on client side of MPin protocol */
        CLIENT_1: function(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT) {
            var r = new ctx.BIG(0),
                x, P, T, W, h;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            //  var q=new ctx.BIG(0); q.rcopy(ctx.ROM_FIELD.Modulus);
            if (rng !== null) {
                x = ctx.BIG.randomnum(r, rng);
                x.toBytes(X);
            } else {
                x = ctx.BIG.fromBytes(X);
            }

            h = this.hashit(sha, 0, CLIENT_ID);
            P = ctx.ECP.mapit(h);
            T = ctx.ECP.fromBytes(TOKEN);
            if (T.is_infinity()) {
                return this.INVALID_POINT;
            }

            pin %= this.MAXPIN;
            W = P.pinmul(pin, this.PBLEN);
            T.add(W);

            if (date != 0) {
                W = ctx.ECP.fromBytes(PERMIT);

                if (W.is_infinity()) {
                    return this.INVALID_POINT;
                }

                T.add(W);
                h = this.hashit(sha, date, h);
                W = ctx.ECP.mapit(h);

                if (xID != null) {
                    P = ctx.PAIR.G1mul(P, x);
                    P.toBytes(xID);
                    W = ctx.PAIR.G1mul(W, x);
                    P.add(W);
                } else {
                    P.add(W);
                    P = ctx.PAIR.G1mul(P, x);
                }

                if (xCID != null) {
                    P.toBytes(xCID);
                }
            } else {
                if (xID != null) {
                    P = ctx.PAIR.G1mul(P, x);
                    P.toBytes(xID);
                }
            }

            T.toBytes(SEC);

            return 0;
        },

        /* Implement step 2 on client side of MPin protocol */
        CLIENT_2: function(X, Y, SEC) {
            var r = new ctx.BIG(0),
                P, px, py;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            P = ctx.ECP.fromBytes(SEC);
            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            px = ctx.BIG.fromBytes(X);
            py = ctx.BIG.fromBytes(Y);
            px.add(py);
            px.mod(r);

            P = ctx.PAIR.G1mul(P, px);
            P.neg();
            P.toBytes(SEC);

            return 0;
        },

        /* Outputs H(CID) and H(T|H(CID)) for time permits. If no time permits set HID=HTID */
        SERVER_1: function(sha, date, CID, HID, HTID) {
            var h = this.hashit(sha, 0, CID),
                P = ctx.ECP.mapit(h),
                R;

            P.toBytes(HID);
            if (date !== 0) {
                h = this.hashit(sha, date, h);
                R = ctx.ECP.mapit(h);
                P.add(R);
                P.toBytes(HTID);
            }
        },

        /* Implement step 1 of MPin protocol on server side. Pa is the client public key in case of DVS, otherwise must be set to null */
        SERVER_2: function(date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, Pa) {
            var Q, sQ, R, y, P, g;

            if (typeof Pa === "undefined" || Pa == null) {
                Q = ctx.ECP2.generator();

            } else {
                Q = ctx.ECP2.fromBytes(Pa);
                if (Q.is_infinity()) {
                    return this.INVALID_POINT;
                }
            }

            sQ = ctx.ECP2.fromBytes(SST);
            if (sQ.is_infinity()) {
                return this.INVALID_POINT;
            }

            if (date !== 0) {
                R = ctx.ECP.fromBytes(xCID);
            } else {
                if (xID == null) {
                    return this.BAD_PARAMS;
                }
                R = ctx.ECP.fromBytes(xID);
            }

            if (R.is_infinity()) {
                return this.INVALID_POINT;
            }

            y = ctx.BIG.fromBytes(Y);

            if (date != 0) {
                P = ctx.ECP.fromBytes(HTID);
            } else {
                if (HID == null) {
                    return this.BAD_PARAMS;
                }
                P = ctx.ECP.fromBytes(HID);
            }

            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            P = ctx.PAIR.G1mul(P, y);
            P.add(R);
            P.affine();
            R = ctx.ECP.fromBytes(mSEC);
            if (R.is_infinity()) {
                return this.INVALID_POINT;
            }

            g = ctx.PAIR.ate2(Q, R, sQ, P);
            g = ctx.PAIR.fexp(g);

            if (!g.isunity()) {
                if (HID != null && xID != null && E != null && F != null) {
                    g.toBytes(E);

                    if (date !== 0) {
                        P = ctx.ECP.fromBytes(HID);
                        if (P.is_infinity()) {
                            return this.INVALID_POINT;
                        }

                        R = ctx.ECP.fromBytes(xID);
                        if (R.is_infinity()) {
                            return this.INVALID_POINT;
                        }

                        P = ctx.PAIR.G1mul(P, y);
                        P.add(R);
                        P.affine();
                    }
                    g = ctx.PAIR.ate(Q, P);
                    g = ctx.PAIR.fexp(g);

                    g.toBytes(F);
                }

                return this.BAD_PIN;
            }

            return 0;
        },

        /* Pollards kangaroos used to return PIN error */
        KANGAROO: function(E, F) {
            var ge = ctx.FP12.fromBytes(E),
                gf = ctx.FP12.fromBytes(F),
                distance = [],
                t = new ctx.FP12(gf),
                table = [],
                i, j, m, s, dn, dm, res, steps;

            s = 1;
            for (m = 0; m < this.TS; m++) {
                distance[m] = s;
                table[m] = new ctx.FP12(t);
                s *= 2;
                t.usqr();
            }
            t.one();
            dn = 0;
            for (j = 0; j < this.TRAP; j++) {
                i = t.geta().geta().getA().lastbits(20) % this.TS;
                t.mul(table[i]);
                dn += distance[i];
            }
            gf.copy(t);
            gf.conj();
            steps = 0;
            dm = 0;
            res = 0;
            while (dm - dn < this.MAXPIN) {
                steps++;
                if (steps > 4 * this.TRAP) {
                    break;
                }
                i = ge.geta().geta().getA().lastbits(20) % this.TS;
                ge.mul(table[i]);
                dm += distance[i];
                if (ge.equals(t)) {
                    res = dm - dn;
                    break;
                }
                if (ge.equals(gf)) {
                    res = dn - dm;
                    break;
                }

            }
            if (steps > 4 * this.TRAP || dm - dn >= this.MAXPIN) {
                res = 0;
            } // Trap Failed  - probable invalid token

            return res;
        },

        /* return time  since epoch */
        GET_TIME: function() {
            var now = new Date();
            return Math.floor(now.getTime() / (1000));
        },

        /* y = H(time,xCID) */
        GET_Y: function(sha, TimeValue, xCID, Y) {
            var q = new ctx.BIG(0),
                h = this.hashit(sha, TimeValue, xCID),
                y = ctx.BIG.fromBytes(h);

            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            y.mod(q);
            y.toBytes(Y);

            return 0;
        },

        /* One pass MPIN Client - DVS signature. Message must be null in case of One pass MPIN. */
        CLIENT: function(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT, TimeValue, Y, Message) {
            var rtn = 0,
                M = [],
                pID, i;

            if (date == 0) {
                pID = xID;
            } else {
                pID = xCID;
                xID = null;
            }

            rtn = this.CLIENT_1(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT);
            if (rtn != 0) {
                return rtn;
            }

            M = pID.slice();

            if (typeof Message !== "undefined" || Message != null) {
                for (i = 0; i < Message.length; i++) {
                    M.push(Message[i]);
                }
            }

            this.GET_Y(sha, TimeValue, M, Y);

            rtn = this.CLIENT_2(X, Y, SEC);
            if (rtn != 0) {
                return rtn;
            }

            return 0;
        },

        /* One pass MPIN Server */
        SERVER: function(sha, date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, CID, TimeValue, Message, Pa) {
            var rtn = 0,
                M = [],
                pID, i;

            if (date == 0) {
                pID = xID;
            } else {
                pID = xCID;
            }

            this.SERVER_1(sha, date, CID, HID, HTID);

            M = pID.slice();

            if (typeof Message !== "undefined" || Message != null) {
                for (i = 0; i < Message.length; i++) {
                    M.push(Message[i]);
                }
            }

            this.GET_Y(sha, TimeValue, M, Y);

            rtn = this.SERVER_2(date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, Pa);
            if (rtn != 0) {
                return rtn;
            }

            return 0;
        },

        /* Functions to support M-Pin Full */
        PRECOMPUTE: function(TOKEN, CID, G1, G2) {
            var P, T, g, Q;

            T = ctx.ECP.fromBytes(TOKEN);
            if (T.is_infinity()) {
                return this.INVALID_POINT;
            }

            P = ctx.ECP.mapit(CID);
            Q = ctx.ECP2.generator();

            g = ctx.PAIR.ate(Q, T);
            g = ctx.PAIR.fexp(g);
            g.toBytes(G1);

            g = ctx.PAIR.ate(Q, P);
            g = ctx.PAIR.fexp(g);
            g.toBytes(G2);

            return 0;
        },

        /* Hash the M-Pin transcript - new */

        HASH_ALL: function(sha, HID, xID, xCID, SEC, Y, R, W) {
            var tlen = 0,
                T = [],
                i;

            for (i = 0; i < HID.length; i++) {
                T[i] = HID[i];
            }
            tlen += HID.length;

            if (xCID != null) {
                for (i = 0; i < xCID.length; i++) {
                    T[i + tlen] = xCID[i];
                }
                tlen += xCID.length;
            } else {
                for (i = 0; i < xID.length; i++) {
                    T[i + tlen] = xID[i];
                }
                tlen += xID.length;
            }

            for (i = 0; i < SEC.length; i++) {
                T[i + tlen] = SEC[i];
            }
            tlen += SEC.length;

            for (i = 0; i < Y.length; i++) {
                T[i + tlen] = Y[i];
            }
            tlen += Y.length;

            for (i = 0; i < R.length; i++) {
                T[i + tlen] = R[i];
            }
            tlen += R.length;

            for (i = 0; i < W.length; i++) {
                T[i + tlen] = W[i];
            }
            tlen += W.length;

            return this.hashit(sha, 0, T);
        },

        /* calculate common key on client side */
        /* wCID = w.(A+AT) */
        CLIENT_KEY: function(sha, G1, G2, pin, R, X, H, wCID, CK) {
            var t = [],
                g1 = ctx.FP12.fromBytes(G1),
                g2 = ctx.FP12.fromBytes(G2),
                z = ctx.BIG.fromBytes(R),
                x = ctx.BIG.fromBytes(X),
                h = ctx.BIG.fromBytes(H),
                W = ctx.ECP.fromBytes(wCID),
                r, c, i;

            if (W.is_infinity()) {
                return this.INVALID_POINT;
            }

            W = ctx.PAIR.G1mul(W, x);

            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            z.add(h);
            z.mod(r);

            g2.pinpow(pin, this.PBLEN);
            g1.mul(g2);

            c = g1.compow(z, r);

            t = this.mpin_hash(sha, c, W);

            for (i = 0; i < ctx.ECP.AESKEY; i++) {
                CK[i] = t[i];
            }

            return 0;
        },

        /* calculate common key on server side */
        /* Z=r.A - no time permits involved */

        SERVER_KEY: function(sha, Z, SST, W, H, HID, xID, xCID, SK) {
            var t = [],
                sQ, R, A, U, w, h, g, c, i;

            sQ = ctx.ECP2.fromBytes(SST);
            if (sQ.is_infinity()) {
                return this.INVALID_POINT;
            }

            R = ctx.ECP.fromBytes(Z);
            if (R.is_infinity()) {
                return this.INVALID_POINT;
            }

            A = ctx.ECP.fromBytes(HID);
            if (A.is_infinity()) {
                return this.INVALID_POINT;
            }

            if (xCID != null) {
                U = ctx.ECP.fromBytes(xCID);
            } else {
                U = ctx.ECP.fromBytes(xID);
            }

            if (U.is_infinity()) {
                return this.INVALID_POINT;
            }

            w = ctx.BIG.fromBytes(W);
            h = ctx.BIG.fromBytes(H);
            A = ctx.PAIR.G1mul(A, h);
            R.add(A);
            R.affine();

            U = ctx.PAIR.G1mul(U, w);
            g = ctx.PAIR.ate(sQ, R);
            g = ctx.PAIR.fexp(g);

            c = g.trace();

            t = this.mpin_hash(sha, c, U);

            for (i = 0; i < ctx.ECP.AESKEY; i++) {
                SK[i] = t[i];
            }

            return 0;
        },

        /* Generate a public key and the corresponding z for the key-escrow less scheme */
        /*
            if R==NULL then Z is passed in
            if R!=NULL then Z is passed out
            Pa=(z^-1).Q
        */
        GET_DVS_KEYPAIR: function(rng, Z, Pa) {
            var r = new ctx.BIG(0),
                z, Q;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (rng != null) {
                z = ctx.BIG.randomnum(r, rng);
                z.toBytes(Z);
            } else {
                z = ctx.BIG.fromBytes(Z);
            }
            z.invmodp(r);

            Q = ctx.ECP2.generator();

            Q = ctx.PAIR.G2mul(Q, z);
            Q.toBytes(Pa);

            return 0;
        }
    };

    return MPIN;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* MPIN API Functions */

function MPIN192(ctx) {

    var MPIN192 = {
        BAD_PARAMS: -11,
        INVALID_POINT: -14,
        WRONG_ORDER: -18,
        BAD_PIN: -19,
        /* configure PIN here */
        MAXPIN: 10000,
        /* max PIN */
        PBLEN: 14,
        /* MAXPIN length in bits */
        TS: 12,
        /* 10 for 4 digit PIN, 14 for 6-digit PIN - 2^TS/TS approx = sqrt(MAXPIN) */
        TRAP: 2000,
        /* 200 for 4 digit PIN, 2000 for 6-digit PIN  - approx 2*sqrt(MAXPIN) */
        EFS: ctx.BIG.MODBYTES,
        EGS: ctx.BIG.MODBYTES,

        SHA256: 32,
        SHA384: 48,
        SHA512: 64,

        /* return time in slots since epoch */
        today: function() {
            var now = new Date();
            return Math.floor(now.getTime() / (60000 * 1440)); // for daily tokens
        },

        bytestostring: function(b) {
            var s = "",
                len = b.length,
                ch, i;

            for (i = 0; i < len; i++) {
                ch = b[i];
                s += ((ch >>> 4) & 15).toString(16);
                s += (ch & 15).toString(16);

            }

            return s;
        },

        stringtobytes: function(s) {
            var b = [],
                i;

            for (i = 0; i < s.length; i++) {
                b.push(s.charCodeAt(i));
            }

            return b;
        },

        comparebytes: function(a, b) {
            if (a.length != b.length) {
                return false;
            }

            for (var i = 0; i < a.length; i++) {
                if (a[i] != b[i]) {
                    return false;
                }
            }

            return true;
        },

        mpin_hash: function(sha, c, U) {
            var t = [],
                w = [],
                h = [],
                H, R, i;

            c.geta().geta().getA().toBytes(w);
            for (i = 0; i < this.EFS; i++) {
                t[i] = w[i];
            }
            c.geta().geta().getB().toBytes(w);
            for (i = this.EFS; i < 2 * this.EFS; i++) {
                t[i] = w[i - this.EFS];
            }
            c.geta().getb().getA().toBytes(w);
            for (i = 2 * this.EFS; i < 3 * this.EFS; i++) {
                t[i] = w[i - 2 * this.EFS];
            }
            c.geta().getb().getB().toBytes(w);
            for (i = 3 * this.EFS; i < 4 * this.EFS; i++) {
                t[i] = w[i - 3 * this.EFS];
            }

            c.getb().geta().getA().toBytes(w);
            for (i = 4 * this.EFS; i < 5 * this.EFS; i++) {
                t[i] = w[i - 4 * this.EFS];
            }
            c.getb().geta().getB().toBytes(w);
            for (i = 5 * this.EFS; i < 6 * this.EFS; i++) {
                t[i] = w[i - 5 * this.EFS];
            }
            c.getb().getb().getA().toBytes(w);
            for (i = 6 * this.EFS; i < 7 * this.EFS; i++) {
                t[i] = w[i - 6 * this.EFS];
            }
            c.getb().getb().getB().toBytes(w);
            for (i = 7 * this.EFS; i < 8 * this.EFS; i++) {
                t[i] = w[i - 7 * this.EFS];
            }

            U.getX().toBytes(w);
            for (i = 8 * this.EFS; i < 9 * this.EFS; i++) {
                t[i] = w[i - 8 * this.EFS];
            }
            U.getY().toBytes(w);
            for (i = 9 * this.EFS; i < 10 * this.EFS; i++) {
                t[i] = w[i - 9 * this.EFS];
            }

            if (sha == this.SHA256) {
                H = new ctx.HASH256();
            } else if (sha == this.SHA384) {
                H = new ctx.HASH384();
            } else if (sha == this.SHA512) {
                H = new ctx.HASH512();
            }

            H.process_array(t);
            h = H.hash();

            if (h.length == 0) {
                return null;
            }

            R = [];
            for (i = 0; i < ctx.ECP.AESKEY; i++) {
                R[i] = h[i];
            }

            return R;
        },

        /* Hash number (optional) and string to point on curve */
        hashit: function(sha, n, B) {
            var R = [],
                H, W, i, len;

            if (sha == this.SHA256) {
                H = new ctx.HASH256();
            } else if (sha == this.SHA384) {
                H = new ctx.HASH384();
            } else if (sha == this.SHA512) {
                H = new ctx.HASH512();
            }

            if (n > 0) {
                H.process_num(n);
            }
            H.process_array(B);
            R = H.hash();

            if (R.length == 0) {
                return null;
            }

            W = [];

            len = ctx.BIG.MODBYTES;

            if (sha >= len) {
                for (i = 0; i < len; i++) {
                    W[i] = R[i];
                }
            } else {
                for (i = 0; i < sha; i++) {
                    W[i + len - sha] = R[i];
                }

                for (i = 0; i < len - sha; i++) {
                    W[i] = 0;
                }
            }

            return W;
        },

        /* these next two functions help to implement elligator squared - http://eprint.iacr.org/2014/043 */
        /* maps a random u to a point on the curve */
        map: function(u, cb) {
            var P = new ctx.ECP(),
                x = new ctx.BIG(u),
                p = new ctx.BIG(0);

            p.rcopy(ctx.ROM_FIELD.Modulus);
            x.mod(p);

            for (;;) {
                P.setxi(x, cb);
                if (!P.is_infinity()) {
                    break;
                }
                x.inc(1);
                x.norm();
            }

            return P;
        },

        /* returns u derived from P. Random value in range 1 to return value should then be added to u */
        unmap: function(u, P) {
            var s = P.getS(),
                R = new ctx.ECP(),
                r = 0,
                x = P.getX();

            u.copy(x);

            for (;;) {
                u.dec(1);
                u.norm();
                r++;
                R.setxi(u, s);
                if (!R.is_infinity()) {
                    break;
                }
            }

            return r;
        },

        /* these next two functions implement elligator squared - http://eprint.iacr.org/2014/043 */
        /* Elliptic curve point E in format (0x04,x,y} is converted to form {0x0-,u,v} */
        /* Note that u and v are indistinguishable from random strings */
        ENCODING: function(rng, E) {
            var T = [],
                i, rn, m, su, sv,
                u, v, P, p, W;

            for (i = 0; i < this.EFS; i++) {
                T[i] = E[i + 1];
            }
            u = ctx.BIG.fromBytes(T);
            for (i = 0; i < this.EFS; i++) {
                T[i] = E[i + this.EFS + 1];
            }
            v = ctx.BIG.fromBytes(T);

            P = new ctx.ECP(0);
            P.setxy(u, v);
            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            p = new ctx.BIG(0);
            p.rcopy(ctx.ROM_FIELD.Modulus);
            u = ctx.BIG.randomnum(p, rng);

            su = rng.getByte();
            if (su < 0) {
                su = -su;
            }
            su %= 2;

            W = this.map(u, su);
            P.sub(W);
            sv = P.getS();
            rn = this.unmap(v, P);
            m = rng.getByte();
            if (m < 0) {
                m = -m;
            }
            m %= rn;
            v.inc(m + 1);
            E[0] = (su + 2 * sv);
            u.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                E[i + 1] = T[i];
            }
            v.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                E[i + this.EFS + 1] = T[i];
            }

            return 0;
        },

        DECODING: function(D) {
            var T = [],
                i, su, sv, u, v, W, P;

            if ((D[0] & 0x04) !== 0) {
                return this.INVALID_POINT;
            }

            for (i = 0; i < this.EFS; i++) {
                T[i] = D[i + 1];
            }
            u = ctx.BIG.fromBytes(T);
            for (i = 0; i < this.EFS; i++) {
                T[i] = D[i + this.EFS + 1];
            }
            v = ctx.BIG.fromBytes(T);

            su = D[0] & 1;
            sv = (D[0] >> 1) & 1;
            W = this.map(u, su);
            P = this.map(v, sv);
            P.add(W);
            u = P.getX();
            v = P.getY();
            D[0] = 0x04;
            u.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                D[i + 1] = T[i];
            }
            v.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                D[i + this.EFS + 1] = T[i];
            }

            return 0;
        },

        /* R=R1+R2 in group G1 */
        RECOMBINE_G1: function(R1, R2, R) {
            var P = ctx.ECP.fromBytes(R1),
                Q = ctx.ECP.fromBytes(R2);

            if (P.is_infinity() || Q.is_infinity()) {
                return this.INVALID_POINT;
            }

            P.add(Q);

            P.toBytes(R,false);

            return 0;
        },

        /* W=W1+W2 in group G2 */
        RECOMBINE_G2: function(W1, W2, W) {
            var P = ctx.ECP4.fromBytes(W1),
                Q = ctx.ECP4.fromBytes(W2);

            if (P.is_infinity() || Q.is_infinity()) {
                return this.INVALID_POINT;
            }

            P.add(Q);

            P.toBytes(W);

            return 0;
        },

        HASH_ID: function(sha, ID) {
            return this.hashit(sha, 0, ID);
        },

        /* create random secret S */
        RANDOM_GENERATE: function(rng, S) {
            var r = new ctx.BIG(0),
                s;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            s = ctx.BIG.randomnum(r, rng);
            s.toBytes(S);

            return 0;
        },

        /* Extract PIN from TOKEN for identity CID */
        EXTRACT_PIN: function(sha, CID, pin, TOKEN) {
            return this.EXTRACT_FACTOR(sha,CID,pin%this.MAXPIN,this.PBLEN,TOKEN);
        },

        /* Extract factor from TOKEN for identity CID */
        EXTRACT_FACTOR: function(sha, CID, factor, facbits, TOKEN) {
            var P, R, h;

            P = ctx.ECP.fromBytes(TOKEN);

            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            h = this.hashit(sha, 0, CID);
            R = ctx.ECP.mapit(h);

            R = R.pinmul(factor, facbits);
            P.sub(R);

            P.toBytes(TOKEN,false);

            return 0;
        },

        /* Restore factor to TOKEN for identity CID */
        RESTORE_FACTOR: function(sha, CID, factor, facbits, TOKEN) {
            var P, R, h;

            P = ctx.ECP.fromBytes(TOKEN);

            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            h = this.hashit(sha, 0, CID),
            R = ctx.ECP.mapit(h);

            R = R.pinmul(factor, facbits);
            P.add(R);

            P.toBytes(TOKEN,false);

            return 0;
        },

        /* Extract Server Secret SST=S*Q where Q is fixed generator in G2 and S is master secret */
        GET_SERVER_SECRET: function(S, SST) {
            var s,Q;

            Q = ctx.ECP4.generator();

            s = ctx.BIG.fromBytes(S);
            Q = ctx.PAIR192.G2mul(Q, s);
            Q.toBytes(SST);

            return 0;
        },

        /*
         W=x*H(G);
         if RNG == NULL then X is passed in
         if RNG != NULL the X is passed out
         if type=0 W=x*G where G is point on the curve, else W=x*M(G), where M(G) is mapping of octet G to point on the curve
        */
        GET_G1_MULTIPLE: function(rng, type, X, G, W) {
            var r = new ctx.BIG(0),
                x, P;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (rng != null) {
                x = ctx.BIG.randomnum(r, rng);
                x.toBytes(X);
            } else {
                x = ctx.BIG.fromBytes(X);
            }

            if (type == 0) {
                P = ctx.ECP.fromBytes(G);
                if (P.is_infinity()) {
                    return this.INVALID_POINT;
                }
            } else {
                P = ctx.ECP.mapit(G);
            }

            ctx.PAIR192.G1mul(P, x).toBytes(W,false);

            return 0;
        },


        /* Client secret CST=S*H(CID) where CID is client ID and S is master secret */
        GET_CLIENT_SECRET: function(S, CID, CST) {
            return this.GET_G1_MULTIPLE(null, 1, S, CID, CST);
        },

        /* Time Permit CTT=S*(date|H(CID)) where S is master secret */
        GET_CLIENT_PERMIT: function(sha, date, S, CID, CTT) {
            var h = this.hashit(sha, date, CID),
                P = ctx.ECP.mapit(h),
                s = ctx.BIG.fromBytes(S);

            P = ctx.PAIR192.G1mul(P, s);
            P.toBytes(CTT,false);

            return 0;
        },

        /* Implement step 1 on client side of MPin protocol */
        CLIENT_1: function(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT) {
            var r = new ctx.BIG(0),
                x, P, T, W, h;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            //  var q=new ctx.BIG(0); q.rcopy(ctx.ROM_FIELD.Modulus);
            if (rng !== null) {
                x = ctx.BIG.randomnum(r, rng);
                x.toBytes(X);
            } else {
                x = ctx.BIG.fromBytes(X);
            }

            h = this.hashit(sha, 0, CLIENT_ID);
            P = ctx.ECP.mapit(h);
            T = ctx.ECP.fromBytes(TOKEN);
            if (T.is_infinity()) {
                return this.INVALID_POINT;
            }

            pin %= this.MAXPIN;
            W = P.pinmul(pin, this.PBLEN);
            T.add(W);

            if (date != 0) {
                W = ctx.ECP.fromBytes(PERMIT);

                if (W.is_infinity()) {
                    return this.INVALID_POINT;
                }

                T.add(W);
                h = this.hashit(sha, date, h);
                W = ctx.ECP.mapit(h);

                if (xID != null) {
                    P = ctx.PAIR192.G1mul(P, x);
                    P.toBytes(xID,false);
                    W = ctx.PAIR192.G1mul(W, x);
                    P.add(W);
                } else {
                    P.add(W);
                    P = ctx.PAIR192.G1mul(P, x);
                }

                if (xCID != null) {
                    P.toBytes(xCID,false);
                }
            } else {
                if (xID != null) {
                    P = ctx.PAIR192.G1mul(P, x);
                    P.toBytes(xID,false);
                }
            }

            T.toBytes(SEC,false);

            return 0;
        },

        /* Implement step 2 on client side of MPin protocol */
        CLIENT_2: function(X, Y, SEC) {
            var r = new ctx.BIG(0),
                P, px, py;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            P = ctx.ECP.fromBytes(SEC);
            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            px = ctx.BIG.fromBytes(X);
            py = ctx.BIG.fromBytes(Y);
            px.add(py);
            px.mod(r);

            P = ctx.PAIR192.G1mul(P, px);
            P.neg();
            P.toBytes(SEC,false);

            return 0;
        },

        /* Outputs H(CID) and H(T|H(CID)) for time permits. If no time permits set HID=HTID */
        SERVER_1: function(sha, date, CID, HID, HTID) {
            var h = this.hashit(sha, 0, CID),
                P = ctx.ECP.mapit(h),
                R;

            P.toBytes(HID,false);
            if (date !== 0) {
                h = this.hashit(sha, date, h);
                R = ctx.ECP.mapit(h);
                P.add(R);
                P.toBytes(HTID,false);
            }
        },

        /* Implement step 1 of MPin protocol on server side. Pa is the client public key in case of DVS, otherwise must be set to null */
        SERVER_2: function(date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, Pa) {
            var Q, sQ, R, y, P, g;

            if (typeof Pa === "undefined" || Pa == null) {
                Q = ctx.ECP4.generator();

            } else {
                Q = ctx.ECP4.fromBytes(Pa);
                if (Q.is_infinity()) {
                    return this.INVALID_POINT;
                }
            }

            sQ = ctx.ECP4.fromBytes(SST);
            if (sQ.is_infinity()) {
                return this.INVALID_POINT;
            }

            if (date !== 0) {
                R = ctx.ECP.fromBytes(xCID);
            } else {
                if (xID == null) {
                    return this.BAD_PARAMS;
                }
                R = ctx.ECP.fromBytes(xID);
            }

            if (R.is_infinity()) {
                return this.INVALID_POINT;
            }

            y = ctx.BIG.fromBytes(Y);

            if (date != 0) {
                P = ctx.ECP.fromBytes(HTID);
            } else {
                if (HID == null) {
                    return this.BAD_PARAMS;
                }
                P = ctx.ECP.fromBytes(HID);
            }

            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            P = ctx.PAIR192.G1mul(P, y);
            P.add(R);
            P.affine();
            R = ctx.ECP.fromBytes(mSEC);
            if (R.is_infinity()) {
                return this.INVALID_POINT;
            }

            g = ctx.PAIR192.ate2(Q, R, sQ, P);
            g = ctx.PAIR192.fexp(g);

            if (!g.isunity()) {
                if (HID != null && xID != null && E != null && F != null) {
                    g.toBytes(E);

                    if (date !== 0) {
                        P = ctx.ECP.fromBytes(HID);
                        if (P.is_infinity()) {
                            return this.INVALID_POINT;
                        }

                        R = ctx.ECP.fromBytes(xID);
                        if (R.is_infinity()) {
                            return this.INVALID_POINT;
                        }

                        P = ctx.PAIR192.G1mul(P, y);
                        P.add(R);
                        P.affine();
                    }
                    g = ctx.PAIR192.ate(Q, P);
                    g = ctx.PAIR192.fexp(g);

                    g.toBytes(F);
                }

                return this.BAD_PIN;
            }

            return 0;
        },

        /* Pollards kangaroos used to return PIN error */
        KANGAROO: function(E, F) {
            var ge = ctx.FP24.fromBytes(E),
                gf = ctx.FP24.fromBytes(F),
                distance = [],
                t = new ctx.FP24(gf),
                table = [],
                i, j, m, s, dn, dm, res, steps;

            s = 1;
            for (m = 0; m < this.TS; m++) {
                distance[m] = s;
                table[m] = new ctx.FP24(t);
                s *= 2;
                t.usqr();
            }
            t.one();
            dn = 0;
            for (j = 0; j < this.TRAP; j++) {
                i = t.geta().geta().geta().getA().lastbits(20) % this.TS;
                t.mul(table[i]);
                dn += distance[i];
            }
            gf.copy(t);
            gf.conj();
            steps = 0;
            dm = 0;
            res = 0;
            while (dm - dn < this.MAXPIN) {
                steps++;
                if (steps > 4 * this.TRAP) {
                    break;
                }
                i = ge.geta().geta().geta().getA().lastbits(20) % this.TS;
                ge.mul(table[i]);
                dm += distance[i];
                if (ge.equals(t)) {
                    res = dm - dn;
                    break;
                }
                if (ge.equals(gf)) {
                    res = dn - dm;
                    break;
                }

            }
            if (steps > 4 * this.TRAP || dm - dn >= this.MAXPIN) {
                res = 0;
            } // Trap Failed  - probable invalid token

            return res;
        },

        /* return time  since epoch */
        GET_TIME: function() {
            var now = new Date();
            return Math.floor(now.getTime() / (1000));
        },

        /* y = H(time,xCID) */
        GET_Y: function(sha, TimeValue, xCID, Y) {
            var q = new ctx.BIG(0),
                h = this.hashit(sha, TimeValue, xCID),
                y = ctx.BIG.fromBytes(h);

            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            y.mod(q);
            y.toBytes(Y);

            return 0;
        },

        /* One pass MPIN Client - DVS signature. Message must be null in case of One pass MPIN. */
        CLIENT: function(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT, TimeValue, Y, Message) {
            var rtn = 0,
                M = [],
                pID, i;

            if (date == 0) {
                pID = xID;
            } else {
                pID = xCID;
                xID = null;
            }

            rtn = this.CLIENT_1(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT);
            if (rtn != 0) {
                return rtn;
            }

            M = pID.slice();

            if (typeof Message !== "undefined" || Message != null) {
                for (i = 0; i < Message.length; i++) {
                    M.push(Message[i]);
                }
            }

            this.GET_Y(sha, TimeValue, M, Y);

            rtn = this.CLIENT_2(X, Y, SEC);
            if (rtn != 0) {
                return rtn;
            }

            return 0;
        },

        /* One pass MPIN Server */
        SERVER: function(sha, date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, CID, TimeValue, Message, Pa) {
            var rtn = 0,
                M = [],
                pID, i;

            if (date == 0) {
                pID = xID;
            } else {
                pID = xCID;
            }

            this.SERVER_1(sha, date, CID, HID, HTID);

            M = pID.slice();

            if (typeof Message !== "undefined" || Message != null) {
                for (i = 0; i < Message.length; i++) {
                    M.push(Message[i]);
                }
            }

            this.GET_Y(sha, TimeValue, M, Y);

            rtn = this.SERVER_2(date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, Pa);
            if (rtn != 0) {
                return rtn;
            }

            return 0;
        },

        /* Functions to support M-Pin Full */
        PRECOMPUTE: function(TOKEN, CID, G1, G2) {
            var P, T, g, Q;

            T = ctx.ECP.fromBytes(TOKEN);
            if (T.is_infinity()) {
                return this.INVALID_POINT;
            }

            P = ctx.ECP.mapit(CID);
            Q = ctx.ECP4.generator();

            g = ctx.PAIR192.ate(Q, T);
            g = ctx.PAIR192.fexp(g);
            g.toBytes(G1);

            g = ctx.PAIR192.ate(Q, P);
            g = ctx.PAIR192.fexp(g);
            g.toBytes(G2);

            return 0;
        },

        /* Hash the M-Pin transcript - new */

        HASH_ALL: function(sha, HID, xID, xCID, SEC, Y, R, W) {
            var tlen = 0,
                T = [],
                i;

            for (i = 0; i < HID.length; i++) {
                T[i] = HID[i];
            }
            tlen += HID.length;

            if (xCID != null) {
                for (i = 0; i < xCID.length; i++) {
                    T[i + tlen] = xCID[i];
                }
                tlen += xCID.length;
            } else {
                for (i = 0; i < xID.length; i++) {
                    T[i + tlen] = xID[i];
                }
                tlen += xID.length;
            }

            for (i = 0; i < SEC.length; i++) {
                T[i + tlen] = SEC[i];
            }
            tlen += SEC.length;

            for (i = 0; i < Y.length; i++) {
                T[i + tlen] = Y[i];
            }
            tlen += Y.length;

            for (i = 0; i < R.length; i++) {
                T[i + tlen] = R[i];
            }
            tlen += R.length;

            for (i = 0; i < W.length; i++) {
                T[i + tlen] = W[i];
            }
            tlen += W.length;

            return this.hashit(sha, 0, T);
        },

        /* calculate common key on client side */
        /* wCID = w.(A+AT) */
        CLIENT_KEY: function(sha, G1, G2, pin, R, X, H, wCID, CK) {
            var t = [],
                g1 = ctx.FP24.fromBytes(G1),
                g2 = ctx.FP24.fromBytes(G2),
                z = ctx.BIG.fromBytes(R),
                x = ctx.BIG.fromBytes(X),
                h = ctx.BIG.fromBytes(H),
                W = ctx.ECP.fromBytes(wCID),
                r, c, i;

            if (W.is_infinity()) {
                return this.INVALID_POINT;
            }

            W = ctx.PAIR192.G1mul(W, x);

            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            z.add(h);
            z.mod(r);

            g2.pinpow(pin, this.PBLEN);
            g1.mul(g2);

            c = g1.compow(z, r);

            t = this.mpin_hash(sha, c, W);

            for (i = 0; i < ctx.ECP.AESKEY; i++) {
                CK[i] = t[i];
            }

            return 0;
        },

        /* calculate common key on server side */
        /* Z=r.A - no time permits involved */

        SERVER_KEY: function(sha, Z, SST, W, H, HID, xID, xCID, SK) {
            var t = [],
                sQ, R, A, U, w, h, g, c, i;

            sQ = ctx.ECP4.fromBytes(SST);
            if (sQ.is_infinity()) {
                return this.INVALID_POINT;
            }

            R = ctx.ECP.fromBytes(Z);
            if (R.is_infinity()) {
                return this.INVALID_POINT;
            }

            A = ctx.ECP.fromBytes(HID);
            if (A.is_infinity()) {
                return this.INVALID_POINT;
            }

            if (xCID != null) {
                U = ctx.ECP.fromBytes(xCID);
            } else {
                U = ctx.ECP.fromBytes(xID);
            }

            if (U.is_infinity()) {
                return this.INVALID_POINT;
            }

            w = ctx.BIG.fromBytes(W);
            h = ctx.BIG.fromBytes(H);
            A = ctx.PAIR192.G1mul(A, h);
            R.add(A);
            R.affine();

            U = ctx.PAIR192.G1mul(U, w);
            g = ctx.PAIR192.ate(sQ, R);
            g = ctx.PAIR192.fexp(g);

            c = g.trace();

            t = this.mpin_hash(sha, c, U);

            for (i = 0; i < ctx.ECP.AESKEY; i++) {
                SK[i] = t[i];
            }

            return 0;
        },

        GET_DVS_KEYPAIR: function(rng, Z, Pa) {
            var r = new ctx.BIG(0),
                z, Q;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (rng != null) {
                z = ctx.BIG.randomnum(r, rng);
                z.toBytes(Z);
            } else {
                z = ctx.BIG.fromBytes(Z);
            }
            z.invmodp(r);

            Q = ctx.ECP4.generator();

            Q = ctx.PAIR192.G2mul(Q, z);
            Q.toBytes(Pa);

            return 0;
        }
    };

    return MPIN192;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* MPIN API Functions */

function MPIN256(ctx) {

    var MPIN256 = {
        BAD_PARAMS: -11,
        INVALID_POINT: -14,
        WRONG_ORDER: -18,
        BAD_PIN: -19,
        /* configure PIN here */
        MAXPIN: 10000,
        /* max PIN */
        PBLEN: 14,
        /* MAXPIN length in bits */
        TS: 12,
        /* 10 for 4 digit PIN, 14 for 6-digit PIN - 2^TS/TS approx = sqrt(MAXPIN) */
        TRAP: 2000,
        /* 200 for 4 digit PIN, 2000 for 6-digit PIN  - approx 2*sqrt(MAXPIN) */
        EFS: ctx.BIG.MODBYTES,
        EGS: ctx.BIG.MODBYTES,

        SHA256: 32,
        SHA384: 48,
        SHA512: 64,

        /* return time in slots since epoch */
        today: function() {
            var now = new Date();
            return Math.floor(now.getTime() / (60000 * 1440)); // for daily tokens
        },

        bytestostring: function(b) {
            var s = "",
                len = b.length,
                ch, i;

            for (i = 0; i < len; i++) {
                ch = b[i];
                s += ((ch >>> 4) & 15).toString(16);
                s += (ch & 15).toString(16);

            }

            return s;
        },

        stringtobytes: function(s) {
            var b = [],
                i;

            for (i = 0; i < s.length; i++) {
                b.push(s.charCodeAt(i));
            }

            return b;
        },

        comparebytes: function(a, b) {
            if (a.length != b.length) {
                return false;
            }

            for (var i = 0; i < a.length; i++) {
                if (a[i] != b[i]) {
                    return false;
                }
            }

            return true;
        },

        mpin_hash: function(sha, c, U) {
            var t = [],
                w = [],
                h = [],
                H, R, i;

            c.geta().geta().geta().getA().toBytes(w);
            for (i = 0; i < this.EFS; i++) {
                t[i] = w[i];
            }
            c.geta().geta().geta().getB().toBytes(w);
            for (i = this.EFS; i < 2 * this.EFS; i++) {
                t[i] = w[i - this.EFS];
            }
            c.geta().geta().getb().getA().toBytes(w);
            for (i = 2 * this.EFS; i < 3 * this.EFS; i++) {
                t[i] = w[i - 2 * this.EFS];
            }
            c.geta().geta().getb().getB().toBytes(w);
            for (i = 3 * this.EFS; i < 4 * this.EFS; i++) {
                t[i] = w[i - 3 * this.EFS];
            }

            c.geta().getb().geta().getA().toBytes(w);
            for (i = 4 * this.EFS; i < 5 * this.EFS; i++) {
                t[i] = w[i - 4 * this.EFS];
            }
            c.geta().getb().geta().getB().toBytes(w);
            for (i = 5 * this.EFS; i < 6 * this.EFS; i++) {
                t[i] = w[i - 5 * this.EFS];
            }
            c.geta().getb().getb().getA().toBytes(w);
            for (i = 6 * this.EFS; i < 7 * this.EFS; i++) {
                t[i] = w[i - 6 * this.EFS];
            }
            c.geta().getb().getb().getB().toBytes(w);
            for (i = 7 * this.EFS; i < 8 * this.EFS; i++) {
                t[i] = w[i - 7 * this.EFS];
            }

            c.getb().geta().geta().getA().toBytes(w);
            for (i = 8 * this.EFS; i < 9 * this.EFS; i++) {
                t[i] = w[i - 8 * this.EFS];
            }
            c.getb().geta().geta().getB().toBytes(w);
            for (i = 9 *this.EFS; i < 10 * this.EFS; i++) {
                t[i] = w[i - 9 * this.EFS];
            }
            c.getb().geta().getb().getA().toBytes(w);
            for (i = 10 * this.EFS; i < 11 * this.EFS; i++) {
                t[i] = w[i - 10 * this.EFS];
            }
            c.getb().geta().getb().getB().toBytes(w);
            for (i = 11 * this.EFS; i < 12 * this.EFS; i++) {
                t[i] = w[i - 11 * this.EFS];
            }

            c.getb().getb().geta().getA().toBytes(w);
            for (i = 12 * this.EFS; i < 13 * this.EFS; i++) {
                t[i] = w[i - 12 * this.EFS];
            }
            c.getb().getb().geta().getB().toBytes(w);
            for (i = 13 * this.EFS; i < 14 * this.EFS; i++) {
                t[i] = w[i - 13 * this.EFS];
            }
            c.getb().getb().getb().getA().toBytes(w);
            for (i = 14 * this.EFS; i < 15 * this.EFS; i++) {
                t[i] = w[i - 14 * this.EFS];
            }
            c.getb().getb().getb().getB().toBytes(w);
            for (i = 15 * this.EFS; i < 16 * this.EFS; i++) {
                t[i] = w[i - 15 * this.EFS];
            }


            U.getX().toBytes(w);
            for (i = 16 * this.EFS; i < 17 * this.EFS; i++) {
                t[i] = w[i - 16 * this.EFS];
            }
            U.getY().toBytes(w);
            for (i = 17 * this.EFS; i < 18 * this.EFS; i++) {
                t[i] = w[i - 17 * this.EFS];
            }

            if (sha == this.SHA256) {
                H = new ctx.HASH256();
            } else if (sha == this.SHA384) {
                H = new ctx.HASH384();
            } else if (sha == this.SHA512) {
                H = new ctx.HASH512();
            }

            H.process_array(t);
            h = H.hash();

            if (h.length == 0) {
                return null;
            }

            R = [];
            for (i = 0; i < ctx.ECP.AESKEY; i++) {
                R[i] = h[i];
            }

            return R;
        },

        /* Hash number (optional) and string to point on curve */
        hashit: function(sha, n, B) {
            var R = [],
                H, W, i, len;

            if (sha == this.SHA256) {
                H = new ctx.HASH256();
            } else if (sha == this.SHA384) {
                H = new ctx.HASH384();
            } else if (sha == this.SHA512) {
                H = new ctx.HASH512();
            }

            if (n > 0) {
                H.process_num(n);
            }
            H.process_array(B);
            R = H.hash();

            if (R.length == 0) {
                return null;
            }

            W = [];

            len = ctx.BIG.MODBYTES;

            if (sha >= len) {
                for (i = 0; i < len; i++) {
                    W[i] = R[i];
                }
            } else {
                for (i = 0; i < sha; i++) {
                    W[i + len - sha] = R[i];
                }

                for (i = 0; i < len - sha; i++) {
                    W[i] = 0;
                }
            }

            return W;
        },

        /* these next two functions help to implement elligator squared - http://eprint.iacr.org/2014/043 */
        /* maps a random u to a point on the curve */
        map: function(u, cb) {
            var P = new ctx.ECP(),
                x = new ctx.BIG(u),
                p = new ctx.BIG(0);

            p.rcopy(ctx.ROM_FIELD.Modulus);
            x.mod(p);

            for (;;) {
                P.setxi(x, cb);
                if (!P.is_infinity()) {
                    break;
                }
                x.inc(1);
                x.norm();
            }

            return P;
        },

        /* returns u derived from P. Random value in range 1 to return value should then be added to u */
        unmap: function(u, P) {
            var s = P.getS(),
                R = new ctx.ECP(),
                r = 0,
                x = P.getX();

            u.copy(x);

            for (;;) {
                u.dec(1);
                u.norm();
                r++;
                R.setxi(u, s); //=new ECP(u,s);
                if (!R.is_infinity()) {
                    break;
                }
            }

            return r;
        },

        /* these next two functions implement elligator squared - http://eprint.iacr.org/2014/043 */
        /* Elliptic curve point E in format (0x04,x,y} is converted to form {0x0-,u,v} */
        /* Note that u and v are indistinguishable from random strings */
        ENCODING: function(rng, E) {
            var T = [],
                i, rn, m, su, sv,
                u, v, P, p, W;

            for (i = 0; i < this.EFS; i++) {
                T[i] = E[i + 1];
            }
            u = ctx.BIG.fromBytes(T);
            for (i = 0; i < this.EFS; i++) {
                T[i] = E[i + this.EFS + 1];
            }
            v = ctx.BIG.fromBytes(T);

            P = new ctx.ECP(0);
            P.setxy(u, v);
            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            p = new ctx.BIG(0);
            p.rcopy(ctx.ROM_FIELD.Modulus);
            u = ctx.BIG.randomnum(p, rng);

            su = rng.getByte();
            if (su < 0) {
                su = -su;
            }
            su %= 2;

            W = this.map(u, su);
            P.sub(W);
            sv = P.getS();
            rn = this.unmap(v, P);
            m = rng.getByte();
            if (m < 0) {
                m = -m;
            }
            m %= rn;
            v.inc(m + 1);
            E[0] = (su + 2 * sv);
            u.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                E[i + 1] = T[i];
            }
            v.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                E[i + this.EFS + 1] = T[i];
            }

            return 0;
        },

        DECODING: function(D) {
            var T = [],
                i, su, sv, u, v, W, P;

            if ((D[0] & 0x04) !== 0) {
                return this.INVALID_POINT;
            }

            for (i = 0; i < this.EFS; i++) {
                T[i] = D[i + 1];
            }
            u = ctx.BIG.fromBytes(T);
            for (i = 0; i < this.EFS; i++) {
                T[i] = D[i + this.EFS + 1];
            }
            v = ctx.BIG.fromBytes(T);

            su = D[0] & 1;
            sv = (D[0] >> 1) & 1;
            W = this.map(u, su);
            P = this.map(v, sv);
            P.add(W);
            u = P.getX();
            v = P.getY();
            D[0] = 0x04;
            u.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                D[i + 1] = T[i];
            }
            v.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                D[i + this.EFS + 1] = T[i];
            }

            return 0;
        },

        /* R=R1+R2 in group G1 */
        RECOMBINE_G1: function(R1, R2, R) {
            var P = ctx.ECP.fromBytes(R1),
                Q = ctx.ECP.fromBytes(R2);

            if (P.is_infinity() || Q.is_infinity()) {
                return this.INVALID_POINT;
            }

            P.add(Q);

            P.toBytes(R,false);

            return 0;
        },

        /* W=W1+W2 in group G2 */
        RECOMBINE_G2: function(W1, W2, W) {
            var P = ctx.ECP8.fromBytes(W1),
                Q = ctx.ECP8.fromBytes(W2);

            if (P.is_infinity() || Q.is_infinity()) {
                return this.INVALID_POINT;
            }

            P.add(Q);

            P.toBytes(W);

            return 0;
        },

        HASH_ID: function(sha, ID) {
            return this.hashit(sha, 0, ID);
        },

        /* create random secret S */
        RANDOM_GENERATE: function(rng, S) {
            var r = new ctx.BIG(0),
                s;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            s = ctx.BIG.randomnum(r, rng);
            s.toBytes(S);

            return 0;
        },

        /* Extract PIN from TOKEN for identity CID */
        EXTRACT_PIN: function(sha, CID, pin, TOKEN) {
            return this.EXTRACT_FACTOR(sha,CID,pin%this.MAXPIN,this.PBLEN,TOKEN);
        },

        /* Extract factor from TOKEN for identity CID */
        EXTRACT_FACTOR: function(sha, CID, factor, facbits, TOKEN) {
            var P, R, h;

            P = ctx.ECP.fromBytes(TOKEN);

            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            h = this.hashit(sha, 0, CID);
            R = ctx.ECP.mapit(h);

            R = R.pinmul(factor, facbits);
            P.sub(R);

            P.toBytes(TOKEN,false);

            return 0;
        },

        /* Restore factor to TOKEN for identity CID */
        RESTORE_FACTOR: function(sha, CID, factor, facbits, TOKEN) {
            var P, R, h;

            P = ctx.ECP.fromBytes(TOKEN);

            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            h = this.hashit(sha, 0, CID),
            R = ctx.ECP.mapit(h);

            R = R.pinmul(factor, facbits);
            P.add(R);

            P.toBytes(TOKEN,false);

            return 0;
        },

        /* Extract Server Secret SST=S*Q where Q is fixed generator in G2 and S is master secret */
        GET_SERVER_SECRET: function(S, SST) {
            var s,Q;

            Q = ctx.ECP8.generator();

            s = ctx.BIG.fromBytes(S);
            Q = ctx.PAIR256.G2mul(Q, s);
            Q.toBytes(SST);

            return 0;
        },

        /*
         * W=x*H(G);
         * if RNG == NULL then X is passed in
         * if RNG != NULL the X is passed out
         * if type=0 W=x*G where G is point on the curve, else W=x*M(G), where M(G) is mapping of octet G to point on the curve
        */
        GET_G1_MULTIPLE: function(rng, type, X, G, W) {
            var r = new ctx.BIG(0),
                x, P;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (rng != null) {
                x = ctx.BIG.randomnum(r, rng);
                x.toBytes(X);
            } else {
                x = ctx.BIG.fromBytes(X);
            }

            if (type == 0) {
                P = ctx.ECP.fromBytes(G);
                if (P.is_infinity()) {
                    return this.INVALID_POINT;
                }
            } else {
                P = ctx.ECP.mapit(G);
            }

            ctx.PAIR256.G1mul(P, x).toBytes(W,false);

            return 0;
        },


        /* Client secret CST=S*H(CID) where CID is client ID and S is master secret */
        GET_CLIENT_SECRET: function(S, CID, CST) {
            return this.GET_G1_MULTIPLE(null, 1, S, CID, CST);
        },

        /* Time Permit CTT=S*(date|H(CID)) where S is master secret */
        GET_CLIENT_PERMIT: function(sha, date, S, CID, CTT) {
            var h = this.hashit(sha, date, CID),
                P = ctx.ECP.mapit(h),
                s = ctx.BIG.fromBytes(S);

            P = ctx.PAIR256.G1mul(P, s);
            P.toBytes(CTT,false);

            return 0;
        },

        /* Implement step 1 on client side of MPin protocol */
        CLIENT_1: function(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT) {
            var r = new ctx.BIG(0),
                x, P, T, W, h;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            //  var q=new ctx.BIG(0); q.rcopy(ctx.ROM_FIELD.Modulus);
            if (rng !== null) {
                x = ctx.BIG.randomnum(r, rng);
                x.toBytes(X);
            } else {
                x = ctx.BIG.fromBytes(X);
            }

            h = this.hashit(sha, 0, CLIENT_ID);
            P = ctx.ECP.mapit(h);
            T = ctx.ECP.fromBytes(TOKEN);
            if (T.is_infinity()) {
                return this.INVALID_POINT;
            }

            pin %= this.MAXPIN;
            W = P.pinmul(pin, this.PBLEN);
            T.add(W);

            if (date != 0) {
                W = ctx.ECP.fromBytes(PERMIT);

                if (W.is_infinity()) {
                    return this.INVALID_POINT;
                }

                T.add(W);
                h = this.hashit(sha, date, h);
                W = ctx.ECP.mapit(h);

                if (xID != null) {
                    P = ctx.PAIR256.G1mul(P, x);
                    P.toBytes(xID,false);
                    W = ctx.PAIR256.G1mul(W, x);
                    P.add(W);
                } else {
                    P.add(W);
                    P = ctx.PAIR256.G1mul(P, x);
                }

                if (xCID != null) {
                    P.toBytes(xCID,false);
                }
            } else {
                if (xID != null) {
                    P = ctx.PAIR256.G1mul(P, x);
                    P.toBytes(xID,false);
                }
            }

            T.toBytes(SEC,false);

            return 0;
        },

        /* Implement step 2 on client side of MPin protocol */
        CLIENT_2: function(X, Y, SEC) {
            var r = new ctx.BIG(0),
                P, px, py;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            P = ctx.ECP.fromBytes(SEC);
            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            px = ctx.BIG.fromBytes(X);
            py = ctx.BIG.fromBytes(Y);
            px.add(py);
            px.mod(r);

            P = ctx.PAIR256.G1mul(P, px);
            P.neg();
            P.toBytes(SEC,false);

            return 0;
        },

        /* Outputs H(CID) and H(T|H(CID)) for time permits. If no time permits set HID=HTID */
        SERVER_1: function(sha, date, CID, HID, HTID) {
            var h = this.hashit(sha, 0, CID),
                P = ctx.ECP.mapit(h),
                R;

            P.toBytes(HID,false);
            if (date !== 0) {
                h = this.hashit(sha, date, h);
                R = ctx.ECP.mapit(h);
                P.add(R);
                P.toBytes(HTID,false);
            }
        },

        /* Implement step 1 of MPin protocol on server side. Pa is the client public key in case of DVS, otherwise must be set to null */
        SERVER_2: function(date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, Pa) {
            var Q, sQ, R, y, P, g;

            if (typeof Pa === "undefined" || Pa == null) {
                Q = ctx.ECP8.generator();

            } else {
                Q = ctx.ECP8.fromBytes(Pa);
                if (Q.is_infinity()) {
                    return this.INVALID_POINT;
                }
            }

            sQ = ctx.ECP8.fromBytes(SST);
            if (sQ.is_infinity()) {
                return this.INVALID_POINT;
            }

            if (date !== 0) {
                R = ctx.ECP.fromBytes(xCID);
            } else {
                if (xID == null) {
                    return this.BAD_PARAMS;
                }
                R = ctx.ECP.fromBytes(xID);
            }

            if (R.is_infinity()) {
                return this.INVALID_POINT;
            }

            y = ctx.BIG.fromBytes(Y);

            if (date != 0) {
                P = ctx.ECP.fromBytes(HTID);
            } else {
                if (HID == null) {
                    return this.BAD_PARAMS;
                }
                P = ctx.ECP.fromBytes(HID);
            }

            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            P = ctx.PAIR256.G1mul(P, y);
            P.add(R);
            P.affine();
            R = ctx.ECP.fromBytes(mSEC);
            if (R.is_infinity()) {
                return this.INVALID_POINT;
            }

            g = ctx.PAIR256.ate2(Q, R, sQ, P);
            g = ctx.PAIR256.fexp(g);

            if (!g.isunity()) {
                if (HID != null && xID != null && E != null && F != null) {
                    g.toBytes(E);

                    if (date !== 0) {
                        P = ctx.ECP.fromBytes(HID);
                        if (P.is_infinity()) {
                            return this.INVALID_POINT;
                        }

                        R = ctx.ECP.fromBytes(xID);
                        if (R.is_infinity()) {
                            return this.INVALID_POINT;
                        }

                        P = ctx.PAIR256.G1mul(P, y);
                        P.add(R);
                        P.affine();
                    }
                    g = ctx.PAIR256.ate(Q, P);
                    g = ctx.PAIR256.fexp(g);

                    g.toBytes(F);
                }

                return this.BAD_PIN;
            }

            return 0;
        },

        /* Pollards kangaroos used to return PIN error */
        KANGAROO: function(E, F) {
            var ge = ctx.FP48.fromBytes(E),
                gf = ctx.FP48.fromBytes(F),
                distance = [],
                t = new ctx.FP48(gf),
                table = [],
                i, j, m, s, dn, dm, res, steps;

            s = 1;
            for (m = 0; m < this.TS; m++) {
                distance[m] = s;
                table[m] = new ctx.FP48(t);
                s *= 2;
                t.usqr();
            }
            t.one();
            dn = 0;
            for (j = 0; j < this.TRAP; j++) {
                i = t.geta().geta().geta().geta().getA().lastbits(20) % this.TS;
                t.mul(table[i]);
                dn += distance[i];
            }
            gf.copy(t);
            gf.conj();
            steps = 0;
            dm = 0;
            res = 0;
            while (dm - dn < this.MAXPIN) {
                steps++;
                if (steps > 4 * this.TRAP) {
                    break;
                }
                i = ge.geta().geta().geta().geta().getA().lastbits(20) % this.TS;
                ge.mul(table[i]);
                dm += distance[i];
                if (ge.equals(t)) {
                    res = dm - dn;
                    break;
                }
                if (ge.equals(gf)) {
                    res = dn - dm;
                    break;
                }

            }
            if (steps > 4 * this.TRAP || dm - dn >= this.MAXPIN) {
                res = 0;
            } // Trap Failed  - probable invalid token

            return res;
        },

        /* return time  since epoch */
        GET_TIME: function() {
            var now = new Date();
            return Math.floor(now.getTime() / (1000));
        },

        /* y = H(time,xCID) */
        GET_Y: function(sha, TimeValue, xCID, Y) {
            var q = new ctx.BIG(0),
                h = this.hashit(sha, TimeValue, xCID),
                y = ctx.BIG.fromBytes(h);

            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            y.mod(q);
            y.toBytes(Y);

            return 0;
        },

        /* One pass MPIN Client - DVS signature. Message must be null in case of One pass MPIN. */
        CLIENT: function(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT, TimeValue, Y, Message) {
            var rtn = 0,
                M = [],
                pID, i;

            if (date == 0) {
                pID = xID;
            } else {
                pID = xCID;
                xID = null;
            }

            rtn = this.CLIENT_1(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT);
            if (rtn != 0) {
                return rtn;
            }

            M = pID.slice();

            if (typeof Message !== "undefined" || Message != null) {
                for (i = 0; i < Message.length; i++) {
                    M.push(Message[i]);
                }
            }

            this.GET_Y(sha, TimeValue, M, Y);

            rtn = this.CLIENT_2(X, Y, SEC);
            if (rtn != 0) {
                return rtn;
            }

            return 0;
        },

        /* One pass MPIN Server */
        SERVER: function(sha, date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, CID, TimeValue, Message, Pa) {
            var rtn = 0,
                M = [],
                pID, i;

            if (date == 0) {
                pID = xID;
            } else {
                pID = xCID;
            }

            this.SERVER_1(sha, date, CID, HID, HTID);

            M = pID.slice();

            if (typeof Message !== "undefined" || Message != null) {
                for (i = 0; i < Message.length; i++) {
                    M.push(Message[i]);
                }
            }

            this.GET_Y(sha, TimeValue, M, Y);

            rtn = this.SERVER_2(date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, Pa);
            if (rtn != 0) {
                return rtn;
            }

            return 0;
        },

        /* Functions to support M-Pin Full */
        PRECOMPUTE: function(TOKEN, CID, G1, G2) {
            var P, T, g, Q;

            T = ctx.ECP.fromBytes(TOKEN);
            if (T.is_infinity()) {
                return this.INVALID_POINT;
            }

            P = ctx.ECP.mapit(CID);
            Q = ctx.ECP8.generator();

            g = ctx.PAIR256.ate(Q, T);
            g = ctx.PAIR256.fexp(g);
            g.toBytes(G1);

            g = ctx.PAIR256.ate(Q, P);
            g = ctx.PAIR256.fexp(g);
            g.toBytes(G2);

            return 0;
        },

        /* Hash the M-Pin transcript - new */

        HASH_ALL: function(sha, HID, xID, xCID, SEC, Y, R, W) {
            var tlen = 0,
                T = [],
                i;

            for (i = 0; i < HID.length; i++) {
                T[i] = HID[i];
            }
            tlen += HID.length;

            if (xCID != null) {
                for (i = 0; i < xCID.length; i++) {
                    T[i + tlen] = xCID[i];
                }
                tlen += xCID.length;
            } else {
                for (i = 0; i < xID.length; i++) {
                    T[i + tlen] = xID[i];
                }
                tlen += xID.length;
            }

            for (i = 0; i < SEC.length; i++) {
                T[i + tlen] = SEC[i];
            }
            tlen += SEC.length;

            for (i = 0; i < Y.length; i++) {
                T[i + tlen] = Y[i];
            }
            tlen += Y.length;

            for (i = 0; i < R.length; i++) {
                T[i + tlen] = R[i];
            }
            tlen += R.length;

            for (i = 0; i < W.length; i++) {
                T[i + tlen] = W[i];
            }
            tlen += W.length;

            return this.hashit(sha, 0, T);
        },

        /* calculate common key on client side */
        /* wCID = w.(A+AT) */
        CLIENT_KEY: function(sha, G1, G2, pin, R, X, H, wCID, CK) {
            var t = [],
                g1 = ctx.FP48.fromBytes(G1),
                g2 = ctx.FP48.fromBytes(G2),
                z = ctx.BIG.fromBytes(R),
                x = ctx.BIG.fromBytes(X),
                h = ctx.BIG.fromBytes(H),
                W = ctx.ECP.fromBytes(wCID),
                r, c, i;

            if (W.is_infinity()) {
                return this.INVALID_POINT;
            }

            W = ctx.PAIR256.G1mul(W, x);

            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            z.add(h);
            z.mod(r);

            g2.pinpow(pin, this.PBLEN);
            g1.mul(g2);

            c = g1.compow(z, r);

            t = this.mpin_hash(sha, c, W);

            for (i = 0; i < ctx.ECP.AESKEY; i++) {
                CK[i] = t[i];
            }

            return 0;
        },

        /* calculate common key on server side */
        /* Z=r.A - no time permits involved */

        SERVER_KEY: function(sha, Z, SST, W, H, HID, xID, xCID, SK) {
            var t = [],
                sQ, R, A, U, w, h, g, c, i;

            sQ = ctx.ECP8.fromBytes(SST);
            if (sQ.is_infinity()) {
                return this.INVALID_POINT;
            }

            R = ctx.ECP.fromBytes(Z);
            if (R.is_infinity()) {
                return this.INVALID_POINT;
            }

            A = ctx.ECP.fromBytes(HID);
            if (A.is_infinity()) {
                return this.INVALID_POINT;
            }

            if (xCID != null) {
                U = ctx.ECP.fromBytes(xCID);
            } else {
                U = ctx.ECP.fromBytes(xID);
            }

            if (U.is_infinity()) {
                return this.INVALID_POINT;
            }

            w = ctx.BIG.fromBytes(W);
            h = ctx.BIG.fromBytes(H);
            A = ctx.PAIR256.G1mul(A, h);
            R.add(A);
            R.affine();

            U = ctx.PAIR256.G1mul(U, w);
            g = ctx.PAIR256.ate(sQ, R);
            g = ctx.PAIR256.fexp(g);

            c = g.trace();

            t = this.mpin_hash(sha, c, U);

            for (i = 0; i < ctx.ECP.AESKEY; i++) {
                SK[i] = t[i];
            }

            return 0;
        },

        GET_DVS_KEYPAIR: function(rng, Z, Pa) {
            var r = new ctx.BIG(0),
                z, Q;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (rng != null) {
                z = ctx.BIG.randomnum(r, rng);
                z.toBytes(Z);
            } else {
                z = ctx.BIG.fromBytes(Z);
            }
            z.invmodp(r);

            Q = ctx.ECP8.generator();

            Q = ctx.PAIR256.G2mul(Q, z);
            Q.toBytes(Pa);

            return 0;
        }
    };

    return MPIN256;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* NewHope API high-level functions  */

function NHS(ctx) {

    var NHS = {

        round: function(a, b) {
            return Math.floor((a + (b >> 1)) / b);
        },

        /* constant time absolute value */
        nabs: function(x) {
            var mask = (x >> 31);
            return (x + mask) ^ mask;
        },

        /* Montgomery stuff */

        redc: function(T) {
            var m = ((T & 0x3ffffff) * NHS.ND) & 0x3ffffff;
            return ((m * NHS.PRIME + T) * NHS.MODINV);
        },

        nres: function(x) {
            return NHS.redc(x * NHS.R2MODP);
        },

        modmul: function(a, b) {
            return NHS.redc(a * b);
        },

        /* NTT code */
        /* Cooley-Tukey NTT */

        ntt: function(x) {
            var t = NHS.DEGREE / 2,
                q = NHS.PRIME,
                m, i, j, k,
                S, U, V;

            /* Convert to Montgomery form */
            for (j = 0; j < NHS.DEGREE; j++) {
                x[j] = NHS.nres(x[j]);
            }

            m = 1;
            while (m < NHS.DEGREE) {
                k = 0;

                for (i = 0; i < m; i++) {
                    S = NHS.roots[m + i];

                    for (j = k; j < k + t; j++) {
                        U = x[j];
                        V = NHS.modmul(x[j + t], S);
                        x[j] = U + V;
                        x[j + t] = U + 2 * q - V;
                    }

                    k += 2 * t;
                }

                t /= 2;
                m *= 2;
            }
        },

        /* Gentleman-Sande INTT */
        intt: function(x) {
            var q = NHS.PRIME,
                t = 1,
                m, i, j, k,
                S, U, V, W;

            m = NHS.DEGREE / 2;
            while (m > 1) {
                k = 0;

                for (i = 0; i < m; i++) {
                    S = NHS.iroots[m + i];

                    for (j = k; j < k + t; j++) {
                        U = x[j];
                        V = x[j + t];
                        x[j] = U + V;
                        W = U + NHS.DEGREE * q - V;
                        x[j + t] = NHS.modmul(W, S);
                    }

                    k += 2 * t;
                }

                t *= 2;
                m /= 2;
            }
            /* Last iteration merged with n^-1 */

            t = NHS.DEGREE / 2;
            for (j = 0; j < t; j++) {
                U = x[j];
                V = x[j + t];
                W = U + NHS.DEGREE * q - V;
                x[j + t] = NHS.modmul(W, NHS.invpr);
                x[j] = NHS.modmul(U + V, NHS.inv);
            }

            /* convert back from Montgomery to "normal" form */
            for (j = 0; j < NHS.DEGREE; j++) {
                x[j] = NHS.redc(x[j]);
                x[j] -= q;
                x[j] += (x[j] >> (NHS.WL - 1)) & q;
            }
        },

        /* See https://eprint.iacr.org/2016/1157.pdf */

        Encode: function(key, poly) {
            var i, j, b, k, kj, q2;

            q2 = NHS.PRIME / 2;
            for (i = j = 0; i < 256;) {
                kj = key[j++];

                for (k = 0; k < 8; k++) {
                    b = kj & 1;
                    poly[i] = b * q2;
                    poly[i + 256] = b * q2;
                    poly[i + 512] = b * q2;
                    poly[i + 768] = b * q2;
                    kj >>= 1;
                    i++;
                }
            }
        },

        Decode: function(poly, key) {
            var q2 = NHS.PRIME / 2,
                i, j, k, b, t;

            for (i = 0; i < 32; i++) {
                key[i] = 0;
            }

            for (i = j = 0; i < 256;) {
                for (k = 0; k < 8; k++) {
                    t = NHS.nabs(poly[i] - q2) + NHS.nabs(poly[i + 256] - q2) + NHS.nabs(poly[i + 512] - q2) + NHS.nabs(poly[i + 768] - q2);

                    b = t - NHS.PRIME;
                    b = (b >> 31) & 1;
                    key[j] = (((key[j] & 0xff) >> 1) + (b << 7));
                    i++;
                }

                j++;
            }
        },

        /* convert 32-byte seed to random polynomial */

        Parse: function(seed, poly) {
            var sh = new ctx.SHA3(ctx.SHA3.SHAKE128),
                hash = [],
                i, j, n;

            for (i = 0; i < 32; i++) {
                sh.process(seed[i]);
            }
            sh.shake(hash, 4 * NHS.DEGREE);

            for (i = j = 0; i < NHS.DEGREE; i++) {
                n = hash[j] & 0x7f;
                n <<= 8;
                n += hash[j + 1] & 0xff;
                n <<= 8;
                n += hash[j + 2] & 0xff;
                n <<= 8;
                n += hash[j + 3] & 0xff;
                j += 4;
                poly[i]=NHS.nres(n);
            }
        },

        /* Compress 14 bits polynomial coefficients into byte array */
        /* 7 bytes is 3x14 */
        pack: function(poly, array) {
            var i, j, a, b, c, d;

            for (i = j = 0; i < NHS.DEGREE;) {
                a = poly[i++];
                b = poly[i++];
                c = poly[i++];
                d = poly[i++];
                array[j++] = a & 0xff;
                array[j++] = ((a >> 8) | (b << 6)) & 0xff;
                array[j++] = (b >> 2) & 0xff;
                array[j++] = ((b >> 10) | (c << 4)) & 0xff;
                array[j++] = (c >> 4) & 0xff;
                array[j++] = ((c >> 12) | (d << 2)) & 0xff;
                array[j++] = (d >> 6);
            }
        },

        unpack: function(array, poly) {
            var i, j, a, b, c, d, e, f, g;

            for (i = j = 0; i < NHS.DEGREE;) {
                a = array[j++] & 0xff;
                b = array[j++] & 0xff;
                c = array[j++] & 0xff;
                d = array[j++] & 0xff;
                e = array[j++] & 0xff;
                f = array[j++] & 0xff;
                g = array[j++] & 0xff;
                poly[i++] = a | ((b & 0x3f) << 8);
                poly[i++] = (b >> 6) | (c << 2) | ((d & 0xf) << 10);
                poly[i++] = (d >> 4) | (e << 4) | ((f & 3) << 12);
                poly[i++] = (f >> 2) | (g << 6);
            }
        },


        /* See https://eprint.iacr.org/2016/1157.pdf */

        Compress: function(poly, array) {
            var col = 0,
                i, j, k, b;

            for (i = j = 0; i < NHS.DEGREE;) {
                for (k = 0; k < 8; k++) {
                    b = NHS.round((poly[i] * 8), NHS.PRIME) & 7;
                    col = (col << 3) + b;
                    i++;
                }

                array[j] = (col & 0xff);
                array[j + 1] = ((col >>> 8) & 0xff);
                array[j + 2] = ((col >>> 16) & 0xff);
                j += 3;
                col = 0;
            }
        },

        Decompress: function(array, poly) {
            var col = 0,
                i, j, k, b;

            for (i = j = 0; i < NHS.DEGREE;) {
                col = array[j + 2] & 0xff;
                col = (col << 8) + (array[j + 1] & 0xff);
                col = (col << 8) + (array[j] & 0xff);
                j += 3;

                for (k = 0; k < 8; k++) {
                    b = (col & 0xe00000) >>> 21;
                    col <<= 3;
                    poly[i] = NHS.round((b * NHS.PRIME), 8);
                    i++;
                }
            }
        },

        /* generate centered binomial distribution */

        Error: function(RNG, poly) {
            var n1, n2, r, i, j;

            for (i = 0; i < NHS.DEGREE; i++) {
                n1 = RNG.getByte() + (RNG.getByte() << 8);
                n2 = RNG.getByte() + (RNG.getByte() << 8);
                r = 0;

                for (j = 0; j < 16; j++) {
                    r += (n1 & 1) - (n2 & 1);
                    n1 >>= 1;
                    n2 >>= 1;
                }

                poly[i] = (r + NHS.PRIME);
            }
        },

        redc_it: function(p) {
            var i;
            for (i = 0; i < NHS.DEGREE; i++) {
                p[i] = NHS.redc(p[i]);
            }
        },

        nres_it: function(p) {
            var i;
            for (i = 0; i < NHS.DEGREE; i++) {
                p[i] = NHS.nres(p[i]);
            }
        },

        poly_mul: function(p1, p2, p3) {
            var i;

            for (i = 0; i < NHS.DEGREE; i++) {
                p1[i] = NHS.modmul(p2[i], p3[i]);
            }
        },

        poly_add: function(p1, p2, p3) {
            var i;

            for (i = 0; i < NHS.DEGREE; i++) {
                p1[i] = (p2[i] + p3[i]);
            }
        },

        poly_sub: function(p1, p2, p3) {
            var i;

            for (i = 0; i < NHS.DEGREE; i++) {
                p1[i] = (p2[i] + NHS.PRIME - p3[i]);
            }
        },

        /* reduces inputs < 2q */
        poly_soft_reduce: function(poly) {
            var i, e;

            for (i = 0; i < NHS.DEGREE; i++) {
                e = poly[i] - NHS.PRIME;
                poly[i] = e + ((e >> (NHS.WL - 1)) & NHS.PRIME);
            }
        },

        /* fully reduces modulo q */
        poly_hard_reduce: function(poly) {
            var i, e;

            for (i = 0; i < NHS.DEGREE; i++) {
                e = NHS.modmul(poly[i], NHS.ONE);
                e = e - NHS.PRIME;
                poly[i] = e + ((e >> (NHS.WL - 1)) & NHS.PRIME);
            }
        },

        bytestostring: function(b) {
            var s = "",
                len = b.length,
                ch, i;

            for (i = 0; i < len; i++) {
                ch = b[i];
                s += ((ch >>> 4) & 15).toString(16);
                s += (ch & 15).toString(16);
            }

            return s;
        },
        /* API files */

        SERVER_1: function(RNG, SB, S) {
            var seed = new Uint8Array(32),
                array = new Uint8Array(1792),
                s = new Int32Array(NHS.DEGREE),
                e = new Int32Array(NHS.DEGREE),
                b = new Int32Array(NHS.DEGREE),
                i;

            for (i = 0; i < 32; i++) {
                seed[i] = RNG.getByte();
            }

            NHS.Parse(seed, b);

            NHS.Error(RNG, e);
            NHS.Error(RNG, s);

            NHS.ntt(s);
            NHS.ntt(e);
            NHS.poly_mul(b, b, s);
            NHS.poly_add(b, b, e);
            NHS.poly_hard_reduce(b);

            NHS.redc_it(b);
            NHS.pack(b, array);

            for (i = 0; i < 32; i++) {
                SB[i] = seed[i];
            }

            for (i = 0; i < 1792; i++) {
                SB[i + 32] = array[i];
            }

            NHS.poly_hard_reduce(s);

            NHS.pack(s, array);

            for (i = 0; i < 1792; i++) {
                S[i] = array[i];
            }
        },

        CLIENT: function(RNG, SB, UC, KEY) {
            var sh = new ctx.SHA3(ctx.SHA3.HASH256),
                seed = new Uint8Array(32),
                array = new Uint8Array(1792),
                key = new Uint8Array(32),
                cc = new Uint8Array(384),
                sd = new Int32Array(NHS.DEGREE),
                ed = new Int32Array(NHS.DEGREE),
                u = new Int32Array(NHS.DEGREE),
                k = new Int32Array(NHS.DEGREE),
                c = new Int32Array(NHS.DEGREE),
                i;

            NHS.Error(RNG, sd);
            NHS.Error(RNG, ed);

            NHS.ntt(sd);
            NHS.ntt(ed);

            for (i = 0; i < 32; i++) {
                seed[i] = SB[i];
            }

            for (i = 0; i < 1792; i++) {
                array[i] = SB[i + 32];
            }

            NHS.Parse(seed, u);

            NHS.poly_mul(u, u, sd);
            NHS.poly_add(u, u, ed);
            NHS.poly_hard_reduce(u);

            for (i = 0; i < 32; i++) {
                key[i] = RNG.getByte();
            }

            for (i = 0; i < 32; i++) {
                sh.process(key[i]);
            }

            sh.hash(key);

            NHS.Encode(key, k);

            NHS.unpack(array, c);
            NHS.nres_it(c);

            NHS.poly_mul(c, c, sd);
            NHS.intt(c);
            NHS.Error(RNG, ed);
            NHS.poly_add(c, c, ed);
            NHS.poly_add(c, c, k);

            NHS.Compress(c, cc);

            sh.init(ctx.SHA3.HASH256);
            for (i = 0; i < 32; i++) {
                sh.process(key[i]);
            }
            sh.hash(key);

            for (i = 0; i < 32; i++) {
                KEY[i] = key[i];
            }

            NHS.redc_it(u);
            NHS.pack(u, array);

            for (i = 0; i < 1792; i++) {
                UC[i] = array[i];
            }

            for (i = 0; i < 384; i++) {
                UC[i + 1792] = cc[i];
            }
        },

        SERVER_2: function(S, UC, KEY) {
            var sh = new ctx.SHA3(ctx.SHA3.HASH256),
                c = new Int32Array(NHS.DEGREE),
                s = new Int32Array(NHS.DEGREE),
                k = new Int32Array(NHS.DEGREE),
                array = new Uint8Array(1792),
                key = new Uint8Array(32),
                cc = new Uint8Array(384),
                i;

            for (i = 0; i < 1792; i++) {
                array[i] = UC[i];
            }

            NHS.unpack(array, k);
            NHS.nres_it(k);

            for (i = 0; i < 384; i++) {
                cc[i] = UC[i + 1792];
            }

            NHS.Decompress(cc, c);

            for (i = 0; i < 1792; i++) {
                array[i] = S[i];
            }

            NHS.unpack(array, s);

            NHS.poly_mul(k, k, s);
            NHS.intt(k);
            NHS.poly_sub(k, c, k);
            NHS.poly_soft_reduce(k);

            NHS.Decode(k, key);

            for (i = 0; i < 32; i++) {
                sh.process(key[i]);
            }
            sh.hash(key);

            for (i = 0; i < 32; i++) {
                KEY[i] = key[i];
            }
        }

    };

    //q=12289
    NHS.PRIME = 0x3001; // q in Hex
    NHS.LGN = 10; // Degree n=2^LGN
    NHS.ND = 0x3002FFF; // 1/(R-q) mod R
    NHS.ONE = 0x2AAC; // R mod q
    NHS.R2MODP = 0x1DA2; // R^2 mod q

    NHS.MODINV = Math.pow(2, -26);

    NHS.DEGREE = 1024; // 1<< LGN
    NHS.WL = 26;

    NHS.inv = 0xffb;
    NHS.invpr = 0x1131;

    NHS.roots = [0x2aac, 0xd6f, 0x1c67, 0x2c5b, 0x2dbd, 0x2697, 0x29f6, 0x8d3, 0x1b7c, 0x9eb, 0x20eb, 0x264a, 0x27d0, 0x121b, 0x58c, 0x4d7, 0x17a2, 0x29eb, 0x1b72, 0x13b0, 0x19b1, 0x1581, 0x2ac9, 0x25e8, 0x249d, 0x2d5e, 0x363, 0x1f74, 0x1f8f, 0x20a4, 0x2cb2, 0x2d04, 0x1407, 0x2df9, 0x3ad, 0x23f7, 0x1a72, 0xa91, 0x37f, 0xdb3, 0x2315, 0x5e6, 0xa8f, 0x211d, 0xdad, 0x1f2b, 0x2e29, 0x26b0, 0x2009, 0x2fdd, 0x2881, 0x399, 0x586, 0x2781, 0x2ab5, 0x971, 0x234b, 0x1df3, 0x1d2a, 0x15dd, 0x1a6d, 0x2774, 0x7ff, 0x1ebe, 0x230, 0x1cf4, 0x180b, 0xb58, 0x198c, 0x2b40, 0x127b, 0x1d9d, 0x137f, 0xfa0, 0x144, 0x4b, 0x2fac, 0xb09, 0x1c7f, 0x1b5, 0xeec, 0xc58, 0x1248, 0x243c, 0x108a, 0x14b8, 0xe9, 0x2dfe, 0xfb, 0x2602, 0x2aec, 0x1bb7, 0x1098, 0x23d8, 0x783, 0x1b13, 0x2067, 0x20d6, 0x171c, 0x4, 0x662, 0x1097, 0x24b9, 0x1b9d, 0x27c4, 0x276e, 0x6bf, 0x757, 0x2e16, 0x472, 0x1d11, 0x1649, 0x2904, 0xed4, 0x6c5, 0x14ae, 0x2ef8, 0x2ae0, 0x2e7c, 0x2735, 0x1186, 0x4f2, 0x17bb, 0x297f, 0x1dc7, 0x1ae5, 0x2a43, 0x2c02, 0xed6, 0x2b70, 0x1c7b, 0x18d1, 0x20ae, 0x6ad, 0x2404, 0x113a, 0x209e, 0x31b, 0x159d, 0x48f, 0xe09, 0x1bb2, 0x14f7, 0x385, 0x1c4, 0x1cdb, 0x22d6, 0x21d8, 0xc, 0x1aae, 0x2ece, 0x2d81, 0xd56, 0x5c1, 0x12da, 0x8cf, 0x1605, 0x1bc4, 0x18b7, 0x19b9, 0x21be, 0x135e, 0x28d6, 0x2891, 0x2208, 0x17e1, 0x2971, 0x926, 0x211b, 0xff, 0x51f, 0xa85, 0xe1, 0x2c35, 0x2585, 0x121, 0xe27, 0x2e64, 0x29f8, 0x2d46, 0xcb2, 0x292a, 0x33d, 0xaf9, 0xb86, 0x2e3a, 0x2138, 0x1978, 0x2324, 0xf3f, 0x2d10, 0x1dfd, 0x13c3, 0x6cc, 0x1a79, 0x1221, 0x250f, 0xacd, 0xfff, 0x7b4, 0x650, 0x1893, 0xe85, 0x1f5d, 0x12dc, 0x2d42, 0xd8e, 0x1240, 0x1082, 0x12ef, 0x11b6, 0xfa8, 0xb0f, 0xdac, 0x191c, 0x1242, 0x1ea, 0x155, 0x270a, 0x9ed, 0x2e5b, 0x25d8, 0x222c, 0x7e9, 0x1fb3, 0x10ac, 0x2919, 0x2584, 0xbe3, 0x24fa, 0x23ed, 0x618, 0x2d80, 0x6fa, 0x140e, 0x588, 0x355, 0x1054, 0x26c4, 0x1e4f, 0x1681, 0x1f6f, 0x1c53, 0xfe4, 0xacb, 0x1680, 0x2fe8, 0x6c, 0x165a, 0x10bb, 0x2c39, 0x1804, 0x1196, 0x884, 0x2622, 0x629, 0x1ac1, 0x2232, 0x2f9b, 0xd3e, 0x20ff, 0x12c0, 0x27ec, 0x5a, 0x2a0, 0x5f1, 0x1cda, 0x403, 0x1ea8, 0x1719, 0x1fc7, 0x2d23, 0x5ea, 0x25d1, 0xb6, 0x49c, 0xac7, 0x2d9c, 0x204e, 0x2142, 0x11e8, 0xed0, 0x15f0, 0x514, 0xa3f, 0xf43, 0x1de5, 0x2d97, 0x1543, 0x2c7b, 0x241a, 0x2223, 0x2fb8, 0x25b7, 0x1b4c, 0x2f36, 0x26e2, 0x100, 0x2555, 0x266c, 0x2e10, 0x271c, 0x5aa, 0x1789, 0x2199, 0x291d, 0x1088, 0x2046, 0x1ea1, 0xf89, 0x1c7a, 0x1e98, 0x137, 0x1b65, 0x24ed, 0xf37, 0x2ec3, 0xd0c, 0x7c7, 0x123f, 0xb2e, 0x1a97, 0x1a03, 0x1bcd, 0x3b2, 0x714, 0x2979, 0xaef, 0x2b3c, 0x2d91, 0xe03, 0xe5b, 0x1fbc, 0xcae, 0x432, 0x23a4, 0xb1d, 0x1ccc, 0x1fb6, 0x2f58, 0x2a5a, 0x723, 0x2c99, 0x2d70, 0xa, 0x263c, 0x2701, 0xdeb, 0x2d08, 0x1c34, 0x200c, 0x1e88, 0x396, 0x18d5, 0x1c45, 0xc4, 0x18bc, 0x2cd7, 0x1744, 0x8f1, 0x1c5c, 0xbe6, 0x2a89, 0x17a0, 0x207, 0x19ce, 0x2024, 0x23e3, 0x299b, 0x685, 0x2baf, 0x539, 0x2d49, 0x24b5, 0x158d, 0xfd, 0x2a95, 0x24d, 0xab3, 0x1125, 0x12f9, 0x15ba, 0x6a8, 0x2c36, 0x6e7, 0x1044, 0x36e, 0xfe8, 0x112d, 0x2717, 0x24a0, 0x1c09, 0xe1d, 0x828, 0x2f7, 0x1f5b, 0xfab, 0xcf6, 0x1332, 0x1c72, 0x2683, 0x15ce, 0x1ad3, 0x1a36, 0x24c, 0xb33, 0x253f, 0x1583, 0x1d69, 0x29ec, 0xba7, 0x2f97, 0x16df, 0x1068, 0xaee, 0xc4f, 0x153c, 0x24eb, 0x20cd, 0x1398, 0x2366, 0x11f9, 0xe77, 0x103d, 0x260a, 0xce, 0xaea, 0x236b, 0x2b11, 0x5f8, 0xe4f, 0x750, 0x1569, 0x10f5, 0x284e, 0xa38, 0x2e06, 0xe0, 0xeaa, 0x99e, 0x249b, 0x8eb, 0x2b97, 0x2fdf, 0x29c1, 0x1b00, 0x2fe3, 0x1d4f, 0x83f, 0x2d06, 0x10e, 0x183f, 0x27ba, 0x132, 0xfbf, 0x296d, 0x154a, 0x40a, 0x2767, 0xad, 0xc09, 0x974, 0x2821, 0x1e2e, 0x28d2, 0xfac, 0x3c4, 0x2f19, 0xdd4, 0x2ddf, 0x1e43, 0x1e90, 0x2dc9, 0x1144, 0x28c3, 0x653, 0xf3c, 0x1e32, 0x2a4a, 0x391, 0x1123, 0xdb, 0x2da0, 0xe1e, 0x667, 0x23b5, 0x2039, 0xa92, 0x1552, 0x5d3, 0x169a, 0x1f03, 0x1342, 0x2004, 0x1b5d, 0x2d01, 0x2e9b, 0x41f, 0x2bc7, 0xa94, 0xd0, 0x2e6a, 0x2b38, 0x14ac, 0x2724, 0x3ba, 0x6bc, 0x18ac, 0x2da5, 0x213c, 0x2c5c, 0xdd3, 0xaae, 0x2e08, 0x6cd, 0x1677, 0x2025, 0x1e1c, 0x5b4, 0xdc4, 0x60, 0x156c, 0x2669, 0x1c01, 0x26ab, 0x1ebb, 0x26d4, 0x21e1, 0x156b, 0x567, 0x1a, 0x29ce, 0x23d4, 0x684, 0xb79, 0x1953, 0x1046, 0x1d8c, 0x17b5, 0x1c28, 0x1ce5, 0x2478, 0x18d8, 0x1b16, 0x2c2f, 0x21c9, 0x19bb, 0xbbc, 0x291b, 0x19f6, 0x1879, 0x2fe4, 0x58e, 0x294a, 0x19e8, 0x27c7, 0x2fba, 0x1a29, 0x2319, 0x1ecb, 0x203b, 0x2f05, 0x2b82, 0x192f, 0x26aa, 0x2482, 0xaed, 0x1216, 0x708, 0x11a1, 0xc22, 0x908, 0x28f8, 0x2427, 0x7f8, 0x172e, 0xf50, 0xaa8, 0x184a, 0x1f67, 0x22d1, 0xeba, 0x215b, 0xf47, 0x2877, 0xd5e, 0x8dc, 0x20d, 0x2dae, 0x1d3e, 0x775, 0xbf3, 0x872, 0x2667, 0x1ff6, 0xd9f, 0x13c4, 0x105, 0x65f, 0x21ec, 0x6dd, 0x1a09, 0xc6e, 0x1fd, 0x1426, 0xae3, 0x494, 0x2d82, 0x22cd, 0x25d6, 0x11c1, 0x1c, 0x2cae, 0x141f, 0x110a, 0x147, 0x2657, 0x23fd, 0x2f39, 0x360, 0x2294, 0x1f1e, 0xb73, 0xbfc, 0x2f17, 0x7ca, 0x2f63, 0xbf, 0x28c2, 0xc1a, 0x255e, 0x226e, 0x1aa8, 0x229e, 0x161a, 0x273, 0x106d, 0x2c40, 0x7cf, 0x1408, 0x7d8, 0x100a, 0x759, 0x1db4, 0x24be, 0x2ebb, 0xc17, 0x1894, 0x244e, 0x15bd, 0x748, 0x1fe9, 0x23d, 0x1da, 0x2be, 0x18a3, 0xc5c, 0x9f9, 0x3d5, 0x2ce4, 0x54, 0x2abf, 0x279c, 0x1e81, 0x2d59, 0x2847, 0x23f4, 0xda8, 0xa20, 0x258, 0x1cfe, 0x240c, 0x2c2e, 0x2790, 0x2dd5, 0x2bf2, 0x2e34, 0x1724, 0x211, 0x1009, 0x27b9, 0x6f9, 0x23d9, 0x19a2, 0x627, 0x156d, 0x169e, 0x7e7, 0x30f, 0x24b6, 0x5c2, 0x1ce4, 0x28dd, 0x20, 0x16ab, 0x1cce, 0x20a9, 0x2390, 0x2884, 0x2245, 0x5f7, 0xab7, 0x1b6a, 0x11e7, 0x2a53, 0x2f94, 0x294c, 0x1ee5, 0x1364, 0x1b9a, 0xff7, 0x5eb, 0x2c30, 0x1c02, 0x5a1, 0x1b87, 0x2402, 0x1cc8, 0x2ee1, 0x1fbe, 0x138c, 0x2487, 0x1bf8, 0xd96, 0x1d68, 0x2fb3, 0x1fc1, 0x1fcc, 0xd66, 0x953, 0x2141, 0x157a, 0x2477, 0x18e3, 0x2f30, 0x75e, 0x1de1, 0x14b2, 0x2faa, 0x1697, 0x2334, 0x12d1, 0xb76, 0x2aa8, 0x1e7a, 0xd5, 0x2c60, 0x26b8, 0x1753, 0x124a, 0x1f57, 0x1425, 0xd84, 0x1c05, 0x641, 0xf3a, 0x1b8c, 0xd7d, 0x2f52, 0x2f4, 0xc73, 0x151b, 0x1589, 0x1819, 0x1b18, 0xb9b, 0x1ae9, 0x2b1f, 0x2b44, 0x2f5a, 0x2d37, 0x2cb1, 0x26f5, 0x233e, 0x276f, 0x276, 0x1260, 0x2997, 0x9f2, 0x1c15, 0x1694, 0x11ac, 0x1e6d, 0x1bef, 0x2966, 0x18b2, 0x4fa, 0x2044, 0x1b70, 0x1f3e, 0x221e, 0x28ca, 0x1d56, 0x7ae, 0x98d, 0x238c, 0x17b8, 0xad3, 0x113f, 0x1f1b, 0x4d2, 0x1757, 0xcb1, 0x2ef1, 0x2e02, 0x17fc, 0x2f11, 0x2a74, 0x2029, 0x700, 0x154e, 0x1cef, 0x226a, 0x21bf, 0x27a6, 0x14bc, 0x2b2b, 0x2fc6, 0x13b6, 0x21e6, 0x1663, 0xcbd, 0x752, 0x1624, 0x881, 0x2fc0, 0x1276, 0xa7f, 0x274f, 0x2b53, 0x670, 0x1fb7, 0x1e41, 0x2a1e, 0x2612, 0x297, 0x19de, 0x18b, 0x249, 0x1c88, 0xe9e, 0x1ef1, 0x213, 0x47b, 0x1e20, 0x28c1, 0x1d5e, 0x977, 0x1dca, 0x990, 0x1df6, 0x2b62, 0x870, 0x1f4, 0x1829, 0x1e0a, 0x46, 0x1b9f, 0x2102, 0x16b, 0x1b32, 0x568, 0x2050, 0x15b4, 0x191a, 0x1dd0, 0x5df, 0x55c, 0x1d21, 0x19db, 0x12d9, 0xe96, 0x680, 0x2349, 0x9b9, 0x155d, 0xe31, 0x249f, 0x20f8, 0xb30, 0x337, 0x2da3, 0x11c3, 0x248f, 0x1cf9, 0x10ee, 0x6d8, 0x6eb, 0xa0d, 0x101b, 0x1ae4, 0x1801, 0x24cd, 0x813, 0x2e98, 0x1574, 0x50, 0x11da, 0x1802, 0xf56, 0x1839, 0x219c, 0x105b, 0x43b, 0x2c9, 0x917, 0x14c1, 0x1b79, 0xdab, 0x2ab9, 0x265c, 0x71a, 0x1d90, 0x89f, 0x2bc2, 0x2777, 0x1014, 0x1e64, 0x14b4, 0x692, 0xddb, 0x56e, 0x2190, 0x2d1b, 0x1016, 0x12d6, 0x1c81, 0x2628, 0x4a1, 0x1268, 0x2597, 0x2926, 0x7c5, 0x1dcd, 0x53f, 0x11a9, 0x1a41, 0x5a2, 0x1c65, 0x7e8, 0xd71, 0x29c8, 0x427, 0x32f, 0x5dc, 0x16b1, 0x2a1d, 0x1787, 0x2224, 0x620, 0x6a4, 0x1351, 0x1038, 0xe6c, 0x111b, 0x2f13, 0x441, 0x2cfd, 0x2f2f, 0xd25, 0x9b8, 0x1b24, 0x762, 0x19b6, 0x2611, 0x85e, 0xe37, 0x1f5, 0x503, 0x1c46, 0x23cc, 0x4bb, 0x243e, 0x122b, 0x28e2, 0x133e, 0x2db9, 0xdb2, 0x1a5c, 0x29a9, 0xca, 0x2113, 0x13d1, 0x15ec, 0x2079, 0x18da, 0x2d50, 0x2c45, 0xaa2, 0x135a, 0x800, 0x18f7, 0x17f3, 0x5fd, 0x1f5a, 0x2d0, 0x2cd1, 0x9ee, 0x218b, 0x19fd, 0x53b, 0x28c5, 0xe33, 0x1911, 0x26cc, 0x2018, 0x2f88, 0x1b01, 0x2637, 0x1cd9, 0x126b, 0x1a0b, 0x5b0, 0x24e0, 0xe82, 0xb1, 0x21f7, 0x1a16, 0x2f24, 0x1cb1, 0x1f7d, 0x28a0, 0x167e, 0xc3];
    NHS.iroots = [0x2aac, 0x2292, 0x3a6, 0x139a, 0x272e, 0x60b, 0x96a, 0x244, 0x2b2a, 0x2a75, 0x1de6, 0x831, 0x9b7, 0xf16, 0x2616, 0x1485, 0x2fd, 0x34f, 0xf5d, 0x1072, 0x108d, 0x2c9e, 0x2a3, 0xb64, 0xa19, 0x538, 0x1a80, 0x1650, 0x1c51, 0x148f, 0x616, 0x185f, 0x1143, 0x2802, 0x88d, 0x1594, 0x1a24, 0x12d7, 0x120e, 0xcb6, 0x2690, 0x54c, 0x880, 0x2a7b, 0x2c68, 0x780, 0x24, 0xff8, 0x951, 0x1d8, 0x10d6, 0x2254, 0xee4, 0x2572, 0x2a1b, 0xcec, 0x224e, 0x2c82, 0x2570, 0x158f, 0xc0a, 0x2c54, 0x208, 0x1bfa, 0x3ff, 0x5be, 0x151c, 0x123a, 0x682, 0x1846, 0x2b0f, 0x1e7b, 0x8cc, 0x185, 0x521, 0x109, 0x1b53, 0x293c, 0x212d, 0x6fd, 0x19b8, 0x12f0, 0x2b8f, 0x1eb, 0x28aa, 0x2942, 0x893, 0x83d, 0x1464, 0xb48, 0x1f6a, 0x299f, 0x2ffd, 0x18e5, 0xf2b, 0xf9a, 0x14ee, 0x287e, 0xc29, 0x1f69, 0x144a, 0x515, 0x9ff, 0x2f06, 0x203, 0x2f18, 0x1b49, 0x1f77, 0xbc5, 0x1db9, 0x23a9, 0x2115, 0x2e4c, 0x1382, 0x24f8, 0x55, 0x2fb6, 0x2ebd, 0x2061, 0x1c82, 0x1264, 0x1d86, 0x4c1, 0x1675, 0x24a9, 0x17f6, 0x130d, 0x2dd1, 0x29d8, 0x9df, 0x277d, 0x1e6b, 0x17fd, 0x3c8, 0x1f46, 0x19a7, 0x2f95, 0x19, 0x1981, 0x2536, 0x201d, 0x13ae, 0x1092, 0x1980, 0x11b2, 0x93d, 0x1fad, 0x2cac, 0x2a79, 0x1bf3, 0x2907, 0x281, 0x29e9, 0xc14, 0xb07, 0x241e, 0xa7d, 0x6e8, 0x1f55, 0x104e, 0x2818, 0xdd5, 0xa29, 0x1a6, 0x2614, 0x8f7, 0x2eac, 0x2e17, 0x1dbf, 0x16e5, 0x2255, 0x24f2, 0x2059, 0x1e4b, 0x1d12, 0x1f7f, 0x1dc1, 0x2273, 0x2bf, 0x1d25, 0x10a4, 0x217c, 0x176e, 0x29b1, 0x284d, 0x2002, 0x2534, 0xaf2, 0x1de0, 0x1588, 0x2935, 0x1c3e, 0x1204, 0x2f1, 0x20c2, 0xcdd, 0x1689, 0xec9, 0x1c7, 0x247b, 0x2508, 0x2cc4, 0x6d7, 0x234f, 0x2bb, 0x609, 0x19d, 0x21da, 0x2ee0, 0xa7c, 0x3cc, 0x2f20, 0x257c, 0x2ae2, 0x2f02, 0xee6, 0x26db, 0x690, 0x1820, 0xdf9, 0x770, 0x72b, 0x1ca3, 0xe43, 0x1648, 0x174a, 0x143d, 0x19fc, 0x2732, 0x1d27, 0x2a40, 0x22ab, 0x280, 0x133, 0x1553, 0x2ff5, 0xe29, 0xd2b, 0x1326, 0x2e3d, 0x2c7c, 0x1b0a, 0x144f, 0x21f8, 0x2b72, 0x1a64, 0x2ce6, 0xf63, 0x1ec7, 0xbfd, 0x2954, 0xf53, 0x1730, 0x1386, 0x491, 0x212b, 0x222e, 0x3a5, 0xec5, 0x25c, 0x1755, 0x2945, 0x2c47, 0x8dd, 0x1b55, 0x4c9, 0x197, 0x2f31, 0x256d, 0x43a, 0x2be2, 0x166, 0x300, 0x14a4, 0xffd, 0x1cbf, 0x10fe, 0x1967, 0x2a2e, 0x1aaf, 0x256f, 0xfc8, 0xc4c, 0x299a, 0x21e3, 0x261, 0x2f26, 0x1ede, 0x2c70, 0x5b7, 0x11cf, 0x20c5, 0x29ae, 0x73e, 0x1ebd, 0x238, 0x1171, 0x11be, 0x222, 0x222d, 0xe8, 0x2c3d, 0x2055, 0x72f, 0x11d3, 0x7e0, 0x268d, 0x23f8, 0x2f54, 0x89a, 0x2bf7, 0x1ab7, 0x694, 0x2042, 0x2ecf, 0x847, 0x17c2, 0x2ef3, 0x2fb, 0x27c2, 0x12b2, 0x1e, 0x1501, 0x640, 0x22, 0x46a, 0x2716, 0xb66, 0x2663, 0x2157, 0x2f21, 0x1fb, 0x25c9, 0x7b3, 0x1f0c, 0x1a98, 0x28b1, 0x21b2, 0x2a09, 0x4f0, 0xc96, 0x2517, 0x2f33, 0x9f7, 0x1fc4, 0x218a, 0x1e08, 0xc9b, 0x1c69, 0xf34, 0xb16, 0x1ac5, 0x23b2, 0x2513, 0x1f99, 0x1922, 0x6a, 0x245a, 0x615, 0x1298, 0x1a7e, 0xac2, 0x24ce, 0x2db5, 0x15cb, 0x152e, 0x1a33, 0x97e, 0x138f, 0x1ccf, 0x230b, 0x2056, 0x10a6, 0x2d0a, 0x27d9, 0x21e4, 0x13f8, 0xb61, 0x8ea, 0x1ed4, 0x2019, 0x2c93, 0x1fbd, 0x291a, 0x3cb, 0x2959, 0x1a47, 0x1d08, 0x1edc, 0x254e, 0x2db4, 0x56c, 0x2f04, 0x1a74, 0xb4c, 0x2b8, 0x2ac8, 0x452, 0x297c, 0x666, 0xc1e, 0xfdd, 0x1633, 0x2dfa, 0x1861, 0x578, 0x241b, 0x13a5, 0x2710, 0x18bd, 0x32a, 0x1745, 0x2f3d, 0x13bc, 0x172c, 0x2c6b, 0x1179, 0xff5, 0x13cd, 0x2f9, 0x2216, 0x900, 0x9c5, 0x2ff7, 0x291, 0x368, 0x28de, 0x5a7, 0xa9, 0x104b, 0x1335, 0x24e4, 0xc5d, 0x2bcf, 0x2353, 0x1045, 0x21a6, 0x21fe, 0x270, 0x4c5, 0x2512, 0x688, 0x28ed, 0x2c4f, 0x1434, 0x15fe, 0x156a, 0x24d3, 0x1dc2, 0x283a, 0x22f5, 0x13e, 0x20ca, 0xb14, 0x149c, 0x2eca, 0x1169, 0x1387, 0x2078, 0x1160, 0xfbb, 0x1f79, 0x6e4, 0xe68, 0x1878, 0x2a57, 0x8e5, 0x1f1, 0x995, 0xaac, 0x2f01, 0x91f, 0xcb, 0x14b5, 0xa4a, 0x49, 0xdde, 0xbe7, 0x386, 0x1abe, 0x26a, 0x121c, 0x20be, 0x25c2, 0x2aed, 0x1a11, 0x2131, 0x1e19, 0xebf, 0xfb3, 0x265, 0x253a, 0x2b65, 0x2f4b, 0xa30, 0x2a17, 0x2de, 0x103a, 0x18e8, 0x1159, 0x2bfe, 0x1327, 0x2a10, 0x2d61, 0x2fa7, 0x815, 0x1d41, 0xf02, 0x22c3, 0x66, 0xdcf, 0x1540, 0x2f3e, 0x1983, 0x761, 0x1084, 0x1350, 0xdd, 0x15eb, 0xe0a, 0x2f50, 0x217f, 0xb21, 0x2a51, 0x15f6, 0x1d96, 0x1328, 0x9ca, 0x1500, 0x79, 0xfe9, 0x935, 0x16f0, 0x21ce, 0x73c, 0x2ac6, 0x1604, 0xe76, 0x2613, 0x330, 0x2d31, 0x10a7, 0x2a04, 0x180e, 0x170a, 0x2801, 0x1ca7, 0x255f, 0x3bc, 0x2b1, 0x1727, 0xf88, 0x1a15, 0x1c30, 0xeee, 0x2f37, 0x658, 0x15a5, 0x224f, 0x248, 0x1cc3, 0x71f, 0x1dd6, 0xbc3, 0x2b46, 0xc35, 0x13bb, 0x2afe, 0x2e0c, 0x21ca, 0x27a3, 0x9f0, 0x164b, 0x289f, 0x14dd, 0x2649, 0x22dc, 0xd2, 0x304, 0x2bc0, 0xee, 0x1ee6, 0x2195, 0x1fc9, 0x1cb0, 0x295d, 0x29e1, 0xddd, 0x187a, 0x5e4, 0x1950, 0x2a25, 0x2cd2, 0x2bda, 0x639, 0x2290, 0x2819, 0x139c, 0x2a5f, 0x15c0, 0x1e58, 0x2ac2, 0x1234, 0x283c, 0x6db, 0xa6a, 0x1d99, 0x2b60, 0x9d9, 0x1380, 0x1d2b, 0x1feb, 0x2e6, 0xe71, 0x2a93, 0x2226, 0x296f, 0x1b4d, 0x119d, 0x1fed, 0x88a, 0x43f, 0x2762, 0x1271, 0x28e7, 0x9a5, 0x548, 0x2256, 0x1488, 0x1b40, 0x26ea, 0x2d38, 0x2bc6, 0x1fa6, 0xe65, 0x17c8, 0x20ab, 0x17ff, 0x1e27, 0x2fb1, 0x1a8d, 0x169, 0x27ee, 0xb34, 0x1800, 0x151d, 0x1fe6, 0x25f4, 0x2916, 0x2929, 0x1f13, 0x1308, 0xb72, 0x1e3e, 0x25e, 0x2cca, 0x24d1, 0xf09, 0xb62, 0x21d0, 0x1aa4, 0x2648, 0xcb8, 0x2981, 0x216b, 0x1d28, 0x1626, 0x12e0, 0x2aa5, 0x2a22, 0x1231, 0x16e7, 0x1a4d, 0xfb1, 0x2a99, 0x14cf, 0x2e96, 0xeff, 0x1462, 0x2fbb, 0x11f7, 0x17d8, 0x2e0d, 0x2791, 0x49f, 0x120b, 0x2671, 0x1237, 0x268a, 0x12a3, 0x740, 0x11e1, 0x2b86, 0x2dee, 0x1110, 0x2163, 0x1379, 0x2db8, 0x2e76, 0x1623, 0x2d6a, 0x9ef, 0x5e3, 0x11c0, 0x104a, 0x2991, 0x4ae, 0x8b2, 0x2582, 0x1d8b, 0x41, 0x2780, 0x19dd, 0x28af, 0x2344, 0x199e, 0xe1b, 0x1c4b, 0x3b, 0x4d6, 0x1b45, 0x85b, 0xe42, 0xd97, 0x1312, 0x1ab3, 0x2901, 0xfd8, 0x58d, 0xf0, 0x1805, 0x1ff, 0x110, 0x2350, 0x18aa, 0x2b2f, 0x10e6, 0x1ec2, 0x252e, 0x1849, 0xc75, 0x2674, 0x2853, 0x12ab, 0x737, 0xde3, 0x10c3, 0x1491, 0xfbd, 0x2b07, 0x174f, 0x69b, 0x1412, 0x1194, 0x1e55, 0x196d, 0x13ec, 0x260f, 0x66a, 0x1da1, 0x2d8b, 0x892, 0xcc3, 0x90c, 0x350, 0x2ca, 0xa7, 0x4bd, 0x4e2, 0x1518, 0x2466, 0x14e9, 0x17e8, 0x1a78, 0x1ae6, 0x238e, 0x2d0d, 0xaf, 0x2284, 0x1475, 0x20c7, 0x29c0, 0x13fc, 0x227d, 0x1bdc, 0x10aa, 0x1db7, 0x18ae, 0x949, 0x3a1, 0x2f2c, 0x1187, 0x559, 0x248b, 0x1d30, 0xccd, 0x196a, 0x57, 0x1b4f, 0x1220, 0x28a3, 0xd1, 0x171e, 0xb8a, 0x1a87, 0xec0, 0x26ae, 0x229b, 0x1035, 0x1040, 0x4e, 0x1299, 0x226b, 0x1409, 0xb7a, 0x1c75, 0x1043, 0x120, 0x1339, 0xbff, 0x147a, 0x2a60, 0x13ff, 0x3d1, 0x2a16, 0x200a, 0x1467, 0x1c9d, 0x111c, 0x6b5, 0x6d, 0x5ae, 0x1e1a, 0x1497, 0x254a, 0x2a0a, 0xdbc, 0x77d, 0xc71, 0xf58, 0x1333, 0x1956, 0x2fe1, 0x724, 0x131d, 0x2a3f, 0xb4b, 0x2cf2, 0x281a, 0x1963, 0x1a94, 0x29da, 0x165f, 0xc28, 0x2908, 0x848, 0x1ff8, 0x2df0, 0x18dd, 0x1cd, 0x40f, 0x22c, 0x871, 0x3d3, 0xbf5, 0x1303, 0x2da9, 0x25e1, 0x2259, 0xc0d, 0x7ba, 0x2a8, 0x1180, 0x865, 0x542, 0x2fad, 0x31d, 0x2c2c, 0x2608, 0x23a5, 0x175e, 0x2d43, 0x2e27, 0x2dc4, 0x1018, 0x28b9, 0x1a44, 0xbb3, 0x176d, 0x23ea, 0x146, 0xb43, 0x124d, 0x28a8, 0x1ff7, 0x2829, 0x1bf9, 0x2832, 0x3c1, 0x1f94, 0x2d8e, 0x19e7, 0xd63, 0x1559, 0xd93, 0xaa3, 0x23e7, 0x73f, 0x2f42, 0x9e, 0x2837, 0xea, 0x2405, 0x248e, 0x10e3, 0xd6d, 0x2ca1, 0xc8, 0xc04, 0x9aa, 0x2eba, 0x1ef7, 0x1be2, 0x353, 0x2fe5, 0x1e40, 0xa2b, 0xd34, 0x27f, 0x2b6d, 0x251e, 0x1bdb, 0x2e04, 0x2393, 0x15f8, 0x2924, 0xe15, 0x29a2, 0x2efc, 0x1c3d, 0x2262, 0x100b, 0x99a, 0x278f, 0x240e, 0x288c, 0x12c3, 0x253, 0x2df4, 0x2725, 0x22a3, 0x78a, 0x20ba, 0xea6, 0x2147, 0xd30, 0x109a, 0x17b7, 0x2559, 0x20b1, 0x18d3, 0x2809, 0xbda, 0x709, 0x26f9, 0x23df, 0x1e60, 0x28f9, 0x1deb, 0x2514, 0xb7f, 0x957, 0x16d2, 0x47f, 0xfc, 0xfc6, 0x1136, 0xce8, 0x15d8, 0x47, 0x83a, 0x1619, 0x6b7, 0x2a73, 0x1d, 0x1788, 0x160b, 0x6e6, 0x2445, 0x1646, 0xe38, 0x3d2, 0x14eb, 0x1729, 0xb89, 0x131c, 0x13d9, 0x184c, 0x1275, 0x1fbb, 0x16ae, 0x2488, 0x297d, 0xc2d, 0x633, 0x2fe7, 0x2a9a, 0x1a96, 0xe20, 0x92d, 0x1146, 0x956, 0x1400, 0x998, 0x1a95, 0x2fa1, 0x223d, 0x2a4d, 0x11e5, 0xfdc, 0x198a, 0x2934, 0x1f9, 0x2553];

    return NHS;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

function PAIR(ctx) {

    var PAIR = {
        /* Line function */
        line: function(A, B, Qx, Qy) {
            var r = new ctx.FP12(1),
                c = new ctx.FP4(0),
                XX, YY, ZZ, YZ, sb,
                X1, Y1, T1, T2,
                a, b;

            if (A == B) {
                /* Doubling */
                XX = new ctx.FP2(A.getx());
                YY = new ctx.FP2(A.gety());
                ZZ = new ctx.FP2(A.getz());
                YZ = new ctx.FP2(YY);

                YZ.mul(ZZ); //YZ
                XX.sqr(); //X^2
                YY.sqr(); //Y^2
                ZZ.sqr(); //Z^2

                YZ.imul(4);
                YZ.neg();
                YZ.norm(); //-2YZ
                YZ.pmul(Qy); //-2YZ.Ys

                XX.imul(6); //3X^2
                XX.pmul(Qx); //3X^2.Xs

                sb = 3 * ctx.ROM_CURVE.CURVE_B_I;
                ZZ.imul(sb);
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                    ZZ.div_ip2();
                }
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    ZZ.mul_ip();
                    ZZ.add(ZZ);
                    YZ.mul_ip();
                    YZ.norm();
                }
                ZZ.norm(); // 3b.Z^2

                YY.add(YY);
                ZZ.sub(YY);
                ZZ.norm(); // 3b.Z^2-Y^2

                a = new ctx.FP4(YZ, ZZ); // -2YZ.Ys | 3b.Z^2-Y^2 | 3X^2.Xs
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                    b = new ctx.FP4(XX); // L(0,1) | L(0,0) | L(1,0)
                    c = new ctx.FP4(0);
                }
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    b = new ctx.FP4(0);
                    c = new ctx.FP4(XX); c.times_i();
                }

                A.dbl();
            } else {
                /* Addition */
                X1 = new ctx.FP2(A.getx()); // X1
                Y1 = new ctx.FP2(A.gety()); // Y1
                T1 = new ctx.FP2(A.getz()); // Z1
                T2 = new ctx.FP2(A.getz()); // Z1

                T1.mul(B.gety()); // T1=Z1.Y2
                T2.mul(B.getx()); // T2=Z1.X2

                X1.sub(T2);
                X1.norm(); // X1=X1-Z1.X2
                Y1.sub(T1);
                Y1.norm(); // Y1=Y1-Z1.Y2

                T1.copy(X1); // T1=X1-Z1.X2
                X1.pmul(Qy); // X1=(X1-Z1.X2).Ys

                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    X1.mul_ip();
                    X1.norm();
                }

                T1.mul(B.gety()); // T1=(X1-Z1.X2).Y2

                T2.copy(Y1); // T2=Y1-Z1.Y2
                T2.mul(B.getx()); // T2=(Y1-Z1.Y2).X2
                T2.sub(T1);
                T2.norm(); // T2=(Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2
                Y1.pmul(Qx);
                Y1.neg();
                Y1.norm(); // Y1=-(Y1-Z1.Y2).Xs

                a = new ctx.FP4(X1, T2); // (X1-Z1.X2).Ys  |  (Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2  | - (Y1-Z1.Y2).Xs
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                    b = new ctx.FP4(Y1);
                    c = new ctx.FP4(0);
                }
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    b = new ctx.FP4(0);
                    c = new ctx.FP4(Y1); c.times_i();
                }

                A.add(B);
            }

            r.set(a, b, c);

            return r;
        },

        /* Optimal R-ate pairing */
        ate: function(P, Q) {
            var fa, fb, f, x, n, n3, K, lv,
                Qx, Qy, A, r, nb, bt,
                i;

            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
            n = new ctx.BIG(x);
            K = new ctx.ECP2();

            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {

                fa = new ctx.BIG(0);
                fa.rcopy(ctx.ROM_FIELD.Fra);
                fb = new ctx.BIG(0);
                fb.rcopy(ctx.ROM_FIELD.Frb);
                f = new ctx.FP2(fa, fb);

                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    f.inverse();
                    f.norm();
                }

                n.pmul(6);
                if (ctx.ECP.SIGN_OF_X == ctx.ECP.POSITIVEX) {
                    n.inc(2);
                } else {
                    n.dec(2);
                }
            } else {
                n.copy(x);
            }
            n.norm();

            n3 = new ctx.BIG(n);
            n3.pmul(3);
            n3.norm();

            Qx = new ctx.FP(Q.getx());
            Qy = new ctx.FP(Q.gety());

            A = new ctx.ECP2();
            r = new ctx.FP12(1);

            A.copy(P);
            nb = n3.nbits();

            for (i = nb - 2; i >= 1; i--) {
                r.sqr();
                lv = PAIR.line(A, A, Qx, Qy);

                r.smul(lv,ctx.ECP.SEXTIC_TWIST);

                bt=n3.bit(i)-n.bit(i);

                if (bt == 1) {
                    lv = PAIR.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                }
                if (bt == -1) {
                    P.neg();
                    lv = PAIR.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    P.neg();
                }
            }

            if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
                r.conj();
            }

            /* R-ate fixup */
            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
                if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
                    A.neg();
                }

                K.copy(P);
                K.frob(f);

                lv = PAIR.line(A, K, Qx, Qy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                K.frob(f);
                K.neg();
                lv = PAIR.line(A, K, Qx, Qy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);
            }

            return r;
        },

        /* Optimal R-ate double pairing e(P,Q).e(R,S) */
        ate2: function(P, Q, R, S) {
            var fa, fb, f, x, n, n3, K, lv,
                Qx, Qy, Sx, Sy, A, B, r, nb, bt,
                i;


            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);

            n = new ctx.BIG(x);
            K = new ctx.ECP2();

            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
                fa = new ctx.BIG(0);
                fa.rcopy(ctx.ROM_FIELD.Fra);
                fb = new ctx.BIG(0);
                fb.rcopy(ctx.ROM_FIELD.Frb);
                f = new ctx.FP2(fa, fb);

                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    f.inverse();
                    f.norm();
                }

                n.pmul(6);
                if (ctx.ECP.SIGN_OF_X == ctx.ECP.POSITIVEX) {
                    n.inc(2);
                } else {
                    n.dec(2);
                }
            } else {
                n.copy(x);
            }
            n.norm();

            n3 = new ctx.BIG(n);
            n3.pmul(3);
            n3.norm();

            Qx = new ctx.FP(Q.getx());
            Qy = new ctx.FP(Q.gety());

            Sx = new ctx.FP(S.getx());
            Sy = new ctx.FP(S.gety());

            A = new ctx.ECP2();
            B = new ctx.ECP2();
            r = new ctx.FP12(1);

            A.copy(P);
            B.copy(R);
            nb = n3.nbits();

            for (i = nb - 2; i >= 1; i--) {
                r.sqr();
                lv = PAIR.line(A, A, Qx, Qy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                lv = PAIR.line(B, B, Sx, Sy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);

                bt=n3.bit(i)-n.bit(i);

                if (bt == 1) {
                    lv = PAIR.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    lv = PAIR.line(B, R, Sx, Sy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                }
                if (bt == -1) {
                    P.neg();
                    lv = PAIR.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    P.neg();
                    R.neg();
                    lv = PAIR.line(B, R, Sx, Sy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    R.neg();
                }
            }

            if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
                r.conj();
            }


            /* R-ate fixup required for BN curves */
            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
                if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
                    A.neg();
                    B.neg();
                }
                K.copy(P);
                K.frob(f);

                lv = PAIR.line(A, K, Qx, Qy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                K.frob(f);
                K.neg();
                lv = PAIR.line(A, K, Qx, Qy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);

                K.copy(R);
                K.frob(f);

                lv = PAIR.line(B, K, Sx, Sy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                K.frob(f);
                K.neg();
                lv = PAIR.line(B, K, Sx, Sy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);
            }

            return r;
        },

        /* final exponentiation - keep separate for multi-pairings and to avoid thrashing stack */
        fexp: function(m) {
            var fa, fb, f, x, r, lv,
                x0, x1, x2, x3, x4, x5,
                y0, y1, y2, y3;

            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb);
            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);

            r = new ctx.FP12(m);

            /* Easy part of final exp */
            lv = new ctx.FP12(r);
            lv.inverse();
            r.conj();
            r.mul(lv);
            lv.copy(r);
            r.frob(f);
            r.frob(f);
            r.mul(lv);

            /* Hard part of final exp */
            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
                lv.copy(r);
                lv.frob(f);
                x0 = new ctx.FP12(lv);
                x0.frob(f);
                lv.mul(r);
                x0.mul(lv);
                x0.frob(f);
                x1 = new ctx.FP12(r);
                x1.conj();

                x4 = r.pow(x);
                if (ctx.ECP.SIGN_OF_X == ctx.ECP.POSITIVEX) {
                    x4.conj();
                }

                x3 = new ctx.FP12(x4);
                x3.frob(f);
                x2 = x4.pow(x);
                if (ctx.ECP.SIGN_OF_X == ctx.ECP.POSITIVEX) {
                    x2.conj();
                }
                x5 = new ctx.FP12(x2);
                x5.conj();
                lv = x2.pow(x);
                if (ctx.ECP.SIGN_OF_X == ctx.ECP.POSITIVEX) {
                    lv.conj();
                }
                x2.frob(f);
                r.copy(x2);
                r.conj();

                x4.mul(r);
                x2.frob(f);

                r.copy(lv);
                r.frob(f);
                lv.mul(r);

                lv.usqr();
                lv.mul(x4);
                lv.mul(x5);
                r.copy(x3);
                r.mul(x5);
                r.mul(lv);
                lv.mul(x2);
                r.usqr();
                r.mul(lv);
                r.usqr();
                lv.copy(r);
                lv.mul(x1);
                r.mul(x0);
                lv.usqr();
                r.mul(lv);
                r.reduce();
            } else {
                // Ghamman & Fouotsa Method
                y0 = new ctx.FP12(r);
                y0.usqr();
                y1 = y0.pow(x);
                if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                    y1.conj();
                }
                x.fshr(1);
                y2 = y1.pow(x);
                if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                    y2.conj();
                }
                x.fshl(1);
                y3 = new ctx.FP12(r);
                y3.conj();
                y1.mul(y3);

                y1.conj();
                y1.mul(y2);

                y2 = y1.pow(x);
                if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                    y2.conj();
                }

                y3 = y2.pow(x);
                if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                    y3.conj();
                }
                y1.conj();
                y3.mul(y1);

                y1.conj();
                y1.frob(f);
                y1.frob(f);
                y1.frob(f);
                y2.frob(f);
                y2.frob(f);
                y1.mul(y2);

                y2 = y3.pow(x);
                if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                    y2.conj();
                }
                y2.mul(y0);
                y2.mul(r);

                y1.mul(y2);
                y2.copy(y3);
                y2.frob(f);
                y1.mul(y2);
                r.copy(y1);
                r.reduce();
            }

            return r;
        }
    };

    /* GLV method */
    PAIR.glv = function(e) {
        var u = [],
            t, q, v, d, x, x2, i, j;

        if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
            t = new ctx.BIG(0);
            q = new ctx.BIG(0);
            v = [];

            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            for (i = 0; i < 2; i++) {
                t.rcopy(ctx.ROM_CURVE.CURVE_W[i]);
                d = ctx.BIG.mul(t, e);
                v[i] = new ctx.BIG(d.div(q));
                u[i] = new ctx.BIG(0);
            }

            u[0].copy(e);

            for (i = 0; i < 2; i++) {
                for (j = 0; j < 2; j++) {
                    t.rcopy(ctx.ROM_CURVE.CURVE_SB[j][i]);
                    t.copy(ctx.BIG.modmul(v[j], t, q));
                    u[i].add(q);
                    u[i].sub(t);
                    u[i].mod(q);
                }
            }
        } else {
            // -(x^2).P = (Beta.x,y)
            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
            x2 = ctx.BIG.smul(x, x);
            u[0] = new ctx.BIG(e);
            u[0].mod(x2);
            u[1] = new ctx.BIG(e);
            u[1].div(x2);
            u[1].rsub(q);
        }

        return u;
    };

    /* Galbraith & Scott Method */
    PAIR.gs = function(e) {
        var u = [],
            i, j, t, q, v, d, x, w;

        if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
            t = new ctx.BIG(0);
            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            v = [];

            for (i = 0; i < 4; i++) {
                t.rcopy(ctx.ROM_CURVE.CURVE_WB[i]);
                d = ctx.BIG.mul(t, e);
                v[i] = new ctx.BIG(d.div(q));
                u[i] = new ctx.BIG(0);
            }

            u[0].copy(e);

            for (i = 0; i < 4; i++) {
                for (j = 0; j < 4; j++) {
                    t.rcopy(ctx.ROM_CURVE.CURVE_BB[j][i]);
                    t.copy(ctx.BIG.modmul(v[j], t, q));
                    u[i].add(q);
                    u[i].sub(t);
                    u[i].mod(q);
                }
            }
        } else {
            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            w = new ctx.BIG(e);

            for (i = 0; i < 3; i++) {
                u[i] = new ctx.BIG(w);
                u[i].mod(x);
                w.div(x);
            }

            u[3] = new ctx.BIG(w);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                u[1].copy(ctx.BIG.modneg(u[1], q));
                u[3].copy(ctx.BIG.modneg(u[3], q));
            }
        }

        return u;
    };

    /* Multiply P by e in group G1 */
    PAIR.G1mul = function(P, e) {
        var R, Q, q, bcru, cru, t, u, np, nn;

        if (ctx.ROM_CURVE.USE_GLV) {
            P.affine();
            R = new ctx.ECP();
            R.copy(P);
            Q = new ctx.ECP();
            Q.copy(P);
            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            bcru = new ctx.BIG(0);
            bcru.rcopy(ctx.ROM_CURVE.CURVE_Cru);
            cru = new ctx.FP(bcru);
            t = new ctx.BIG(0);
            u = PAIR.glv(e);

            Q.getx().mul(cru);

            np = u[0].nbits();
            t.copy(ctx.BIG.modneg(u[0], q));
            nn = t.nbits();
            if (nn < np) {
                u[0].copy(t);
                R.neg();
            }

            np = u[1].nbits();
            t.copy(ctx.BIG.modneg(u[1], q));
            nn = t.nbits();
            if (nn < np) {
                u[1].copy(t);
                Q.neg();
            }
            u[0].norm();
            u[1].norm();
            R = R.mul2(u[0], Q, u[1]);
        } else {
            R = P.mul(e);
        }

        return R;
    };

    /* Multiply P by e in group G2 */
    PAIR.G2mul = function(P, e) {
        var R, Q, fa, fb, f, q, u, t, i, np, nn;

        if (ctx.ROM_CURVE.USE_GS_G2) {
            Q = [];
            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb);

            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                f.inverse();
                f.norm();
            }

            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            u = PAIR.gs(e);
            t = new ctx.BIG(0);
            P.affine();
            Q[0] = new ctx.ECP2();
            Q[0].copy(P);

            for (i = 1; i < 4; i++) {
                Q[i] = new ctx.ECP2();
                Q[i].copy(Q[i - 1]);
                Q[i].frob(f);
            }

            for (i = 0; i < 4; i++) {
                np = u[i].nbits();
                t.copy(ctx.BIG.modneg(u[i], q));
                nn = t.nbits();

                if (nn < np) {
                    u[i].copy(t);
                    Q[i].neg();
                }
                u[i].norm();
            }

            R = ctx.ECP2.mul4(Q, u);
        } else {
            R = P.mul(e);
        }
        return R;
    };

    /* Note that this method requires a lot of RAM! Better to use compressed XTR method, see ctx.FP4.js */
    PAIR.GTpow = function(d, e) {
        var r, g, fa, fb, f, q, t, u, i, np, nn;

        if (ctx.ROM_CURVE.USE_GS_GT) {
            g = [];
            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb);
            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            t = new ctx.BIG(0);
            u = PAIR.gs(e);

            g[0] = new ctx.FP12(d);

            for (i = 1; i < 4; i++) {
                g[i] = new ctx.FP12(0);
                g[i].copy(g[i - 1]);
                g[i].frob(f);
            }

            for (i = 0; i < 4; i++) {
                np = u[i].nbits();
                t.copy(ctx.BIG.modneg(u[i], q));
                nn = t.nbits();

                if (nn < np) {
                    u[i].copy(t);
                    g[i].conj();
                }
                u[i].norm();
            }

            r = ctx.FP12.pow4(g, u);
        } else {
            r = d.pow(e);
        }

        return r;
    };

    return PAIR;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

function PAIR192(ctx) {

    var PAIR192 = {
        /* Line function */
        line: function(A, B, Qx, Qy) {
            var r = new ctx.FP24(1),
                XX, YY, ZZ, YZ, sb,
                X1, Y1, T1, T2,
                a, b, c;

            if (A == B) { /* Doubling */
                XX = new ctx.FP4(A.getx());
                YY = new ctx.FP4(A.gety());
                ZZ = new ctx.FP4(A.getz());
                YZ = new ctx.FP4(YY);

                YZ.mul(ZZ); //YZ
                XX.sqr(); //X^2
                YY.sqr(); //Y^2
                ZZ.sqr(); //Z^2

                YZ.imul(4);
                YZ.neg();
                YZ.norm(); //-2YZ
                YZ.qmul(Qy); //-2YZ.Ys

                XX.imul(6); //3X^2
                XX.qmul(Qx); //3X^2.Xs

                sb = 3 * ctx.ROM_CURVE.CURVE_B_I;
                ZZ.imul(sb);
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                    ZZ.div_2i();
                }
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    ZZ.times_i();
                    ZZ.add(ZZ);
                    YZ.times_i();
                    YZ.norm();
                }
                ZZ.norm(); // 3b.Z^2

                YY.add(YY);
                ZZ.sub(YY);
                ZZ.norm(); // 3b.Z^2-Y^2

                a = new ctx.FP8(YZ, ZZ); // -2YZ.Ys | 3b.Z^2-Y^2 | 3X^2.Xs
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                    b = new ctx.FP8(XX); // L(0,1) | L(0,0) | L(1,0)
                    c = new ctx.FP8(0);
                }
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    b = new ctx.FP8(0);
                    c = new ctx.FP8(XX); c.times_i();
                }

                A.dbl();
            } else { /* Addition */
                X1 = new ctx.FP4(A.getx()); // X1
                Y1 = new ctx.FP4(A.gety()); // Y1
                T1 = new ctx.FP4(A.getz()); // Z1
                T2 = new ctx.FP4(A.getz()); // Z1

                T1.mul(B.gety()); // T1=Z1.Y2
                T2.mul(B.getx()); // T2=Z1.X2

                X1.sub(T2);
                X1.norm(); // X1=X1-Z1.X2
                Y1.sub(T1);
                Y1.norm(); // Y1=Y1-Z1.Y2

                T1.copy(X1); // T1=X1-Z1.X2
                X1.qmul(Qy); // X1=(X1-Z1.X2).Ys

                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    X1.times_i();
                    X1.norm();
                }

                T1.mul(B.gety()); // T1=(X1-Z1.X2).Y2

                T2.copy(Y1); // T2=Y1-Z1.Y2
                T2.mul(B.getx()); // T2=(Y1-Z1.Y2).X2
                T2.sub(T1);
                T2.norm(); // T2=(Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2
                Y1.qmul(Qx);
                Y1.neg();
                Y1.norm(); // Y1=-(Y1-Z1.Y2).Xs

                a = new ctx.FP8(X1, T2); // (X1-Z1.X2).Ys  |  (Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2  | - (Y1-Z1.Y2).Xs
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                    b = new ctx.FP8(Y1);
                    c = new ctx.FP8(0);
                }
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    b = new ctx.FP8(0);
                    c = new ctx.FP8(Y1); c.times_i();
                }

                A.add(B);
            }

            r.set(a, b, c);

            return r;
        },

        /* Optimal R-ate pairing */
        ate: function(P, Q) {
            var x, n, n3, lv,
                Qx, Qy, A, r, nb, bt,
                i;

            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
            n = new ctx.BIG(x);

            n3 = new ctx.BIG(n);
            n3.pmul(3);
            n3.norm();

            Qx = new ctx.FP(Q.getx());
            Qy = new ctx.FP(Q.gety());

            A = new ctx.ECP4();
            r = new ctx.FP24(1);

            A.copy(P);
            nb = n3.nbits();

            for (i = nb - 2; i >= 1; i--) {
                r.sqr();
                lv = PAIR192.line(A, A, Qx, Qy);

                r.smul(lv,ctx.ECP.SEXTIC_TWIST);

                bt=n3.bit(i)-n.bit(i);

                if (bt == 1) {
                    lv = PAIR192.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                }
                if (bt == -1) {
                    P.neg();
                    lv = PAIR192.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    P.neg();
                }
            }

            if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
                r.conj();
            }

            return r;
        },

        /* Optimal R-ate double pairing e(P,Q).e(R,S) */
        ate2: function(P, Q, R, S) {
            var x, n, n3, lv,
                Qx, Qy, Sx, Sy, A, B, r, nb, bt,
                i;


            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);

            n = new ctx.BIG(x);
            n3 = new ctx.BIG(n);
            n3.pmul(3);
            n3.norm();

            Qx = new ctx.FP(Q.getx());
            Qy = new ctx.FP(Q.gety());

            Sx = new ctx.FP(S.getx());
            Sy = new ctx.FP(S.gety());

            A = new ctx.ECP4();
            B = new ctx.ECP4();
            r = new ctx.FP24(1);

            A.copy(P);
            B.copy(R);
            nb = n3.nbits();

            for (i = nb - 2; i >= 1; i--) {
                r.sqr();
                lv = PAIR192.line(A, A, Qx, Qy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                lv = PAIR192.line(B, B, Sx, Sy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);

                bt=n3.bit(i)-n.bit(i);

                if (bt == 1) {
                    lv = PAIR192.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    lv = PAIR192.line(B, R, Sx, Sy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                }
                if (bt == -1) {
                    P.neg();
                    lv = PAIR192.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    P.neg();
                    R.neg();
                    lv = PAIR192.line(B, R, Sx, Sy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    R.neg();
                }
            }

            if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
                r.conj();
            }

            return r;
        },

        /* final exponentiation - keep separate for multi-pairings and to avoid thrashing stack */
        fexp: function(m) {
            var fa, fb, f, x, r, lv,
                t0,t1,t2,t3,t4,t5,t6,t7;

            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb);
            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);

            r = new ctx.FP24(m);

            /* Easy part of final exp */
            lv = new ctx.FP24(r);
            lv.inverse();
            r.conj();
            r.mul(lv);
            lv.copy(r);
            r.frob(f,4);
            r.mul(lv);

            /* Hard part of final exp */
            // Ghamman & Fouotsa Method
            t7=new ctx.FP24(r); t7.usqr();
            t1=t7.pow(x);

            x.fshr(1);
            t2=t1.pow(x);
            x.fshl(1);

            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }
            t3=new ctx.FP24(t1); t3.conj();
            t2.mul(t3);
            t2.mul(r);

            t3=t2.pow(x);
            t4=t3.pow(x);
            t5=t4.pow(x);

            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t3.conj(); t5.conj();
            }

            t3.frob(f,6); t4.frob(f,5);
            t3.mul(t4);

            t6=t5.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t6.conj();
            }

            t5.frob(f,4);
            t3.mul(t5);

            t0=new ctx.FP24(t2); t0.conj();
            t6.mul(t0);

            t5.copy(t6);
            t5.frob(f,3);

            t3.mul(t5);
            t5=t6.pow(x);
            t6=t5.pow(x);

            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t5.conj();
            }

            t0.copy(t5);
            t0.frob(f,2);
            t3.mul(t0);
            t0.copy(t6);
            t0.frob(f,1);

            t3.mul(t0);
            t5=t6.pow(x);

            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t5.conj();
            }
            t2.frob(f,7);

            t5.mul(t7);
            t3.mul(t2);
            t3.mul(t5);

            r.mul(t3);

            r.reduce();

            return r;
        }
    };

    /* GLV method */
    PAIR192.glv = function(e) {
        var u = [],
            q, x, x2;

        // -(x^2).P = (Beta.x,y)
        q = new ctx.BIG(0);
        q.rcopy(ctx.ROM_CURVE.CURVE_Order);
        x = new ctx.BIG(0);
        x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
        x2 = ctx.BIG.smul(x, x);
        x = ctx.BIG.smul(x2,x2);
        u[0] = new ctx.BIG(e);
        u[0].mod(x);
        u[1] = new ctx.BIG(e);
        u[1].div(x);
        u[1].rsub(q);

        return u;
    };

    /* Galbraith & Scott Method */
    PAIR192.gs = function(e) {
        var u = [],
            i, q, x, w;

        x = new ctx.BIG(0);
        x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
        q = new ctx.BIG(0);
        q.rcopy(ctx.ROM_CURVE.CURVE_Order);
        w = new ctx.BIG(e);

        for (i = 0; i < 7; i++) {
            u[i] = new ctx.BIG(w);
            u[i].mod(x);
            w.div(x);
        }

        u[7] = new ctx.BIG(w);
        if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
            u[1].copy(ctx.BIG.modneg(u[1], q));
            u[3].copy(ctx.BIG.modneg(u[3], q));
            u[5].copy(ctx.BIG.modneg(u[5], q));
            u[7].copy(ctx.BIG.modneg(u[7], q));
        }

        return u;
    };

    /* Multiply P by e in group G1 */
    PAIR192.G1mul = function(P, e) {
        var R, Q, q, bcru, cru, t, u, np, nn;

        if (ctx.ROM_CURVE.USE_GLV) {
            P.affine();
            R = new ctx.ECP();
            R.copy(P);
            Q = new ctx.ECP();
            Q.copy(P);
            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            bcru = new ctx.BIG(0);
            bcru.rcopy(ctx.ROM_CURVE.CURVE_Cru);
            cru = new ctx.FP(bcru);
            t = new ctx.BIG(0);
            u = PAIR192.glv(e);

            Q.getx().mul(cru);

            np = u[0].nbits();
            t.copy(ctx.BIG.modneg(u[0], q));
            nn = t.nbits();
            if (nn < np) {
                u[0].copy(t);
                R.neg();
            }

            np = u[1].nbits();
            t.copy(ctx.BIG.modneg(u[1], q));
            nn = t.nbits();
            if (nn < np) {
                u[1].copy(t);
                Q.neg();
            }
            u[0].norm();
            u[1].norm();
            R = R.mul2(u[0], Q, u[1]);
        } else {
            R = P.mul(e);
        }

        return R;
    };

    /* Multiply P by e in group G2 */
    PAIR192.G2mul = function(P, e) {
        var R, Q, F, q, u, t, i, np, nn;

        if (ctx.ROM_CURVE.USE_GS_G2) {
            Q = [];
            F = ctx.ECP4.frob_constants();

            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            u = PAIR192.gs(e);
            t = new ctx.BIG(0);
            P.affine();
            Q[0] = new ctx.ECP4();
            Q[0].copy(P);

            for (i = 1; i < 8; i++) {
                Q[i] = new ctx.ECP4();
                Q[i].copy(Q[i - 1]);
                Q[i].frob(F,1);
            }

            for (i = 0; i < 8; i++) {
                np = u[i].nbits();
                t.copy(ctx.BIG.modneg(u[i], q));
                nn = t.nbits();

                if (nn < np) {
                    u[i].copy(t);
                    Q[i].neg();
                }
                u[i].norm();
            }

            R = ctx.ECP4.mul8(Q, u);
        } else {
            R = P.mul(e);
        }
        return R;
    };

    /* Note that this method requires a lot of RAM! Better to use compressed XTR method, see ctx.FP4.js */
    PAIR192.GTpow = function(d, e) {
        var r, g, fa, fb, f, q, t, u, i, np, nn;

        if (ctx.ROM_CURVE.USE_GS_GT) {
            g = [];
            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb);
            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            t = new ctx.BIG(0);
            u = PAIR192.gs(e);

            g[0] = new ctx.FP24(d);

            for (i = 1; i < 8; i++) {
                g[i] = new ctx.FP24(0);
                g[i].copy(g[i - 1]);
                g[i].frob(f,1);
            }

            for (i = 0; i < 8; i++) {
                np = u[i].nbits();
                t.copy(ctx.BIG.modneg(u[i], q));
                nn = t.nbits();

                if (nn < np) {
                    u[i].copy(t);
                    g[i].conj();
                }
                u[i].norm();
            }

            r = ctx.FP24.pow8(g, u);
        } else {
            r = d.pow(e);
        }

        return r;
    };

    return PAIR192;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

function PAIR256(ctx) {

    var PAIR256 = {
        /* Line function */
        line: function(A, B, Qx, Qy) {
            var r = new ctx.FP48(1),
                XX, YY, ZZ, YZ, sb,
                X1, Y1, T1, T2,
                a, b, c;

            if (A == B) { /* Doubling */
                XX = new ctx.FP8(A.getx());
                YY = new ctx.FP8(A.gety());
                ZZ = new ctx.FP8(A.getz());
                YZ = new ctx.FP8(YY);

                YZ.mul(ZZ); //YZ
                XX.sqr(); //X^2
                YY.sqr(); //Y^2
                ZZ.sqr(); //Z^2

                YZ.imul(4);
                YZ.neg();
                YZ.norm(); //-2YZ
                YZ.tmul(Qy); //-2YZ.Ys

                XX.imul(6); //3X^2
                XX.tmul(Qx); //3X^2.Xs

                sb = 3 * ctx.ROM_CURVE.CURVE_B_I;
                ZZ.imul(sb);
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                    ZZ.div_2i();
                }
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    ZZ.times_i();
                    ZZ.add(ZZ);
                    YZ.times_i();
                    YZ.norm();
                }
                ZZ.norm(); // 3b.Z^2

                YY.add(YY);
                ZZ.sub(YY);
                ZZ.norm(); // 3b.Z^2-Y^2

                a = new ctx.FP16(YZ, ZZ); // -2YZ.Ys | 3b.Z^2-Y^2 | 3X^2.Xs
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                    b = new ctx.FP16(XX); // L(0,1) | L(0,0) | L(1,0)
                    c = new ctx.FP16(0);
                }
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    b = new ctx.FP16(0);
                    c = new ctx.FP16(XX); c.times_i();
                }

                A.dbl();
            } else { /* Addition */
                X1 = new ctx.FP8(A.getx()); // X1
                Y1 = new ctx.FP8(A.gety()); // Y1
                T1 = new ctx.FP8(A.getz()); // Z1
                T2 = new ctx.FP8(A.getz()); // Z1

                T1.mul(B.gety()); // T1=Z1.Y2
                T2.mul(B.getx()); // T2=Z1.X2

                X1.sub(T2);
                X1.norm(); // X1=X1-Z1.X2
                Y1.sub(T1);
                Y1.norm(); // Y1=Y1-Z1.Y2

                T1.copy(X1); // T1=X1-Z1.X2
                X1.tmul(Qy); // X1=(X1-Z1.X2).Ys

                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    X1.times_i();
                    X1.norm();
                }

                T1.mul(B.gety()); // T1=(X1-Z1.X2).Y2

                T2.copy(Y1); // T2=Y1-Z1.Y2
                T2.mul(B.getx()); // T2=(Y1-Z1.Y2).X2
                T2.sub(T1);
                T2.norm(); // T2=(Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2
                Y1.tmul(Qx);
                Y1.neg();
                Y1.norm(); // Y1=-(Y1-Z1.Y2).Xs

                a = new ctx.FP16(X1, T2); // (X1-Z1.X2).Ys  |  (Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2  | - (Y1-Z1.Y2).Xs
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                    b = new ctx.FP16(Y1);
                    c = new ctx.FP16(0);
                }
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    b = new ctx.FP16(0);
                    c = new ctx.FP16(Y1); c.times_i();
                }

                A.add(B);
            }

            r.set(a, b, c);

            return r;
        },

        /* Optimal R-ate pairing */
        ate: function(P, Q) {
            var x, n, n3, lv,
                Qx, Qy, A, r, nb, bt,
                i;

            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
            n = new ctx.BIG(x);

            n3 = new ctx.BIG(n);
            n3.pmul(3);
            n3.norm();

            Qx = new ctx.FP(Q.getx());
            Qy = new ctx.FP(Q.gety());

            A = new ctx.ECP8();
            r = new ctx.FP48(1);

            A.copy(P);
            nb = n3.nbits();

            for (i = nb - 2; i >= 1; i--) {
                r.sqr();
                lv = PAIR256.line(A, A, Qx, Qy);

                r.smul(lv,ctx.ECP.SEXTIC_TWIST);

                bt=n3.bit(i)-n.bit(i);

                if (bt == 1) {
                    lv = PAIR256.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                }
                if (bt == -1) {
                    P.neg();
                    lv = PAIR256.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    P.neg();
                }
            }

            if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
                r.conj();
            }

            return r;
        },

        /* Optimal R-ate double pairing e(P,Q).e(R,S) */
        ate2: function(P, Q, R, S) {
            var x, n, n3, lv,
                Qx, Qy, Sx, Sy, A, B, r, nb, bt,
                i;


            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);

            n = new ctx.BIG(x);
            n3 = new ctx.BIG(n);
            n3.pmul(3);
            n3.norm();

            Qx = new ctx.FP(Q.getx());
            Qy = new ctx.FP(Q.gety());

            Sx = new ctx.FP(S.getx());
            Sy = new ctx.FP(S.gety());

            A = new ctx.ECP8();
            B = new ctx.ECP8();
            r = new ctx.FP48(1);

            A.copy(P);
            B.copy(R);
            nb = n3.nbits();

            for (i = nb - 2; i >= 1; i--) {
                r.sqr();
                lv = PAIR256.line(A, A, Qx, Qy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                lv = PAIR256.line(B, B, Sx, Sy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);

                bt=n3.bit(i)-n.bit(i);

                if (bt == 1) {
                    lv = PAIR256.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    lv = PAIR256.line(B, R, Sx, Sy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                }
                if (bt == -1) {
                    P.neg();
                    lv = PAIR256.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    P.neg();
                    R.neg();
                    lv = PAIR256.line(B, R, Sx, Sy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    R.neg();
                }
            }

            if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
                r.conj();
            }

            return r;
        },

        /* final exponentiation - keep separate for multi-pairings and to avoid thrashing stack */
        fexp: function(m) {
            var fa, fb, f, x, r, lv,
                t1,t2,t3,t7;

            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb);
            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);

            r = new ctx.FP48(m);

            /* Easy part of final exp */
            lv = new ctx.FP48(r);
            lv.inverse();
            r.conj();
            r.mul(lv);
            lv.copy(r);
            r.frob(f,8);
            r.mul(lv);

            /* Hard part of final exp */
            // Ghamman & Fouotsa Method
            t7=new ctx.FP48(r); t7.usqr();
            t1=t7.pow(x);

            x.fshr(1);
            t2=t1.pow(x);
            x.fshl(1);

            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            t3=new ctx.FP48(t1); t3.conj();
            t2.mul(t3);
            t2.mul(r);

            r.mul(t7);

            t1=t2.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }
            t3.copy(t1);
            t3.frob(f,14);
            r.mul(t3);
            t1=t1.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            t3.copy(t1);
            t3.frob(f,13);
            r.mul(t3);
            t1=t1.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            t3.copy(t1);
            t3.frob(f,12);
            r.mul(t3);
            t1=t1.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            t3.copy(t1);
            t3.frob(f,11);
            r.mul(t3);
            t1=t1.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            t3.copy(t1);
            t3.frob(f,10);
            r.mul(t3);
            t1=t1.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            t3.copy(t1);
            t3.frob(f,9);
            r.mul(t3);
            t1=t1.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            t3.copy(t1);
            t3.frob(f,8);
            r.mul(t3);
            t1=t1.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            t3.copy(t2); t3.conj();
            t1.mul(t3);
            t3.copy(t1);
            t3.frob(f,7);
            r.mul(t3);
            t1=t1.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            t3.copy(t1);
            t3.frob(f,6);
            r.mul(t3);
            t1=t1.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            t3.copy(t1);
            t3.frob(f,5);
            r.mul(t3);
            t1=t1.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            t3.copy(t1);
            t3.frob(f,4);
            r.mul(t3);
            t1=t1.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            t3.copy(t1);
            t3.frob(f,3);
            r.mul(t3);
            t1=t1.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            t3.copy(t1);
            t3.frob(f,2);
            r.mul(t3);
            t1=t1.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            t3.copy(t1);
            t3.frob(f,1);
            r.mul(t3);
            t1=t1.pow(x);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                t1.conj();
            }

            r.mul(t1);
            t2.frob(f,15);
            r.mul(t2);

            r.reduce();
            return r;
        }
    };

    /* GLV method */
    PAIR256.glv = function(e) {
        var u = [],
            q, x, x2;

        // -(x^2).P = (Beta.x,y)
        q = new ctx.BIG(0);
        q.rcopy(ctx.ROM_CURVE.CURVE_Order);
        x = new ctx.BIG(0);
        x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
        x2 = ctx.BIG.smul(x, x);
        x = ctx.BIG.smul(x2,x2);
        x2 = ctx.BIG.smul(x,x);
        u[0] = new ctx.BIG(e);
        u[0].mod(x2);
        u[1] = new ctx.BIG(e);
        u[1].div(x2);
        u[1].rsub(q);

        return u;
    };

    /* Galbraith & Scott Method */
    PAIR256.gs = function(e) {
        var u = [],
            i, q, x, w;

        x = new ctx.BIG(0);
        x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
        q = new ctx.BIG(0);
        q.rcopy(ctx.ROM_CURVE.CURVE_Order);
        w = new ctx.BIG(e);

        for (i = 0; i < 15; i++) {
            u[i] = new ctx.BIG(w);
            u[i].mod(x);
            w.div(x);
        }

        u[15] = new ctx.BIG(w);
        if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
            u[1].copy(ctx.BIG.modneg(u[1], q));
            u[3].copy(ctx.BIG.modneg(u[3], q));
            u[5].copy(ctx.BIG.modneg(u[5], q));
            u[7].copy(ctx.BIG.modneg(u[7], q));
            u[9].copy(ctx.BIG.modneg(u[9],q));
            u[11].copy(ctx.BIG.modneg(u[11],q));
            u[13].copy(ctx.BIG.modneg(u[13],q));
            u[15].copy(ctx.BIG.modneg(u[15],q));

        }

        return u;
    };

    /* Multiply P by e in group G1 */
    PAIR256.G1mul = function(P, e) {
        var R, Q, q, bcru, cru, t, u, np, nn;

        if (ctx.ROM_CURVE.USE_GLV) {
            P.affine();
            R = new ctx.ECP();
            R.copy(P);
            Q = new ctx.ECP();
            Q.copy(P);
            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            bcru = new ctx.BIG(0);
            bcru.rcopy(ctx.ROM_CURVE.CURVE_Cru);
            cru = new ctx.FP(bcru);
            t = new ctx.BIG(0);
            u = PAIR256.glv(e);

            Q.getx().mul(cru);

            np = u[0].nbits();
            t.copy(ctx.BIG.modneg(u[0], q));
            nn = t.nbits();
            if (nn < np) {
                u[0].copy(t);
                R.neg();
            }

            np = u[1].nbits();
            t.copy(ctx.BIG.modneg(u[1], q));
            nn = t.nbits();
            if (nn < np) {
                u[1].copy(t);
                Q.neg();
            }
            u[0].norm();
            u[1].norm();
            R = R.mul2(u[0], Q, u[1]);
        } else {
            R = P.mul(e);
        }

        return R;
    };

    /* Multiply P by e in group G2 */
    PAIR256.G2mul = function(P, e) {
        var R, Q, F, q, u, t, i, np, nn;

        if (ctx.ROM_CURVE.USE_GS_G2) {
            Q = [];
            F = ctx.ECP8.frob_constants();

            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            u = PAIR256.gs(e);
            t = new ctx.BIG(0);
            P.affine();
            Q[0] = new ctx.ECP8();
            Q[0].copy(P);

            for (i = 1; i < 16; i++) {
                Q[i] = new ctx.ECP8();
                Q[i].copy(Q[i - 1]);
                Q[i].frob(F,1);
            }

            for (i = 0; i < 16; i++) {
                np = u[i].nbits();
                t.copy(ctx.BIG.modneg(u[i], q));
                nn = t.nbits();

                if (nn < np) {
                    u[i].copy(t);
                    Q[i].neg();
                }
                u[i].norm();
            }

            R = ctx.ECP8.mul16(Q, u);
        } else {
            R = P.mul(e);
        }
        return R;
    };

    /* Note that this method requires a lot of RAM! Better to use compressed XTR method, see ctx.FP4.js */
    PAIR256.GTpow = function(d, e) {
        var r, g, fa, fb, f, q, t, u, i, np, nn;

        if (ctx.ROM_CURVE.USE_GS_GT) {
            g = [];
            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb);
            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            t = new ctx.BIG(0);
            u = PAIR256.gs(e);

            g[0] = new ctx.FP48(d);

            for (i = 1; i < 16; i++) {
                g[i] = new ctx.FP48(0);
                g[i].copy(g[i - 1]);
                g[i].frob(f,1);
            }

            for (i = 0; i < 16; i++) {
                np = u[i].nbits();
                t.copy(ctx.BIG.modneg(u[i], q));
                nn = t.nbits();

                if (nn < np) {
                    u[i].copy(t);
                    g[i].conj();
                }
                u[i].norm();
            }

            r = ctx.FP48.pow16(g, u);
        } else {
            r = d.pow(e);
        }

        return r;
    };

    return PAIR256;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/*
 *   Cryptographic strong random number generator
 *
 *   Unguessable seed -> SHA -> PRNG internal state -> SHA -> random numbers
 *   Slow - but secure
 *
 *   See ftp://ftp.rsasecurity.com/pub/pdfs/bull-1.pdf for a justification
 */

/* Marsaglia & Zaman Random number generator constants */

function RAND(ctx) {

    var RAND = function() {
        /* Cryptographically strong pseudo-random number generator */
        /* random number...   */
        this.ira = [];
        /* ...array & pointer */
        this.rndptr = 0;
        this.borrow = 0;
        this.pool_ptr = 0;
        /* random pool */
        this.pool = [];
        this.clean();
    };

    RAND.prototype = {
        NK: 21,
        NJ: 6,
        NV: 8,

        /* Terminate and clean up */
        clean: function() {
            var i;

            for (i = 0; i < 32; i++) {
                this.pool[i] = 0;
            }

            for (i = 0; i < this.NK; i++) {
                this.ira[i] = 0;
            }

            this.rndptr = 0;
            this.borrow = 0;
            this.pool_ptr = 0;
        },

        sbrand: function() { /* Marsaglia & Zaman random number generator */
            var i, k, pdiff, t;

            this.rndptr++;
            if (this.rndptr < this.NK) {
                return this.ira[this.rndptr];
            }

            this.rndptr = 0;

            /* calculate next NK values */
            for (i = 0, k = this.NK - this.NJ; i < this.NK; i++, k++) {
                if (k == this.NK) {
                    k = 0;
                }

                t = this.ira[k] >>> 0;
                pdiff = (t - this.ira[i] - this.borrow) | 0;
                /* This is seriously weird stuff. I got to do this to get a proper unsigned comparison... */
                pdiff >>>= 0;

                if (pdiff < t) {
                    this.borrow = 0;
                }

                if (pdiff > t) {
                    this.borrow = 1;
                }

                this.ira[i] = (pdiff | 0);
            }

            return this.ira[0];
        },

        sirand: function(seed) {
            var m = 1,
                i, inn, t;

            this.borrow = 0;
            this.rndptr = 0;
            seed >>>= 0;
            this.ira[0] ^= seed;

            /* fill initialisation vector */
            for (i = 1; i < this.NK; i++) {
                inn = (this.NV * i) % this.NK;
                /* note XOR */
                this.ira[inn] ^= m;
                t = m;
                m = (seed - m) | 0;
                seed = t;
            }

            /* "warm-up" & stir the generator */
            for (i = 0; i < 10000; i++) {
                this.sbrand();
            }
        },

        fill_pool: function() {
            var sh = new ctx.HASH256(),
                i;

            for (i = 0; i < 128; i++) {
                sh.process(this.sbrand());
            }

            this.pool = sh.hash();
            this.pool_ptr = 0;
        },

        /* Initialize RNG with some real entropy from some external source - at least 128 byte string */
        seed: function(rawlen, raw) {
            var sh = new ctx.HASH256(),
                digest = [],
                b = [],
                i;

            this.pool_ptr = 0;

            for (i = 0; i < this.NK; i++) {
                this.ira[i] = 0;
            }

            if (rawlen > 0) {
                for (i = 0; i < rawlen; i++) {
                    sh.process(raw[i]);
                }

                digest = sh.hash();

                /* initialise PRNG from distilled randomness */
                for (i = 0; i < 8; i++) {
                    b[0] = digest[4 * i];
                    b[1] = digest[4 * i + 1];
                    b[2] = digest[4 * i + 2];
                    b[3] = digest[4 * i + 3];
                    this.sirand(RAND.pack(b));
                }
            }

            this.fill_pool();
        },

        /* get random byte */
        getByte: function() {
            var r = this.pool[this.pool_ptr++];

            if (this.pool_ptr >= 32) {
                this.fill_pool();
            }

            return (r & 0xff);
        }
    };

    /* pack 4 bytes into a 32-bit Word */
    RAND.pack = function(b) {
        return (((b[3]) & 0xff) << 24) | ((b[2] & 0xff) << 16) | ((b[1] & 0xff) << 8) | (b[0] & 0xff);
    };

    return RAND;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* Fixed Data in ROM - Field and Curve parameters */

var ROM_CURVE_ANSSI,
    ROM_CURVE_BLS383,
    ROM_CURVE_BLS24,
    ROM_CURVE_BLS48,
    ROM_CURVE_BLS381,
    ROM_CURVE_BLS461,
    ROM_CURVE_FP256BN,
    ROM_CURVE_FP512BN,
    ROM_CURVE_BN254,
    ROM_CURVE_BN254CX,
    ROM_CURVE_BRAINPOOL,
    ROM_CURVE_C25519,
    ROM_CURVE_C41417,
    ROM_CURVE_ED25519,
    ROM_CURVE_GOLDILOCKS,
    ROM_CURVE_HIFIVE,
    ROM_CURVE_NIST256,
    ROM_CURVE_NIST384,
    ROM_CURVE_NIST521,
    ROM_CURVE_NUMS256E,
    ROM_CURVE_NUMS256W,
    ROM_CURVE_NUMS384E,
    ROM_CURVE_NUMS384W,
    ROM_CURVE_NUMS512E,
    ROM_CURVE_NUMS512W,
    ROM_CURVE_SECP256K1;


ROM_CURVE_ANSSI = {

    // ANSSI curve

    Curve_Cof_I: 1,
    CURVE_A: -3,
    CURVE_B_I: 0,
    CURVE_B: [0x7BB73F, 0xED967B, 0x803075, 0xE4B1A1, 0xEC0C9A, 0xC00FDF, 0x754A44, 0xD4ABA, 0x28A930, 0x3FCA54, 0xEE35],
    CURVE_Order: [0xD655E1, 0xD459C6, 0x941FFD, 0x40D2BF, 0xDC67E1, 0x435B53, 0xE8CE42, 0x10126D, 0x3AD58F, 0x178C0B, 0xF1FD],
    CURVE_Gx: [0x8F5CFF, 0x7A2DD9, 0x164C9, 0xAF98B7, 0x27D2DC, 0x23958C, 0x4749D4, 0x31183D, 0xC139EB, 0xD4C356, 0xB6B3],
    CURVE_Gy: [0x62CFB, 0x5A1554, 0xE18311, 0xE8E4C9, 0x1C307, 0xEF8C27, 0xF0F3EC, 0x1F9271, 0xB20491, 0xE0F7C8, 0x6142],

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_BLS383 = {

    // BLS383 Curve
    // Base Bits= 23

    CURVE_Cof_I: 0,
    CURVE_A: 0,
    CURVE_B_I: 15,
    CURVE_B: [0xF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0x3C0001, 0x33D7FD, 0x5CEC82, 0x9069C, 0x5F095A, 0x703BC0, 0x5A62C, 0x2200E4, 0x3809C0, 0x1801, 0x8006, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Gx: [0x734573, 0x6E7210, 0x11E311, 0x1FA3B8, 0x5DBF08, 0x688B8A, 0x12BC78, 0x43DD6C, 0x742C2F, 0x6D6103, 0x4C767D, 0x6D8287, 0x74052D, 0x1C706B, 0x5E7B39, 0x5D2ADC, 0x41FC],
    CURVE_Gy: [0x3F224, 0x2CBD00, 0x7484B4, 0x43FCC7, 0x7D49EC, 0x25BBCA, 0x2B7AD3, 0x29854A, 0x449107, 0xCD76C, 0x7436B7, 0x6236CC, 0x1CDC31, 0x495D, 0x33ECC0, 0xB393A, 0x68F],

    CURVE_Bnx: [0x1200, 0x2, 0x40020, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cof: [0x169EAB, 0x2AC2AA, 0x7ED541, 0x555DF, 0x2AAC00, 0xAAB, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cru: [0x2AC2A9, 0x4EA05D, 0x4B730D, 0x16FB2E, 0x5F681A, 0x683784, 0xD37A8, 0x2917A5, 0x715CE2, 0x69B7BA, 0x15114, 0x4A43A3, 0x34406E, 0x1408B5, 0x2ADBAD, 0x2B4AB2, 0x5565],
    CURVE_Pxa: [0x7F2D86, 0x676C5A, 0x7850F2, 0x4AE8E9, 0x7DAB67, 0x65DD03, 0x3D5895, 0x3F8E48, 0x725BD4, 0x10A5AA, 0xC9407, 0xF3A32, 0x967CB, 0x180F32, 0x7B00FA, 0x691203, 0x634],
    CURVE_Pxb: [0x52DE15, 0x483D88, 0x37BF67, 0x2BFF30, 0x4AB28D, 0x3AEB6A, 0x23A4B5, 0x6CC5D4, 0x4C89DF, 0x5B3A0B, 0x13D263, 0x1B0EE9, 0x717288, 0x5E6F4E, 0x592E, 0x3C0030, 0x300D],
    CURVE_Pya: [0x8CB41, 0x617728, 0x5971A3, 0x106B0C, 0x1EDE4F, 0x5CEB69, 0x2A44E8, 0x4BC1D6, 0x1B3E68, 0x2CE793, 0x3A643B, 0x31A3DB, 0x573FE, 0x79293B, 0x4894D1, 0x167C9E, 0x3379],
    CURVE_Pyb: [0x479093, 0xC86FE, 0x18EB61, 0x731124, 0x43CB0D, 0x131602, 0x127DEF, 0x78597A, 0x7A8F7A, 0x8D67D, 0x73835, 0x53D700, 0x3A7D15, 0x649DCF, 0x33631A, 0x123EE9, 0x20E5],
    CURVE_W: [
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_SB: [
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ]
    ],
    CURVE_WB: [
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_BB: [
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ]
    ],

    USE_GLV: true,
    USE_GS_G2: true,
    USE_GS_GT: true,
    GT_STRONG: true,

    //debug: false,

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_BLS24 = {

    // BLS24 Curve
    // Base Bits= 23
    CURVE_Cof_I: 0,
    CURVE_A: 0,
    CURVE_B_I: 19,
    CURVE_B: [0x13, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0x1, 0x11FFE0, 0x464068, 0x1FFAA8, 0x71E703, 0x645BB5, 0x379FB8, 0x689D35, 0x49D0CE, 0x49091F, 0x4A7308, 0x286C0B, 0x3B44A0, 0x60B731, 0x6807C3, 0x8002, 0x10010, 0x0, 0x0, 0x0, 0x0],
    CURVE_Gx: [0x63CCD4, 0x41EBD7, 0x15919D, 0x576CFA, 0x1EFE2D, 0x743F98, 0xFC23A, 0x409A3C, 0x595AF8, 0x6F8DF1, 0x38B611, 0x65468D, 0x7E4BFD, 0x6B0D9D, 0x7641D, 0x2ECCDE, 0xB7FEA, 0x5BD3C3, 0x2BE521, 0x71A0BE, 0x1AB2B],
    CURVE_Gy: [0x1E5245, 0x4B95A4, 0x5B132E, 0x462AEF, 0x36D660, 0x672E8D, 0x7B4A53, 0x79E459, 0x24920F, 0x4828B0, 0x58F969, 0x1D527E, 0x4E00F6, 0x457EF3, 0x66924A, 0x294FFB, 0x66A7A4, 0x70C394, 0x4F91DE, 0x386362, 0x47FCB],

    CURVE_Bnx: [0x11FF80, 0x400, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cof: [0x7415AB, 0x7F7FF3, 0x5FFF07, 0x2AB555, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cru: [0x5794A9, 0x4E28DB, 0x690EF0, 0x1C5799, 0x63A309, 0x447BB8, 0x4485D4, 0x36FDD8, 0x7BB423, 0xE24B9, 0x5E7398, 0x11AC71, 0x806E0, 0x18DD64, 0x5DF5A0, 0x4307F, 0x314C20, 0x4D1C8, 0x2F16A2, 0x3C01E, 0x555C0],
    CURVE_Pxaa: [0x624678, 0x26A6E9, 0x22F8A, 0x212C12, 0x60C343, 0x3DF8D3, 0x5D9733, 0x6BFC87, 0x2D2888, 0x758675, 0x259D1C, 0x7E922C, 0x4BAB37, 0x11DAAB, 0x6214A4, 0x758A55, 0x786671, 0x72B190, 0x32581D, 0x729D1F, 0x959D],
    CURVE_Pxab: [0x3099B8, 0x3D75FF, 0x40E1FE, 0x9523, 0x63775A, 0x78470A, 0x5746C7, 0x7CF1B5, 0x26A730, 0x14FE14, 0x76CA97, 0x61C7C2, 0x669261, 0x6A7C2F, 0x3E5DA9, 0x5F2D68, 0x2D39D1, 0x4A3C98, 0x4CF7F1, 0x68418B, 0x3B0DE],
    CURVE_Pxba: [0x2D15D3, 0x1BCE23, 0x5BB687, 0x46FB70, 0x185317, 0x47C134, 0x2FD0FA, 0x3597B2, 0x56DE56, 0x165B19, 0x1D3F6E, 0x10E136, 0x76B1EF, 0x1913C7, 0x4011EF, 0x1F994F, 0x3FE210, 0x545186, 0x41EBCA, 0x7D6A72, 0x3EC27],
    CURVE_Pxbb: [0x60F480, 0x650EBD, 0x2E31EA, 0x21EB62, 0x14556E, 0x1C3973, 0x48B7E0, 0xFFEFD, 0x50122F, 0x55EE1F, 0x263BD7, 0x2ED92B, 0x1BA3AD, 0x39C35E, 0x2DD201, 0x17232E, 0x1DA7CE, 0x4CB0AA, 0x1E67DF, 0x46DE50, 0xA5B3],
    CURVE_Pyaa: [0x781AA0, 0x132628, 0x2AC619, 0x181DB8, 0x3609DA, 0x3F8897, 0x4A9851, 0x189252, 0x4C42A, 0x768C5C, 0x66B9A2, 0x1C1D70, 0x4FCADC, 0x69ED7C, 0x7D286C, 0xD685, 0x198F9, 0x459DA0, 0x30250D, 0x1AEB9B, 0x5057F],
    CURVE_Pyab: [0x2E08FA, 0x58AFDD, 0x5AB6EF, 0x5D52FC, 0x78774, 0x348594, 0x32BC26, 0x23C32, 0x3BCCF7, 0xB913F, 0x3E1549, 0x5B907F, 0x77B3E6, 0x22C6ED, 0x7865FE, 0x3DAEFB, 0x60F558, 0x702D7A, 0x3A258D, 0x24B30F, 0x2CE2B],
    CURVE_Pyba: [0x70CC41, 0x4ED4B, 0x7D5CC, 0x2A9855, 0x7F8932, 0x5F1428, 0x7361E6, 0x14406C, 0x68A9FE, 0x21DCA7, 0x4DC54E, 0x10783E, 0x71F3A4, 0x3AA336, 0x6C5305, 0x1E5ADC, 0x1A39DD, 0x7C73F0, 0x18C69A, 0x2331F7, 0x18070],
    CURVE_Pybb: [0x5C1CAE, 0x65CCA2, 0x2373C6, 0x2AD84C, 0x2D40D3, 0x714EEE, 0x10FF70, 0x3AE561, 0x136B6, 0x3EBA67, 0x75CBF3, 0x327450, 0x161AC1, 0x5CB9A1, 0x2C42EE, 0x48BB8F, 0x56D046, 0x725081, 0x77B22D, 0x2756CD, 0x499D1],
    CURVE_W: [
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_SB: [
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ]
    ],
    CURVE_WB: [
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_BB: [
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ]
    ],

    USE_GLV: true,
    USE_GS_G2: true,
    USE_GS_GT: true,
    GT_STRONG: true,

    //debug: false,
};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_BLS48 = {

    // BLS48 Curve
    // Base Bits= 23
    CURVE_Cof_I: 0,
    CURVE_A: 0,
    CURVE_B_I: 17,
    CURVE_B: [0x11, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0x1, 0x7E0000, 0x421BFF, 0x714ED3, 0x455409, 0x53842, 0x7AC588, 0x7E8A68, 0xAD8C1, 0x184DA5, 0x7FB5E2, 0x5E936, 0x5EF479, 0x12B881, 0x46FE3F, 0x32FD85, 0x2973C4, 0x3D260D, 0x318DF1, 0x88D57, 0x3F73EA, 0x1887, 0x0, 0x0, 0x0],
    CURVE_Gx: [0x571D33, 0x5A5ECB, 0x3FCA1, 0x7F196F, 0x580554, 0x23DC17, 0x591DC, 0x1987F8, 0x7CA7F6, 0x345E03, 0x203D9A, 0x1734D, 0x444E07, 0x5602B2, 0x5003E, 0x5961D5, 0x30D242, 0x336BC2, 0x79241, 0xE0499, 0x7EDD74, 0x3B712A, 0x215D65, 0x544F49, 0x9],
    CURVE_Gy: [0x6ED83A, 0x367FD4, 0x33DA69, 0x254538, 0x5C4B95, 0x2B0CEF, 0x7AA39A, 0x47D9C8, 0x677B5F, 0x4F9E3D, 0x6DC8A6, 0x71C0C7, 0x4B44E2, 0x4AA8F1, 0x4C3099, 0x3071E3, 0x240862, 0x1B9CCF, 0x579C4, 0x4D1997, 0x3349DA, 0x3F5C56, 0x5318B1, 0x56C684, 0x0],

    CURVE_Bnx: [0x640020, 0xFB, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cof: [0x12ABEB, 0x221EFE, 0x528B, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cru: [0x3BA429, 0x1CFCD9, 0x1600D9, 0x49A7BA, 0x4E30A2, 0x101275, 0xF1A0C, 0x6D146E, 0x42B839, 0x118594, 0x4EF0B4, 0x55CDB, 0x67127B, 0x3D8D31, 0x319233, 0x2571C, 0x1AEEFF, 0x72BC73, 0x91318, 0x1911E0, 0x279F78, 0x646407, 0x73DF3B, 0x68BEC1, 0xF],
    CURVE_Pxaaa: [0x23CE4A, 0x5D1D12, 0x74AA34, 0x695C09, 0x3D7102, 0x274419, 0x76284C, 0x69F0B2, 0x4637C1, 0x5FE3FE, 0x242E62, 0x3F853E, 0x4DD2B3, 0x672BDE, 0x6ED92, 0x2B9BAD, 0x6C4ABF, 0x393882, 0x32EE21, 0x2EF3A1, 0x59487E, 0x92F4B, 0x26870, 0x32BC6C, 0xE],
    CURVE_Pxaab: [0xA1BE1, 0x1B8B58, 0x7DC9C7, 0x3BEB, 0x28FE3B, 0x72E58B, 0x51E10C, 0x31856A, 0x389247, 0x15B9FD, 0x2847EA, 0x2E35A0, 0x9B0E7, 0x7F92CE, 0x6960C8, 0xC5821, 0x48632D, 0xC919C, 0x3C27F4, 0x2A934D, 0x348B6E, 0x2F6B1B, 0x179D2A, 0x4A1009, 0x2],
    CURVE_Pxaba: [0xC5DC4, 0x6498EE, 0x4B68E9, 0x6ED677, 0x2964AD, 0x7D8E6D, 0x4D0966, 0x550884, 0x1926AC, 0x47162D, 0x633555, 0x265962, 0x6402B8, 0x48F745, 0x68195F, 0x198B3A, 0x117CE2, 0x5E9EFB, 0x729335, 0x471F6E, 0x3689BA, 0x3BB4F1, 0x3DDB5C, 0x297F7C, 0xB],
    CURVE_Pxabb: [0x64B740, 0x52CD34, 0x578358, 0x464902, 0x11FD49, 0x475BA2, 0x5C150C, 0x436206, 0x335E27, 0x7CFA66, 0x53BA9F, 0x39E20F, 0x41E3C, 0x30CB43, 0x5E7D7A, 0x4869DA, 0x6B405, 0x57B683, 0x77306A, 0x3E774A, 0x63B1A6, 0x4BE47E, 0x764B7F, 0x1C2054, 0x9],
    CURVE_Pxbaa: [0x71E01F, 0x18C2E5, 0x26EC, 0x1A5853, 0x4311CD, 0x430F11, 0x43E8E4, 0x20204C, 0x35AB89, 0x775C07, 0x43202C, 0x442943, 0x1E3472, 0xB1BEA, 0x14841D, 0x56A6A1, 0x4E27C3, 0x6AC397, 0x111E6A, 0x453F3C, 0x449D32, 0x6288F9, 0x7D0633, 0x6F0F7B, 0xD],
    CURVE_Pxbab: [0x37383D, 0x70470C, 0x66C28, 0x7CCC3F, 0x220253, 0x27A425, 0x147B57, 0x64A9AE, 0x7A0147, 0x61CE2B, 0x7620BF, 0x1CEB9B, 0x3F1646, 0x5546DC, 0x12AEC8, 0x2A6D46, 0x38885E, 0xA7FD0, 0x3A2974, 0x7872F1, 0x4F91FB, 0x2ADE02, 0x632141, 0x16D9D3, 0x8],
    CURVE_Pxbba: [0x11939C, 0x7B67AE, 0x6BA5A0, 0x34D20C, 0x1BE51D, 0x65ED81, 0x6D5CB3, 0x6465E6, 0x40B384, 0x146E44, 0x54F471, 0x119F79, 0x11A9B3, 0x5235B8, 0x342402, 0x6B0380, 0x51A403, 0x22E30F, 0x1F23BA, 0x468CDF, 0x5A9CCF, 0x77C486, 0x613650, 0x411539, 0xA],
    CURVE_Pxbbb: [0x6F4899, 0x2150A, 0x750CB5, 0x4952B2, 0x1C51EB, 0x179378, 0x295E64, 0x5B5457, 0x47A789, 0x1403F8, 0x62578C, 0x2F5D38, 0x7FE82C, 0x6CFF62, 0x32162, 0x3ACBE5, 0x1E3000, 0x668F, 0x426A4B, 0x4F46ED, 0x57A328, 0x62ACF0, 0xF705B, 0x7BAA3C, 0xD],
    CURVE_Pyaaa: [0x137844, 0x2F9F68, 0x4DDB82, 0x4FFA79, 0x44EC64, 0x6D10A3, 0x1BEAF1, 0x4B2F5C, 0xB8A71, 0x20AB1C, 0x225B80, 0x663E7C, 0x673C10, 0x7E8EA9, 0x2FC388, 0x66E9CC, 0x202F56, 0x39587C, 0x343E8C, 0x52C8BF, 0x6190B, 0x11FB0E, 0x6124D5, 0x337685, 0x7],
    CURVE_Pyaab: [0x483190, 0x6491DB, 0x424978, 0x23544C, 0x2EAAF4, 0x31A65, 0x48EEB1, 0x7EEB0E, 0x91F2F, 0x2D992C, 0xF07C, 0x4AE56F, 0x688ED2, 0x62E3A0, 0x284758, 0x15CF7, 0x7E205E, 0x9FA40, 0x24EA65, 0xCE87C, 0x7A1C42, 0x1C4D1D, 0x4F76AA, 0x3CE59C, 0x2],
    CURVE_Pyaba: [0x185C0D, 0x3FA083, 0xFA771, 0x50C8EE, 0xD404D, 0x759D3, 0x697D52, 0x6598BC, 0x685C7C, 0x612D58, 0x160D06, 0x2201F3, 0x5C797C, 0x10C374, 0xE7E1C, 0x52FA00, 0x1F60B0, 0x42B24, 0x7635E0, 0xDD262, 0x140D61, 0x26A7E6, 0x595FBC, 0x22CDE4, 0xD],
    CURVE_Pyabb: [0x1D42F8, 0x41502B, 0x5D7DBF, 0x88B12, 0x243AFD, 0x3CFE57, 0x4EC3FA, 0x2FB013, 0x7C3CFF, 0x1D3717, 0x79401A, 0x33C434, 0x635F37, 0x29E4F6, 0x2CA2DB, 0x7A8EF0, 0x3FD902, 0x3309C9, 0x1F125B, 0x3FF0C9, 0x7310, 0x3137DB, 0x280E0B, 0x70755, 0xA],
    CURVE_Pybaa: [0x38039F, 0x25673E, 0x184354, 0x3E78D1, 0xEE895, 0x1279F, 0x285016, 0x445C85, 0x4BFE85, 0x7F8597, 0x2AEDD5, 0x2E62F9, 0x32710C, 0x4F5B51, 0x59016C, 0x6178C7, 0x6E268E, 0x2D39EF, 0x2C36B6, 0x717762, 0x1D1ABC, 0x323714, 0x7C7BB9, 0x582324, 0x2],
    CURVE_Pybab: [0x5F7865, 0x40DE52, 0x20E9A7, 0x7439D3, 0x3F0756, 0x595BAF, 0x7CFC76, 0x287B18, 0x56074E, 0x186679, 0x416EC0, 0x1DC812, 0x127FBE, 0x18D9B5, 0x3C4A9D, 0x1C2BB4, 0x135CA4, 0x7A40AC, 0x739984, 0x6F008C, 0x7180EA, 0x58AF6D, 0x5B4B02, 0x9194C, 0x3],
    CURVE_Pybba: [0x4C1979, 0x753ECF, 0x6F0760, 0x3BB13C, 0x4AAF9C, 0x6BFB52, 0x470858, 0x41323D, 0x5401D8, 0x494404, 0x5CCF5C, 0xBCF06, 0x7E6ECF, 0x5A9C20, 0xD2DFF, 0x64FF44, 0x31645B, 0x4EE883, 0x4E22EC, 0x112445, 0x486C5C, 0x5C8211, 0x67DA66, 0x400692, 0xC],
    CURVE_Pybbb: [0x49F25B, 0x12AC5F, 0x5D33F2, 0x35D356, 0x2C4F80, 0x3A4C9E, 0x3C5A72, 0x426C74, 0x5DAC92, 0x52C146, 0x61366B, 0x6CDE77, 0x5A9E8F, 0x6DFF70, 0x6D20E3, 0x5A60E6, 0x33DF1A, 0x2AFA7, 0x390F0, 0x6320A2, 0x3F5493, 0x1CC373, 0x174990, 0x7B09B, 0xA],
    CURVE_W: [
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_SB: [
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ]
    ],
    CURVE_WB: [
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_BB: [
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ]
    ],

    USE_GLV: true,
    USE_GS_G2: true,
    USE_GS_GT: true,
    GT_STRONG: true,

    //debug: false,


};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_BLS381 = {

    // BLS381 Curve
    // Base Bits= 23

    CURVE_Cof_I: 0,
    CURVE_A: 0,
    CURVE_B_I: 4,
    CURVE_B: [0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0x1, 0x7FFE00, 0x7BFFFF, 0x7FF2DF, 0x5A402F, 0xAA77, 0x26876, 0x1CEC04, 0x7D4833, 0x26533A, 0x4FB69D, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Gx: [0x22C6BB, 0x6015B6, 0x3FECEB, 0x4BD0D7, 0x5E83FF, 0xB0D8A, 0x45C6EB, 0x271D1F, 0x3905A1, 0x1F2EE9, 0xDA231, 0x4D607E, 0x38C4FA, 0x4D2AC, 0x65F5E5, 0x69D398, 0x17F1],
    CURVE_Gy: [0x45E7E1, 0x46528D, 0x1032A8, 0x144457, 0x4C744A, 0x7DBA07, 0x4B012C, 0x6D8C65, 0xAF600, 0x2BABA0, 0x73D782, 0x6C5727, 0xED741, 0x3413C6, 0x6AA83C, 0x7A40F1, 0x8B3],

    CURVE_Bnx: [0x10000, 0x0, 0x34804, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cof: [0xAAAB, 0x555600, 0x5A3002, 0x2AAF0A, 0x48C005, 0x72D, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cru: [0x7EFFFE, 0x7FFFFF, 0x8B807, 0x105000, 0x7D8136, 0x511BC2, 0x79BE25, 0x59D49D, 0x77EADD, 0xED41E, 0x69A718, 0x36728D, 0x72FDF7, 0xBE32C, 0x0, 0x0, 0x0],

    CURVE_Pxa: [0x21BDB8, 0x2D9182, 0x3F5201, 0x402DDF, 0x40326A, 0x2EE175, 0x1EB8F4, 0x2885B2, 0x3B02B4, 0x29F480, 0x1B91EB, 0x28828E, 0x5272DC, 0x24C100, 0x23C2A4, 0x515978, 0x24A],
    CURVE_Pxb: [0x42B7E, 0x7A0ABA, 0x5F96B1, 0x1CA2EA, 0x4F1121, 0x92669, 0x771FD4, 0x6D30DD, 0x361AB5, 0x213241, 0x65AF43, 0x3A7B2A, 0x3A0882, 0xFB59A, 0x1C67D8, 0x15B029, 0x13E0],
    CURVE_Pya: [0x382801, 0x290C11, 0x27864D, 0x5D6514, 0x2C9CC3, 0x259247, 0x545834, 0x214D34, 0x53A76D, 0x55197B, 0x37F66E, 0x71A8D5, 0x5C6DA2, 0x319939, 0x1F5B84, 0x6A93B9, 0xCE5],
    CURVE_Pyb: [0x5F79BE, 0xEBFE0, 0x6AAA4, 0x6760ED, 0x70D275, 0x3567E6, 0x55CBA6, 0x3A4955, 0x63AF26, 0x7D0B4E, 0x2CF8A1, 0x145CCE, 0x2B02BC, 0x6559A, 0x29CD33, 0x625017, 0x606],
    CURVE_W: [
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_SB: [
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ]
    ],
    CURVE_WB: [
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_BB: [
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ]
    ],

    USE_GLV: true,
    USE_GS_G2: true,
    USE_GS_GT: true,
    GT_STRONG: false,

    //debug: false,

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_BLS461 = {

    // BLS461 Curve
    // Base Bits= 23

    Curve_Cof_I : 0,
    CURVE_A: 0,
    CURVE_B_I: 9,
    CURVE_B: [0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0x1, 0x0, 0x700000, 0x7F7FFF, 0x7FEFF, 0x22000, 0x7F2000, 0x7E00BF, 0xE801, 0x40BFA0, 0x5FF, 0x7FE00C, 0x7FFF7F, 0x1FF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Gx: [0x5EE93D, 0x4D515, 0x504534, 0x773A5B, 0x2D9C00, 0x6358FE, 0x6606D4, 0x4114E1, 0x4DC921, 0x21A6AC, 0x282599, 0x7BE149, 0x436166, 0x45632E, 0x1A2FA4, 0x38967B, 0xC8132, 0x476E74, 0x3A66D1, 0x56873A, 0x0],
    CURVE_Gy: [0x51D465, 0x462AF5, 0x51C3DD, 0x64627F, 0x517884, 0x71A42B, 0x6799A, 0x2CE854, 0x245F49, 0x15CB86, 0x2E1244, 0x45FD20, 0x16EECB, 0x3F197D, 0x3322FE, 0x1793BD, 0x5F1C3F, 0x3ED192, 0x452CC1, 0x3BDE6D, 0x0],

    CURVE_Bnx: [0x0, 0x7FFC00, 0x7FFFEF, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cof: [0x2AAAAB, 0x7FFD55, 0x5AAA9F, 0x5580AA, 0x7D55AA, 0x2A9FFF, 0x5555, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cru: [0x7FFFFE, 0x3FF, 0x10, 0x7FFF00, 0x7FFE7F, 0x61FFED, 0x311F, 0x630239, 0x6DB7BC, 0x622AF2, 0x73D1DD, 0x43AA19, 0x3F0E89, 0xA04C2, 0x581400, 0x7F5FFF, 0x1FFFF, 0x0, 0x0, 0x0, 0x0],
    CURVE_Pxa: [0x50A37C, 0x20630D, 0x31196D, 0x173AEE, 0x1C2E49, 0x2D0F15, 0x7E467, 0x7AB270, 0x74FF92, 0x610DB6, 0x19A00F, 0x36AC0D, 0x6D78D4, 0x78520F, 0x224BE5, 0x1E1386, 0x767945, 0x4A1535, 0x4E281A, 0x662A0, 0x1],
    CURVE_Pxb: [0x41C0AD, 0x395185, 0x37A7E1, 0x6212E5, 0x16CD66, 0x4512C1, 0x4A546, 0x200D63, 0x3EBEE2, 0x7AA535, 0x7D96C5, 0x504E99, 0x45AF5B, 0x6E3DA9, 0x4B9350, 0x123533, 0x2279D2, 0x1D46F9, 0x53F96B, 0x4AE0FD, 0x0],
    CURVE_Pya: [0x2FB006, 0x218360, 0xCDF33, 0x525095, 0x53D194, 0x125912, 0x5833F3, 0x6345A4, 0xF39F, 0x1E7536, 0x7B46E8, 0x3EDDE2, 0x4DFD8A, 0x5EF53, 0x3489F3, 0x7A739F, 0x6070F4, 0x74FCCE, 0x1239FA, 0x113564, 0x0],
    CURVE_Pyb: [0x71457C, 0xD5BFB, 0x2A294, 0x6E0261, 0x4D6A31, 0x6DC7F6, 0x26A3C4, 0x2B3475, 0x64492F, 0x2E7877, 0x19E84A, 0x25F55D, 0x220BE7, 0x5C70AD, 0x7C1310, 0x228AB, 0x2AB1D0, 0x6805D4, 0x6D3EAE, 0x71C080, 0x0],
    CURVE_W: [
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_SB: [
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ]
    ],
    CURVE_WB: [
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_BB: [
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ]
    ],

    USE_GLV: true,
    USE_GS_G2: true,
    USE_GS_GT: true,
    GT_STRONG: false,

    //debug: false,

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_FP256BN = {

    // FP256BN Curve
    // Base Bits= 24

    Curve_Cof_I : 1,
    CURVE_A: 0,
    CURVE_B_I: 3,
    CURVE_B: [0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0xB500D, 0x536CD1, 0x1AF62D, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
    CURVE_Gx: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Gy: [0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],

    CURVE_Bnx: [0xB0A801, 0xF5C030, 0x6882, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cof: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cru: [0xA1B807, 0xA24A3, 0x1EDB1C, 0xF1932D, 0xCDD79D, 0x18659B, 0x409210, 0x3988E1, 0x1, 0x0, 0x0],
    CURVE_Pxa: [0xC09EFB, 0x16B689, 0x3CD226, 0x12BF84, 0x1C539A, 0x913ACE, 0x577C28, 0x28560F, 0xC96C20, 0x3350B4, 0xFE0C],
    CURVE_Pxb: [0x7E6A2B, 0xED34A3, 0x89D269, 0x87D035, 0xDD78E2, 0x13B924, 0xC637D8, 0xDB5AE1, 0x8AC054, 0x605773, 0x4EA6],
    CURVE_Pya: [0xDC27FF, 0xB481BE, 0x48E909, 0x8D6158, 0xCB2475, 0x3E51EF, 0x75124E, 0x76770D, 0x42A3B3, 0x46E7C5, 0x7020],
    CURVE_Pyb: [0xAD049B, 0x81114A, 0xB3E012, 0x821A98, 0x4CBE80, 0xB29F8B, 0x49297E, 0x42EEA6, 0x88C290, 0xE3BCD3, 0x554],

    CURVE_W: [
        [0x54003, 0x36E1B, 0x663AF0, 0xFFFE78, 0xFFFFFF, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x615001, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_SB: [
        [
            [0x669004, 0xEEEE7C, 0x670BF5, 0xFFFE78, 0xFFFFFF, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x615001, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x615001, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x6100A, 0x4FFEB6, 0xB4BB3D, 0x129B19, 0xDC65FB, 0xA49D0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF]
        ]
    ],
    CURVE_WB: [
        [0x30A800, 0x678F0D, 0xCC1020, 0x5554D2, 0x555555, 0x55, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x7DC805, 0x764C0D, 0xAD1AD6, 0xA10BC3, 0xDE8FBE, 0x104467, 0x806160, 0xD105EB, 0x0, 0x0, 0x0],
        [0x173803, 0xB6061F, 0xD6C1AC, 0x5085E1, 0xEF47DF, 0x82233, 0xC030B0, 0x6882F5, 0x0, 0x0, 0x0],
        [0x91F801, 0x530F6E, 0xCCE126, 0x5554D2, 0x555555, 0x55, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_BB: [
        [
            [0x5AA80D, 0x5DACA0, 0x1A8DAA, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
            [0x5AA80C, 0x5DACA0, 0x1A8DAA, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
            [0x5AA80C, 0x5DACA0, 0x1A8DAA, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
            [0x615002, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x615001, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x5AA80C, 0x5DACA0, 0x1A8DAA, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
            [0x5AA80D, 0x5DACA0, 0x1A8DAA, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
            [0x5AA80C, 0x5DACA0, 0x1A8DAA, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF]
        ],
        [
            [0x615002, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x615001, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x615001, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x615001, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0xB0A802, 0xF5C030, 0x6882, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0xC2A002, 0xD700C2, 0x1A20B, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0xAA000A, 0x67EC6F, 0x1A2527, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
            [0xB0A802, 0xF5C030, 0x6882, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ]
    ],

    USE_GLV: true,
    USE_GS_G2: true,
    USE_GS_GT: true,
    GT_STRONG: false,

    //debug: false,

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_FP512BN = {

    // FP512BN Curve

    // Base Bits= 23


    Curve_Cof_I : 1,
    CURVE_A: 0,
    CURVE_B_I: 3,
    CURVE_B: [0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0x1A09ED, 0x14BEA3, 0x501A99, 0x27CD15, 0x313E0, 0x346942, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
    CURVE_Gx: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Gy: [0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],

    CURVE_Bnx: [0x1BD80F, 0xD76BC, 0x4042CC, 0x587BF, 0x2F5C03, 0xD10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cof: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cru: [0x79298A, 0x2C4138, 0x52C1C, 0x5C58BE, 0x6E6799, 0x1255D9, 0x2F9498, 0x43C4B3, 0x507ACD, 0x11384E, 0x1D2C80, 0x8FD18, 0x78EF76, 0x71D459, 0x2E1ACD, 0x1530A3, 0x7DC83D, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
    CURVE_Pxa: [0x3646B5, 0x52DC1B, 0x7A3C1E, 0x48397F, 0xF8731, 0x71E443, 0x6F2EF1, 0x2BDF10, 0x4DC6DC, 0x70C6A2, 0x40914D, 0x3C6685, 0x5A57CC, 0x3736AF, 0x4D63C3, 0x5DE94D, 0x6A1E4B, 0x25E79, 0x6E9D, 0x244AC4, 0x1E1386, 0x62CA67, 0xE],
    CURVE_Pxb: [0xAE0E9, 0x17DFB5, 0x6CF6D7, 0x6C4488, 0x4A411C, 0x5B9C81, 0x4E0F56, 0x286B70, 0x6E0D5E, 0x650AA4, 0x607889, 0x5CA6CB, 0x302566, 0x48ED51, 0x1B1BBC, 0x532B6E, 0x34825E, 0x157D1, 0x6D311A, 0x3F3644, 0x3F8506, 0x38279, 0x12],
    CURVE_Pya: [0x5E67A1, 0x6255B, 0x178920, 0xAF7DC, 0x217AD6, 0x778B9B, 0xA022D, 0x11892A, 0x3E8EDD, 0x7BD82A, 0x5B3462, 0x34CEA5, 0x65C158, 0x1BA07D, 0x5982BF, 0x42D8EF, 0x4F2770, 0x19746E, 0x3BD6AC, 0x3DC149, 0x4C827C, 0x603D90, 0x1B],
    CURVE_Pyb: [0x4F8E8B, 0x630D90, 0x5A162D, 0x25FBB0, 0x5C222, 0x11BFE, 0x7B89E7, 0x18856B, 0x714A4, 0x7C5CA, 0xA25FF, 0xCA0ED, 0x3D0496, 0x61936C, 0x46219E, 0xA1C60, 0x591F02, 0x62BEEB, 0xD9030, 0x3C18D6, 0x48B04E, 0x34779D, 0x14],
    CURVE_W: [
        [0x34583, 0x712E93, 0x4FC443, 0x68B50B, 0x5FB911, 0x47FD2C, 0x7FFF3D, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x37B01F, 0x1AED78, 0x8598, 0xB0F7F, 0x5EB806, 0x1A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_SB: [
        [
            [0x4B9564, 0x56411A, 0x4F3EAB, 0x5DA58C, 0x1010B, 0x47E30C, 0x7FFF3D, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x6259CE, 0x79D12A, 0x4F9500, 0x1CBD96, 0x245BDA, 0x344F21, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F]
        ],
        [
            [0x37B01F, 0x1AED78, 0x8598, 0xB0F7F, 0x5EB806, 0x1A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x34583, 0x712E93, 0x4FC443, 0x68B50B, 0x5FB911, 0x47FD2C, 0x7FFF3D, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ]
    ],
    CURVE_WB: [
        [0x5A29F0, 0x66D56A, 0x305B6A, 0x2C1E98, 0x442C60, 0x42BF7F, 0x555514, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x355D4B, 0x25744, 0x45FBAC, 0x6BFC27, 0x20FC1F, 0x6BCB9E, 0x2778AE, 0x2C497D, 0x5AD40F, 0x72C0C9, 0x4549D2, 0x29A8B1, 0x576BC3, 0x42CC1, 0x587BF8, 0x75C030, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x289AAD, 0x7E700, 0x431F3C, 0x38C1F3, 0x282C11, 0x35EC57, 0x53BC57, 0x5624BE, 0x6D6A07, 0x396064, 0x62A4E9, 0x54D458, 0x6BB5E1, 0x21660, 0x2C3DFC, 0x7AE018, 0x6882, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x2279D1, 0x4BE7F2, 0x2FD5D2, 0x210F19, 0x65745A, 0x42A55E, 0x555514, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_BB: [
        [
            [0x1BD810, 0xD76BC, 0x4042CC, 0x587BF, 0x2F5C03, 0xD10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x1BD80F, 0xD76BC, 0x4042CC, 0x587BF, 0x2F5C03, 0xD10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x1BD80F, 0xD76BC, 0x4042CC, 0x587BF, 0x2F5C03, 0xD10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x6259CF, 0x79D12A, 0x4F9500, 0x1CBD96, 0x245BDA, 0x344F21, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F]
        ],
        [
            [0x37B01F, 0x1AED78, 0x8598, 0xB0F7F, 0x5EB806, 0x1A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x7E31DE, 0x747E6, 0xFD7CD, 0x224556, 0x53B7DD, 0x345C31, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
            [0x7E31DD, 0x747E6, 0xFD7CD, 0x224556, 0x53B7DD, 0x345C31, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
            [0x7E31DE, 0x747E6, 0xFD7CD, 0x224556, 0x53B7DD, 0x345C31, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F]
        ],
        [
            [0x37B01E, 0x1AED78, 0x8598, 0xB0F7F, 0x5EB806, 0x1A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x37B01F, 0x1AED78, 0x8598, 0xB0F7F, 0x5EB806, 0x1A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x37B01F, 0x1AED78, 0x8598, 0xB0F7F, 0x5EB806, 0x1A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x37B01F, 0x1AED78, 0x8598, 0xB0F7F, 0x5EB806, 0x1A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x7E31DF, 0x0747E6, 0x0FD7CD, 0x224556, 0x53B7DD, 0x345C31, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
            [0x2AA9AF, 0x5EE3B2, 0x4F0F68, 0x11AE17, 0x45A3D4, 0x343500, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
            [0x37B01D, 0x1AED78, 0x008598, 0x0B0F7F, 0x5EB806, 0x001A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x7E31DF, 0x0747E6, 0x0FD7CD, 0x224556, 0x53B7DD, 0x345C31, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F]
        ]
    ],

    USE_GLV: true,
    USE_GS_G2: true,
    USE_GS_GT: true,
    GT_STRONG: false,

    //debug: false,

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_BN254 = {

    // BN254 Curve

    // Base Bits= 24

    Curve_Cof_I : 1,
    CURVE_A: 0,
    CURVE_B_I: 2,
    CURVE_B: [0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0xD, 0x0, 0x10A100, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
    CURVE_Gx: [0x12, 0x0, 0x13A700, 0x0, 0x210000, 0x861, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
    CURVE_Gy: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],

    CURVE_Bnx: [0x1, 0x0, 0x4080, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cof: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cru: [0x7, 0x0, 0x6CD80, 0x0, 0x90000, 0x249, 0x400000, 0x49B362, 0x0, 0x0, 0x0],
    CURVE_Pxa: [0x3FB2B, 0x4224C8, 0xD91EE, 0x4898BF, 0x648BBB, 0xEDB6A4, 0x7E8C61, 0xEB8D8C, 0x9EB62F, 0x10BB51, 0x61A],
    CURVE_Pxb: [0xD54CF3, 0x34C1E7, 0xB70D8C, 0xAE3784, 0x4D746B, 0xAA5B1F, 0x8C5982, 0x310AA7, 0x737833, 0xAAF9BA, 0x516],
    CURVE_Pya: [0xCD2B9A, 0xE07891, 0xBD19F0, 0xBDBE09, 0xBD0AE6, 0x822329, 0x96698C, 0x9A90E0, 0xAF9343, 0x97A06B, 0x218],
    CURVE_Pyb: [0x3ACE9B, 0x1AEC6B, 0x578A2D, 0xD739C9, 0x9006FF, 0x8D37B0, 0x56F5F3, 0x8F6D44, 0x8B1526, 0x2B0E7C, 0xEBB],
    CURVE_W: [
        [0x3, 0x0, 0x20400, 0x0, 0x818000, 0x61, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_SB: [
        [
            [0x4, 0x0, 0x28500, 0x0, 0x818000, 0x61, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0xA, 0x0, 0xE9D00, 0x0, 0x1E0000, 0x79E, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523]
        ]
    ],
    CURVE_WB: [
        [0x0, 0x0, 0x4080, 0x0, 0x808000, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x5, 0x0, 0x54A80, 0x0, 0x70000, 0x1C7, 0x800000, 0x312241, 0x0, 0x0, 0x0],
        [0x3, 0x0, 0x2C580, 0x0, 0x838000, 0xE3, 0xC00000, 0x189120, 0x0, 0x0, 0x0],
        [0x1, 0x0, 0xC180, 0x0, 0x808000, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_BB: [
        [
            [0xD, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
            [0xC, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
            [0xC, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
            [0x2, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0xC, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
            [0xD, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
            [0xC, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523]
        ],
        [
            [0x2, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x2, 0x0, 0x4080, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x2, 0x0, 0x10200, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0xA, 0x0, 0x102000, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
            [0x2, 0x0, 0x4080, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ]
    ],

    USE_GLV: true,
    USE_GS_G2: true,
    USE_GS_GT: true,
    GT_STRONG: false,

    //debug: false,
};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_BN254CX = {

    // BN254CX Curve
    // Base Bits= 24

    Curve_Cof_I : 1,
    CURVE_A: 0,
    CURVE_B_I: 2,
    CURVE_B: [0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0xEB1F6D, 0xC0A636, 0xCEBE11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
    CURVE_Gx: [0x1B55B2, 0x23EF5C, 0xE1BE66, 0x18093E, 0x3FD6EE, 0x66D324, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
    CURVE_Gy: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],

    CURVE_Bnx: [0xC012B1, 0x3, 0x4000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cof: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Cru: [0x235C97, 0x931794, 0x5631E0, 0x71EF87, 0xBDDF64, 0x3F1440, 0xCA8, 0x480000, 0x0, 0x0, 0x0],

    CURVE_Pxa: [0xD2EC74,0x1CEEE4,0x26C085,0xA03E27,0x7C85BF,0x4BBB90,0xF5C3,0x358B25,0x53B256,0x2D2C70,0x1968],
    CURVE_Pxb: [0x29CFE1,0x8E8B2E,0xF47A5,0xC209C3,0x1B97B0,0x9743F8,0x37A8E9,0xA011C9,0x19F64A,0xB9EC3E,0x1466],
    CURVE_Pya: [0xBE09F,0xFCEBCF,0xB30CFB,0x847EC1,0x61B33D,0xE20963,0x157DAE,0xD81E22,0x332B8D,0xEDD972,0xA79],
    CURVE_Pyb: [0x98EE9D,0x4B2288,0xEBED90,0x69D2ED,0x864EA5,0x3461C2,0x512D8D,0x35C6E4,0xC4C090,0xC39EC,0x616],


    CURVE_W: [
        [0x2FEB83, 0x634916, 0x120054, 0xB4038, 0x0, 0x60, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_SB: [
        [
            [0xB010E4, 0x63491D, 0x128054, 0xB4038, 0x0, 0x60, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0xBB33EA, 0x5D5D20, 0xBCBDBD, 0x188CE, 0x3FD6EE, 0x66D264, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400]
        ]
    ],
    CURVE_WB: [
        [0x7A84B0, 0x211856, 0xB0401C, 0x3C012, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0],
        [0x220475, 0xF995BE, 0x9A36CD, 0xA8CA7F, 0x7E94ED, 0x2A0DC0, 0x870, 0x300000, 0x0, 0x0, 0x0],
        [0xF10B93, 0xFCCAE0, 0xCD3B66, 0xD4653F, 0x3F4A76, 0x1506E0, 0x438, 0x180000, 0x0, 0x0, 0x0],
        [0xFAAA11, 0x21185D, 0xB0C01C, 0x3C012, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0]
    ],
    CURVE_BB: [
        [
            [0x2B0CBD, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
            [0x2B0CBC, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
            [0x2B0CBC, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
            [0x802562, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x2B0CBC, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
            [0x2B0CBD, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
            [0x2B0CBC, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400]
        ],
        [
            [0x802562, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        [
            [0xC012B2, 0x3, 0x4000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x4AC2, 0xF, 0x10000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x6AFA0A, 0xC0A62F, 0xCE3E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
            [0xC012B2, 0x3, 0x4000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ]
    ],

    USE_GLV: true,
    USE_GS_G2: true,
    USE_GS_GT: true,
    GT_STRONG: false,

    //debug: false,

};


/* Fixed Data in ROM - Field and Curve parameters */

/* Note that the original curve has been transformed to an isomorphic curve with A=-3 */


ROM_CURVE_BRAINPOOL = {

    // Brainpool curve
    // Base Bits= 24

    Curve_Cof_I : 1,
    CURVE_A: -3,
    CURVE_B_I: 0,
    CURVE_B: [0xE92B04, 0x8101FE, 0x256AE5, 0xAF2F49, 0x93EBC4, 0x76B7BF, 0x733D0B, 0xFE66A7, 0xD84EA4, 0x61C430, 0x662C],
    CURVE_Order: [0x4856A7, 0xE8297, 0xF7901E, 0xB561A6, 0x397AA3, 0x8D718C, 0x909D83, 0x3E660A, 0xEEA9BC, 0x57DBA1, 0xA9FB],
    CURVE_Gx: [0x1305F4, 0x91562E, 0x2B79A1, 0x7AAFBC, 0xA142C4, 0x6149AF, 0xB23A65, 0x732213, 0xCFE7B7, 0xEB3CC1, 0xA3E8],
    CURVE_Gy: [0x25C9BE, 0xE8F35B, 0x1DAB, 0x39D027, 0xBCB6DE, 0x417E69, 0xE14644, 0x7F7B22, 0x39C56D, 0x6C8234, 0x2D99],
};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_C25519 = {

    // C25519 Curve

    Curve_Cof_I : 8,
    CURVE_A: 486662,
    CURVE_B_I: 0,
    CURVE_B: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0xF5D3ED, 0x631A5C, 0xD65812, 0xA2F79C, 0xDEF9DE, 0x14, 0x0, 0x0, 0x0, 0x0, 0x1000],
    CURVE_Gx: [0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Gy: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_C41417 = {

    // C41417 curve
    Curve_Cof_I : 8,
    CURVE_A: 1,
    CURVE_B_I: 3617,
    CURVE_B: [0xE21, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0x6AF79, 0x69784, 0x1B0E7, 0x18F3C6, 0x338AD, 0xDBC70, 0x6022B, 0x533DC, 0x3CC924, 0x3FFFAC, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x7FFF],
    CURVE_Gx: [0xBC595, 0x204BCF, 0xC4FD3, 0x14DF19, 0x33FAA8, 0x4C069, 0x16BA11, 0x2AD35B, 0x1498A4, 0x15FFCD, 0x3EC7F, 0x27D130, 0xD4636, 0x9B97F, 0x631C3, 0x8630, 0x144330, 0x241450, 0x1A334],
    CURVE_Gy: [0x22, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_ED25519 = {

    // ED25519 Curve

    Curve_Cof_I : 8,
    CURVE_A: -1,
    CURVE_B_I: 0,
    CURVE_B: [0x5978A3, 0x4DCA13, 0xAB75EB, 0x4141D8, 0x700A4D, 0xE89800, 0x797779, 0x8CC740, 0x6FFE73, 0x6CEE2B, 0x5203],
    CURVE_Order: [0xF5D3ED, 0x631A5C, 0xD65812, 0xA2F79C, 0xDEF9DE, 0x14, 0x0, 0x0, 0x0, 0x0, 0x1000],
    CURVE_Gx: [0x25D51A, 0x2D608F, 0xB2C956, 0x9525A7, 0x2CC760, 0xDC5C69, 0x31FDD6, 0xC0A4E2, 0x6E53FE, 0x36D3CD, 0x2169],
    CURVE_Gy: [0x666658, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x6666],


};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_GOLDILOCKS = {

    // GOLDILOCKS curve
    Curve_Cof_I : 4,
    CURVE_A: 1,
    CURVE_B_I: -39081,
    CURVE_B: [0x7F6756, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7DFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FF],
    CURVE_Order: [0x5844F3, 0x52556, 0x548DE3, 0x6E2C7A, 0x4C2728, 0x52042D, 0x6BB58D, 0x276DA4, 0x23E9C4, 0x7EF994, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x1FF],
    CURVE_Gx: [0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x52AAAA, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555],
    CURVE_Gy: [0x1386ED, 0x779BD5, 0x2F6BAB, 0xE6D03, 0x4B2BED, 0x131777, 0x4E8A8C, 0x32B2C1, 0x44B80D, 0x6515B1, 0x5F8DB5, 0x426EBD, 0x7A0358, 0x6DDA, 0x21B0AC, 0x6B1028, 0xDB359, 0x15AE09, 0x17A58D, 0x570],
};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_HIFIVE = {

    // HIFIVE curve

    Curve_Cof_I : 8,
    CURVE_A: 1,
    CURVE_B_I: 11111,
    CURVE_B: [0x2B67, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0x1FA805, 0x2B2E7D, 0x29ECBE, 0x3FC9DD, 0xBD6B8, 0x530A18, 0x45057E, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x800],
    CURVE_Gx: [0xC, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Gy: [0x7E8632, 0xD0A0B, 0x6C4AFB, 0x501B2E, 0x55650C, 0x36DB6B, 0x1FBD0D, 0x61C08E, 0x314B46, 0x70A7A3, 0x587401, 0xC70E0, 0x56502E, 0x38C2D6, 0x303],

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_NIST256 = {

    // NIST256 Curve
    Curve_Cof_I : 1,
    CURVE_A: -3,
    CURVE_B_I: 0,
    CURVE_B: [0xD2604B, 0x3C3E27, 0xF63BCE, 0xCC53B0, 0x1D06B0, 0x86BC65, 0x557698, 0xB3EBBD, 0x3A93E7, 0x35D8AA, 0x5AC6],
    CURVE_Order: [0x632551, 0xCAC2FC, 0x84F3B9, 0xA7179E, 0xE6FAAD, 0xFFFFBC, 0xFFFFFF, 0xFFFFFF, 0x0, 0xFFFF00, 0xFFFF],
    CURVE_Gx: [0x98C296, 0x3945D8, 0xA0F4A1, 0x2DEB33, 0x37D81, 0x40F277, 0xE563A4, 0xF8BCE6, 0x2C4247, 0xD1F2E1, 0x6B17],
    CURVE_Gy: [0xBF51F5, 0x406837, 0xCECBB6, 0x6B315E, 0xCE3357, 0x9E162B, 0x4A7C0F, 0x8EE7EB, 0x1A7F9B, 0x42E2FE, 0x4FE3],

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_NIST384 = {

    // NIST384 curve
    Curve_Cof_I : 1,
    CURVE_A: -3,
    CURVE_B_I: 0,
    CURVE_B: [0x6C2AEF, 0x11DBA7, 0x74AA17, 0x51768C, 0x6398D8, 0x6B58CA, 0x5404E1, 0xA0447, 0x411203, 0x5DFD02, 0x607671, 0x4168C8, 0x56BE3F, 0x1311C0, 0xFB9F9, 0x17D3F1, 0xB331],
    CURVE_Order: [0x452973, 0x32D599, 0x6BB3B0, 0x45853B, 0x20DB24, 0x3BEB03, 0x7D0DCB, 0x31A6C0, 0x7FFFC7, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
    CURVE_Gx: [0x760AB7, 0x3C70E4, 0x30E951, 0x7AA94B, 0x2F25DB, 0x470AA0, 0x20950A, 0x7BA0F0, 0x1B9859, 0x45174F, 0x3874ED, 0x56BA3, 0x71EF32, 0x71D638, 0x22C14D, 0x65115F, 0xAA87],
    CURVE_Gy: [0x6A0E5F, 0x3AF921, 0x75E90C, 0x6BF40C, 0xB1CE1, 0x18014C, 0x6D7C2E, 0x6D1889, 0x147CE9, 0x7A5134, 0x63D076, 0x16E14F, 0xBF929, 0x6BB3D3, 0x98B1B, 0x6F254B, 0x3617],
};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_NIST521 = {

    // NIST521 curve

    Curve_Cof_I : 1,
    CURVE_A: -3,
    CURVE_B_I: 0,
    CURVE_B: [0x503F00, 0x3FA8D6, 0x47BD14, 0x6961A7, 0x3DF883, 0x60E6AE, 0x4EEC6F, 0x29605E, 0x137B16, 0x23D8FD, 0x5864E5, 0x84F0A, 0x1918EF, 0x771691, 0x6CC57C, 0x392DCC, 0x6EA2DA, 0x6D0A81, 0x688682, 0x50FC94, 0x18E1C9, 0x27D72C, 0x1465],
    CURVE_Order: [0x386409, 0x6E3D22, 0x3AEDBE, 0x4CE23D, 0x5C9B88, 0x3A0776, 0x3DC269, 0x6600A4, 0x166B7F, 0x77E5F, 0x461A1E, 0x7FFFD2, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFF],
    CURVE_Gx: [0x65BD66, 0x7C6385, 0x6FE5F9, 0x2B5214, 0xB3C18, 0x1BC669, 0x68BFEA, 0xEE093, 0x5928FE, 0x6FDFCE, 0x52D79, 0x69EDD5, 0x7606B4, 0x3F0515, 0x4FED48, 0x409C82, 0x429C64, 0x472B68, 0x7B2D98, 0x4E6CF1, 0x70404E, 0x31C0D6, 0x31A1],
    CURVE_Gy: [0x516650, 0x28ED3F, 0x222FA, 0x139612, 0x47086A, 0x6C26A7, 0x4FEB41, 0x285C80, 0x2640C5, 0x32BDE8, 0x5FB9CA, 0x733164, 0x517273, 0x2F5F7, 0x66D11A, 0x2224AB, 0x5998F5, 0x58FA37, 0x297ED0, 0x22E4, 0x9A3BC, 0x252D4F, 0x460E],
};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_NUMS256E = {

    // NUMS256E Curve
    Curve_Cof_I : 4,
    CURVE_A: 1,
    CURVE_B_I: -15342,
    CURVE_B: [0xFFC355, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFF],
    CURVE_Order: [0xDD4AF5, 0xB190EE, 0x9B1A47, 0x2F5943, 0x955AA5, 0x41, 0x0, 0x0, 0x0, 0x0, 0x4000],
    CURVE_Gx: [0xED13DA, 0xC0902E, 0x86A0DE, 0xE30835, 0x398A0E, 0x9BD60C, 0x5F6920, 0xCD1E3D, 0xEA237D, 0x14FB6A, 0x8A75],
    CURVE_Gy: [0x8A89E6, 0x16E779, 0xD32FA6, 0x10856E, 0x5F61D8, 0x801071, 0xD9A64B, 0xCE9665, 0xD925C7, 0x3E9FD9, 0x44D5],


};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_NUMS256W = {

    // NUMS256W Curve
    Curve_Cof_I : 1,
    CURVE_A: -3,
    CURVE_B_I: 152961,
    CURVE_B: [0x25581, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0x51A825, 0x202947, 0x6020AB, 0xEA265C, 0x3C8275, 0xFFFFE4, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFF],
    CURVE_Gx: [0x1AACB1, 0xEE1EB2, 0x3ABC52, 0x3D4C7, 0x579B09, 0xCB0983, 0xA04F42, 0x297A95, 0xAADB61, 0xD6B65A, 0xBC9E],
    CURVE_Gy: [0x84DE9F, 0xB9CB21, 0xBB80B5, 0x15310F, 0x55C3D1, 0xE035C9, 0xF77E04, 0x73448B, 0x99B6A6, 0xC0F133, 0xD08F],


};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_NUMS384E = {

    // NUMS384E Curve
    Curve_Cof_I : 4,
    CURVE_A: 1,
    CURVE_B_I: -11556,
    CURVE_B: [0x7FD19F, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
    CURVE_Order: [0x23897D, 0x3989CD, 0x6482E7, 0x59AE43, 0x4555AA, 0x39EC3C, 0x2D1AF8, 0x238D0E, 0x7FFFE2, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3FFF],
    CURVE_Gx: [0x206BDE, 0x1C8D8, 0x4D4355, 0x2A2CA0, 0x292B16, 0x680DFE, 0x3CCC58, 0x31FFD4, 0x4C0057, 0xDCB7C, 0x4C2FD1, 0x2AEDAD, 0x2129AE, 0x1816D4, 0x6A499B, 0x8FDA2, 0x61B1],
    CURVE_Gy: [0x729392, 0x7C3E0, 0x727634, 0x376246, 0x2B0F94, 0x49600E, 0x7D9165, 0x7CC7B, 0x5F5683, 0x69E284, 0x5AB609, 0x86EB8, 0x1A423B, 0x10E716, 0x69BBAC, 0x1F33DC, 0x8298],

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_NUMS384W = {

    // NUMS384W Curve
    Curve_Cof_I : 1,
    CURVE_A: -3,
    CURVE_B_I: -34568,
    CURVE_B: [0x7F77BB, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
    CURVE_Order: [0xE61B9, 0x3ECF6, 0x698136, 0x61BF13, 0x29D3D4, 0x1037DB, 0x3AD75A, 0xF578F, 0x7FFFD6, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
    CURVE_Gx: [0x18152A, 0x740841, 0x6FAE72, 0x7B0E23, 0x6ED100, 0x684A45, 0x4A9B31, 0x5E948D, 0x79F4F3, 0x1BF703, 0x89707, 0x2F8D30, 0x222410, 0x91019, 0x5BC607, 0x2B7858, 0x7579],
    CURVE_Gy: [0x180716, 0x71D8CC, 0x1971D2, 0x7FA569, 0x6B4DBB, 0x6FD79A, 0x4486A0, 0x1041BE, 0x739CB9, 0x6FF0FE, 0x4011A5, 0x267BF5, 0x530058, 0x1AFC67, 0x66E38E, 0x71B470, 0xACDE],


};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_NUMS512E = {

    // NUMS512E Curve
    Curve_Cof_I : 4,
    CURVE_A: 1,
    CURVE_B_I: -78296,
    CURVE_B: [0x7ECBEF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
    CURVE_Order: [0x6ED46D, 0x19EA37, 0x7D9D1A, 0x6F7F67, 0x605786, 0x5EA548, 0x5C2DA1, 0x1FEC64, 0x11BA9E, 0x5A5F9F, 0x53C18D, 0x7FFFFD, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xF],
    CURVE_Gx: [0x6C57FE, 0x565333, 0x5716E6, 0x662780, 0x525427, 0x15A1FC, 0x15A241, 0x5EE4C9, 0x730F78, 0x1DDC8C, 0x188705, 0x5C0A3A, 0x6BE273, 0x44F42F, 0x7128E0, 0x73CFA6, 0x332FD1, 0x11A78A, 0x632DE2, 0x34E3D0, 0x5128DB, 0x71C62D, 0x37],
    CURVE_Gy: [0x62F5E1, 0x3D8183, 0x7CC9B7, 0x5F8E80, 0x6D38A9, 0x3FA04C, 0xABB30, 0xD0343, 0x356260, 0x65D32C, 0x3294F, 0x741A09, 0x395909, 0x55256D, 0x96748, 0x7B936C, 0x6EE476, 0x50544A, 0x43D5DE, 0x538CC5, 0x39D49C, 0x2137FE, 0x1B],

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_NUMS512W = {

    // NUMS512W Curve
    Curve_Cof_I : 1,
    CURVE_A: -3,
    CURVE_B_I: 121243,
    CURVE_B: [0x1D99B, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0x33555D, 0x7E7208, 0xF3854, 0x3E692, 0x68B366, 0x38C76A, 0x65F42F, 0x612C76, 0x31B4F, 0x7729CF, 0x6CF293, 0x7FFFFA, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
    CURVE_Gx: [0x2BAE57, 0xF2B19, 0xB720A, 0x6B7AEF, 0x560137, 0x3063AB, 0x95585, 0x3CA143, 0x359E93, 0x220ED6, 0x408685, 0x36CFCA, 0xC2530, 0x28A0DC, 0x407DA1, 0x6C1DDA, 0x5298CA, 0x407A76, 0x2DC00A, 0x549ED1, 0x7141D0, 0x580688, 0xE],
    CURVE_Gy: [0x3527A6, 0xEC070, 0x248E82, 0x67E87F, 0x35C1E4, 0x4059E5, 0x2C9695, 0x10D420, 0x6DE9C1, 0x35161D, 0xA1057, 0xA78A5, 0x60C7BD, 0x11E964, 0x6F2EE3, 0x6DEF55, 0x4B97, 0x47D762, 0x3BBB71, 0x359E70, 0x229AD5, 0x74A99, 0x25],

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_CURVE_SECP256K1 = {

    // SECP256K1 Curve
    // Base Bits= 24

    CURVE_Cof_I: 1,
    CURVE_A: 0,
    CURVE_B_I: 7,
    CURVE_B: [0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    CURVE_Order: [0x364141, 0x5E8CD0, 0x3BBFD2, 0xAF48A0, 0xAEDCE6, 0xFFFEBA, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFF],
    CURVE_Gx: [0xF81798, 0x815B16, 0xD959F2, 0x2DCE28, 0x9BFCDB, 0xB0702, 0x95CE87, 0x55A062, 0xDCBBAC, 0x667EF9, 0x79BE],
    CURVE_Gy: [0x10D4B8, 0xD08FFB, 0x199C47, 0xA68554, 0x17B448, 0x8A8FD, 0xFC0E11, 0x5DA4FB, 0xA3C465, 0xDA7726, 0x483A],

};

var ROM_CURVE = {
    "ANSSI": ROM_CURVE_ANSSI,
    "BLS383": ROM_CURVE_BLS383,
    "BLS24": ROM_CURVE_BLS24,
    "BLS48": ROM_CURVE_BLS48,
    "BLS381": ROM_CURVE_BLS381,
    "BLS461": ROM_CURVE_BLS461,
    "FP256BN": ROM_CURVE_FP256BN,
    "FP512BN": ROM_CURVE_FP512BN,
    "BN254": ROM_CURVE_BN254,
    "BN254CX": ROM_CURVE_BN254CX,
    "BRAINPOOL": ROM_CURVE_BRAINPOOL,
    "C25519": ROM_CURVE_C25519,
    "C41417": ROM_CURVE_C41417,
    "ED25519": ROM_CURVE_ED25519,
    "GOLDILOCKS": ROM_CURVE_GOLDILOCKS,
    "HIFIVE": ROM_CURVE_HIFIVE,
    "NIST256": ROM_CURVE_NIST256,
    "NIST384": ROM_CURVE_NIST384,
    "NIST521": ROM_CURVE_NIST521,
    "NUMS256E": ROM_CURVE_NUMS256E,
    "NUMS256W": ROM_CURVE_NUMS256W,
    "NUMS384E": ROM_CURVE_NUMS384E,
    "NUMS384W": ROM_CURVE_NUMS384W,
    "NUMS512E": ROM_CURVE_NUMS512E,
    "NUMS512W": ROM_CURVE_NUMS512W,
    "SECP256K1": ROM_CURVE_SECP256K1
};

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* Fixed Data in ROM - Field and Curve parameters */

var ROM_FIELD_25519,
    ROM_FIELD_256PM,
    ROM_FIELD_384PM,
    ROM_FIELD_512PM,
    ROM_FIELD_ANSSI,
    ROM_FIELD_BLS383,
    ROM_FIELD_BLS24,
    ROM_FIELD_BLS48,
    ROM_FIELD_BLS381,
    ROM_FIELD_BLS461,
    ROM_FIELD_FP256BN,
    ROM_FIELD_FP512BN,
    ROM_FIELD_BN254,
    ROM_FIELD_BN254CX,
    ROM_FIELD_BRAINPOOL,
    ROM_FIELD_C41417,
    ROM_FIELD_GOLDILOCKS,
    ROM_FIELD_HIFIVE,
    ROM_FIELD_NIST256,
    ROM_FIELD_NIST384,
    ROM_FIELD_NIST521,
    ROM_FIELD_SECP256K1;


ROM_FIELD_25519 = {

    // 25519 Curve Modulus
    Modulus: [0xFFFFED, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x7FFF],
    R2modp: [0xA40000, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    MConst: 0x13,

};

/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_256PM = {

    // NUMS256 Curve Modulus
    // Base Bits= 24
    Modulus: [0xFFFF43, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFF],
    R2modp: [0x890000, 0x8B, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    MConst: 0xBD,

};

/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_384PM = {

    // NUMS384 Curve Modulus
    // Base Bits= 23
    Modulus: [0x7FFEC3, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
    R2modp: [0x224000, 0xC4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    MConst: 0x13D,

};

/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_512PM = {

    // NUMS512 Curve Modulus
    // Base Bits= 23
    Modulus: [0x7FFDC7, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
    R2modp: [0x0, 0x58800, 0x4F, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    MConst: 0x239,

};

/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_ANSSI = {

    // ANSSI modulus
    // Base Bits= 24
    Modulus: [0x6E9C03, 0xF353D8, 0x6DE8FC, 0xABC8CA, 0x61ADBC, 0x435B39, 0xE8CE42, 0x10126D, 0x3AD58F, 0x178C0B, 0xF1FD],
    R2modp: [0xACECE3, 0x924166, 0xB10FCE, 0x6CFBB6, 0x87EC2, 0x3DE43D, 0xD2CF67, 0xA67DDE, 0xAD30F2, 0xBCAAE, 0xDF98],
    MConst: 0x4E1155,

};

/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_BLS383 = {

    // BLS383 Modulus
    // Base Bits= 23
    Modulus: [0x2AB0AB,0x3AC90B,0x2F68DC,0x532429,0x43F298,0x1E8F51,0x5A5849,0x18DC00,0x2511AC,0x59E6CB,0x2B518,0x549425,0x5C41FE,0x340DB5,0x2ADBAD,0x2B4AB2,0x5565],
    R2modp: [0x250A44,0x68F66F,0xE3C74,0x791772,0x3525E3,0xE1E15,0x356616,0x54F624,0x508069,0x272663,0x4A4CB0,0x359293,0x5B6573,0x9F27F,0x5EA3B4,0x60FD2D,0x5167],
    MConst: 0x3435FD,
    Fra: [0x11DAC1,0x2E5A66,0x614B,0x733B9F,0x13480F,0x19146D,0x395436,0x2B3A25,0x1A8682,0x247F74,0x3931B3,0x5A9788,0x7C2C11,0x67173,0x1FDA2F,0x6ADF81,0x22AC],
    Frb: [0x18D5EA,0xC6EA5,0x2F0791,0x5FE88A,0x30AA88,0x57AE4,0x210413,0x6DA1DB,0xA8B29,0x356757,0x498365,0x79FC9C,0x6015EC,0x2D9C41,0xB017E,0x406B31,0x32B8],


};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_BLS24 = {

    // BLS24 Modulus
    // Base Bits= 23

    Modulus: [0x6152B,0x2CE94,0x6BE113,0x416986,0x2FFE2E,0x36D4C8,0x47172F,0x1945B7,0x5F068A,0xE6441,0x110186,0x4F0F9,0x33568E,0x4A0F2E,0x306EA0,0x173BF2,0x6E803F,0x735D8,0x3316EA,0x3C01E,0x555C0],
    R2modp: [0x22D6FA,0x7AA299,0x4C307E,0x68E711,0x7DA4AE,0x383CC3,0x12048C,0x11B7D,0x3CA412,0x2CE421,0x4932AC,0x27A306,0x340B6A,0x666E,0x3F6575,0x2F823C,0xA0DE6,0x137EC5,0x37D4BC,0x48A54E,0x4C28B],
    MConst: 0x15FE7D,
    Fra: [0x796F1D,0x4E9577,0x6EB572,0x68637F,0x41FF8B,0x46E8D3,0x7A7898,0x7C72A4,0x248407,0x6E79D9,0x56499E,0x4EB47F,0x27CBD6,0x33C662,0x4E9746,0xC2798,0x397549,0x4A5B1B,0x5C90B6,0x3DCA73,0x4BBC8],
    Frb: [0xCA60E,0x34391C,0x7D2BA0,0x590606,0x6DFEA2,0x6FEBF4,0x4C9E96,0x1CD312,0x3A8282,0x1FEA68,0x3AB7E7,0x363C79,0xB8AB7,0x1648CC,0x61D75A,0xB1459,0x350AF6,0x3CDABD,0x568633,0x45F5AA,0x99F7],

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_BLS48 = {

    // BLS48 Modulus
    // Base Bits= 23

    Modulus: [0x76AC0B,0x4C1FF9,0x67BBDB,0x5330EF,0x167009,0x450805,0x61C350,0x609BD4,0x76B2E,0x40410D,0x169054,0x353E01,0x141301,0x66F371,0x3B355A,0x6D4A85,0x36F405,0x28840A,0x454AB3,0x2B6433,0x29047A,0xB646E,0xBFF3F,0x68BEC2,0xF],
    R2modp: [0x5F42C2,0x596E88,0x2ED8FA,0x15C970,0x2518B4,0x2A75E7,0x62CE53,0x431C50,0x3CF507,0x620E44,0xD6FCD,0x21A7D,0x1FDA3F,0x6A099,0x53487,0x53EEBF,0x54E2D0,0x48437D,0x2233D8,0x63296F,0x21EE21,0x611417,0x619D35,0x13A61A,0xB],
    MConst: 0x5A805D,
    Fra: [0x25BF89,0x79FB26,0x56F988,0x399A14,0x507EA3,0x77995,0x3EE83A,0x52ECA9,0x3E3474,0x5F1E13,0x2E7CB0,0x255F3D,0x3AE7F8,0x2E4EF6,0x3BDE94,0x7B05A,0x13C83C,0x7BF664,0x1FF27F,0x6FE082,0x3B36CE,0x138113,0x6E2002,0x4C5C03,0x2],
    Frb: [0x25BF89,0x79FB26,0x56F988,0x399A14,0x507EA3,0x77995,0x3EE83A,0x52ECA9,0x3E3474,0x5F1E13,0x2E7CB0,0x255F3D,0x3AE7F8,0x2E4EF6,0x3BDE94,0x7B05A,0x13C83C,0x7BF664,0x1FF27F,0x6FE082,0x3B36CE,0x138113,0x6E2002,0x4C5C03,0x2],
};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_BLS381 = {

    // BLS381 Modulus
    // Base Bits= 23

    Modulus: [0x7FAAAB,0x7FFFFF,0x7EE7FB,0xA9FFF,0x3FFFEB,0x4483D5,0x3DAC3D,0x186950,0x12BF67,0x9E70A,0x11DD2E,0x5D66BB,0x7B6434,0x496374,0x5FF9A6,0x8F51C,0x1A01],
    R2modp: [0x40C6E6,0xE1A28,0x3D1C6C,0x6D2448,0x1BB111,0x4EAFA8,0x229C8C,0x4CEE55,0x46D2AD,0x7BA87C,0x708835,0x2413D1,0x6702E3,0x390116,0xD9E3F,0x4BD65C,0x9A3],
    MConst: 0x7CFFFD,
    Fra: [0x235FB8,0x6BDB24,0x76341D,0x1F3C09,0x6A53D6,0x389ECF,0x612EAE,0x1221EB,0x5F4F7B,0x7A797A,0x3F580F,0x6068F8,0x6B4202,0x784637,0x2EC199,0x69DF81,0x1904],
    Frb: [0x5C4AF3,0x1424DB,0x8B3DE,0x6B63F6,0x55AC14,0xBE505,0x5C7D8F,0x64764,0x336FEC,0xF6D8F,0x52851E,0x7CFDC2,0x102231,0x511D3D,0x31380C,0x1F159B,0xFC],

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_BLS461 = {

    // BLS461 Modulus
    // Base Bits= 23
    Modulus: [0x2AAAAB, 0x155, 0x2AAAB0, 0x2AAA55, 0x55, 0x80004, 0x555FC0, 0x135548, 0x1CC00F, 0x3FF4B8, 0x2D0AA3, 0x58A424, 0x2CCA47, 0x465B17, 0x6F5BC7, 0xA49AF, 0x55D694, 0x34AAB4, 0x155535, 0x2AAAAA, 0x1],
    R2modp: [0x621498, 0x3B585F, 0x41688, 0x6F780D, 0x17C239, 0x158D8A, 0x491A92, 0x737DF1, 0x22A06, 0x460263, 0x275FF2, 0x5496C3, 0x6D4AD2, 0x3A7B46, 0x3A6323, 0x1723B1, 0x76204B, 0x66FD26, 0x4E743E, 0x1BE66E, 0x0],
    MConst: 0x7FFFFD,
    Fra: [0x12A3A, 0x2F7F37, 0x3DC4, 0x52CCE2, 0x1C6308, 0xB7F14, 0x4381D4, 0x52D328, 0x58D45F, 0x359C90, 0x1DC2CC, 0x616582, 0x7C61EB, 0x6B11C5, 0x64341C, 0x421B30, 0x4DFEFA, 0x3CABC4, 0x12DFDA, 0x172028, 0x1],
    Frb: [0x298071, 0x50821E, 0x2A6CEB, 0x57DD73, 0x639D4C, 0x7C80EF, 0x11DDEB, 0x408220, 0x43EBAF, 0xA5827, 0xF47D7, 0x773EA2, 0x30685B, 0x5B4951, 0xB27AA, 0x482E7F, 0x7D799, 0x77FEF0, 0x2755A, 0x138A82, 0x0],

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_FP256BN = {

    // FP256BN Modulus
    // Base Bits= 24
    Modulus: [0xD33013, 0x2DDBAE, 0x82D329, 0x12980A, 0xDC65FB, 0xA49F0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
    R2modp: [0x2F4801, 0xF779D1, 0x3E7F6E, 0xB42A3A, 0xC919C9, 0xC26C08, 0x1BB715, 0xCA2ED6, 0x54293E, 0xE578E, 0x78EA],
    MConst: 0x37E5E5,
    Fra: [0x943106, 0x328AF, 0x8F7476, 0x1E3AB2, 0xA17151, 0x67CF39, 0x8DDB08, 0x2D1A6E, 0x786F35, 0x7662CA, 0x3D61],
    Frb: [0x3EFF0D, 0x2AB2FF, 0xF35EB3, 0xF45D57, 0x3AF4A9, 0x3CCFD3, 0xD11369, 0x19CB83, 0x848198, 0x899D35, 0xC29E],
};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_FP512BN = {

    // FP512BN Modulus
    // Base Bits= 23
    Modulus: [0x2DEF33, 0x501245, 0x1ED3AC, 0x7A6323, 0x255CE5, 0x7C322D, 0x2AC8DB, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A2A, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
    R2modp: [0x23E65D, 0x575A37, 0x411CD0, 0x295FB3, 0x640669, 0x375C69, 0x92395, 0x738492, 0x780D6D, 0x1BCD9D, 0x417CAA, 0x2DC6FB, 0x7EACFB, 0x327043, 0x7F2FC7, 0xF268C, 0x73D733, 0x2147C9, 0x2ACCD3, 0x32EAF8, 0x3B2C1E, 0xD46A2, 0x30],
    MConst: 0x4C5C05,
    Fra: [0x373AB2, 0x2F63E9, 0x47D258, 0x101576, 0x1514F6, 0x503C2E, 0x34EF61, 0x4FB040, 0x2CBBB5, 0x553D0A, 0x63A7E2, 0x10341C, 0x48CF2E, 0x3564D7, 0x25BDE4, 0x50C529, 0x468B4E, 0x2D518F, 0x6DE46, 0x7C84AD, 0x1CF5BB, 0x5EE355, 0x7],
    Frb: [0x76B481, 0x20AE5B, 0x570154, 0x6A4DAC, 0x1047EF, 0x2BF5FF, 0x75D97A, 0x7682AE, 0x6BFD2E, 0x681C72, 0x617359, 0x77460D, 0x7341EC, 0x42B2A4, 0xD16DD, 0x350BC3, 0x387677, 0x52A249, 0x7921B9, 0x37B52, 0x630A44, 0x211CAA, 0x38],

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_BN254 = {

    // BN254 Modulus
    // Base Bits= 24
    Modulus: [0x13, 0x0, 0x13A700, 0x0, 0x210000, 0x861, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
    R2modp: [0x2F2AA7, 0x537047, 0xF8F174, 0xC3E364, 0xAB8C1C, 0x3C2035, 0x69549, 0x379287, 0x3BE629, 0x75617A, 0x1F47],
    MConst: 0x9435E5,
    Fra: [0x2A6DE9, 0xE6C06F, 0xC2E17D, 0x4D3F77, 0x97492, 0x953F85, 0x50A846, 0xB6499B, 0x2E7C8C, 0x761921, 0x1B37],
    Frb: [0xD5922A, 0x193F90, 0x50C582, 0xB2C088, 0x178B6D, 0x6AC8DC, 0x2F57B9, 0x3EAB2, 0xD18375, 0xEE691E, 0x9EB],

};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_BN254CX = {

    // BN254CX Modulus
    // Base Bits= 24
    Modulus: [0x1B55B3, 0x23EF5C, 0xE1BE66, 0x18093E, 0x3FD6EE, 0x66D324, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
    R2modp: [0x8EE63D, 0x721FDE, 0xCC0891, 0x10C28B, 0xD4F5A, 0x4C18FB, 0x9036FA, 0x3F845F, 0xA507E4, 0x78EB29, 0x1587],
    MConst: 0x789E85,
    Fra: [0xC80EA3, 0x83355, 0x215BD9, 0xF173F8, 0x677326, 0x189868, 0x8AACA7, 0xAFE18B, 0x3A0164, 0x82FA6, 0x1359],
    Frb: [0x534710, 0x1BBC06, 0xC0628D, 0x269546, 0xD863C7, 0x4E3ABB, 0xD9CDBC, 0xDC53, 0x3628A9, 0xF7D062, 0x10A6],
};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_BRAINPOOL = {

    // Brainpool modulus
    // Base Bits= 24
    Modulus: [0x6E5377, 0x481D1F, 0x282013, 0xD52620, 0x3BF623, 0x8D726E, 0x909D83, 0x3E660A, 0xEEA9BC, 0x57DBA1, 0xA9FB],
    R2modp: [0x35B819, 0xB03428, 0xECAF0F, 0x3854A4, 0x4A0ED5, 0x2421EA, 0xAA562C, 0xF9C45, 0xDDAE58, 0x4350FD, 0x52B8],
    MConst: 0xFD89B9,

};

/* Fixed Data in ROM - Field and Curve parameters */


ROM_FIELD_C41417 = {

    // C41417 modulus
    // Base Bits= 2
    Modulus: [0x3FFFEF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFF],
    R2modp: [0x12100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    MConst: 0x11,
};

/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_GOLDILOCKS = {

    // GOLDILOCKS modulus
    // Base Bits= 23
    Modulus: [0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7DFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FF],
    R2modp: [0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xC0000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    MConst: 0x1,
};

/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_HIFIVE = {

    // HIFIVE modulus
    // Base Bits= 23
    Modulus: [0x7FFFFD, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3FFF],
    R2modp: [0x240000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    MConst: 0x3,
};

/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_NIST256 = {

    // NIST256 Modulus
    // Base Bits= 24
    Modulus: [0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x0, 0x0, 0x0, 0x0, 0x1, 0xFFFF00, 0xFFFF],
    R2modp: [0x30000, 0x0, 0x0, 0xFFFF00, 0xFBFFFF, 0xFFFFFF, 0xFFFFFE, 0xFFFFFF, 0xFDFFFF, 0xFFFFFF, 0x4],
    MConst: 0x1,

};

/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_NIST384 = {

    // NIST384 modulus
    // Base Bits= 23
    Modulus: [0x7FFFFF, 0x1FF, 0x0, 0x0, 0x7FFFF0, 0x7FDFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
    R2modp: [0x4000, 0x0, 0x7FFFFE, 0x1FF, 0x80000, 0x0, 0x0, 0x7FC000, 0x3FFFFF, 0x0, 0x200, 0x20000, 0x0, 0x0, 0x0, 0x0, 0x0],
    MConst: 0x1,

};

/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_NIST521 = {

    // NIST521 modulus
    // Base Bits= 23
    Modulus: [0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFF],
    R2modp: [0x10000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    MConst: 0x1,
};


/* Fixed Data in ROM - Field and Curve parameters */

ROM_FIELD_SECP256K1 = {

    // SECP256K1 modulus
    // Base Bits= 24
    Modulus: [0xFFFC2F,0xFFFEFF,0xFFFFFF,0xFFFFFF,0xFFFFFF,0xFFFFFF,0xFFFFFF,0xFFFFFF,0xFFFFFF,0xFFFFFF,0xFFFF],
    R2modp: [0xA10000,0xE90,0x7A2,0x100,0x0,0x0,0x0,0x0,0x0,0x0,0x0],
    MConst: 0x253531,
};

var ROM_FIELD = {
    "25519": ROM_FIELD_25519,
    "256PM": ROM_FIELD_256PM,
    "384PM": ROM_FIELD_384PM,
    "512PM": ROM_FIELD_512PM,
    "ANSSI": ROM_FIELD_ANSSI,
    "BLS383": ROM_FIELD_BLS383,
    "BLS24": ROM_FIELD_BLS24,
    "BLS48": ROM_FIELD_BLS48,
    "BLS381": ROM_FIELD_BLS381,
    "BLS461": ROM_FIELD_BLS461,
    "FP256BN": ROM_FIELD_FP256BN,
    "FP512BN": ROM_FIELD_FP512BN,
    "BN254": ROM_FIELD_BN254,
    "BN254CX": ROM_FIELD_BN254CX,
    "BRAINPOOL": ROM_FIELD_BRAINPOOL,
    "C41417": ROM_FIELD_C41417,
    "GOLDILOCKS": ROM_FIELD_GOLDILOCKS,
    "HIFIVE": ROM_FIELD_HIFIVE,
    "NIST256": ROM_FIELD_NIST256,
    "NIST384": ROM_FIELD_NIST384,
    "NIST521": ROM_FIELD_NIST521,
    "SECP256K1": ROM_FIELD_SECP256K1
};

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* RSA API Functions */

function RSA(ctx) {

    var RSA = {
        RFS: ctx.BIG.MODBYTES * ctx.FF.FFLEN,
        SHA256: 32,
        SHA384: 48,
        SHA512: 64,

        HASH_TYPE: 32,

        /* SHAXXX identifier strings */
        SHA256ID: [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
        SHA384ID: [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
        SHA512ID: [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],

        bytestohex: function(b) {
            var s = "",
                len = b.length,
                ch, i;

            for (i = 0; i < len; i++) {
                ch = b[i];
                s += ((ch >>> 4) & 15).toString(16);
                s += (ch & 15).toString(16);

            }
            return s;
        },

        bytestostring: function(b) {
            var s = "",
                i;

            for (i = 0; i < b.length; i++) {
                s += String.fromCharCode(b[i]);
            }

            return s;
        },

        stringtobytes: function(s) {
            var b = [],
                i;

            for (i = 0; i < s.length; i++) {
                b.push(s.charCodeAt(i));
            }

            return b;
        },

        hashit: function(sha, A, n) {
            var R = [],
                H;

            if (sha == this.SHA256) {
                H = new ctx.HASH256();

                if (A != null) {
                    H.process_array(A);
                }

                if (n >= 0) {
                    H.process_num(n);
                }

                R = H.hash();
            } else if (sha == this.SHA384) {
                H = new ctx.HASH384();

                if (A != null) {
                    H.process_array(A);
                }

                if (n >= 0) {
                    H.process_num(n);
                }

                R = H.hash();
            } else if (sha == this.SHA512) {
                H = new ctx.HASH512();

                if (A != null) {
                    H.process_array(A);
                }

                if (n >= 0) {
                    H.process_num(n);
                }

                R = H.hash();
            }

            return R;
        },

        /* IEEE1363 A16.11/A16.12 more or less */
        KEY_PAIR: function(rng, e, PRIV, PUB) {
            var n = PUB.n.length >> 1,
                t = new ctx.FF(n),
                p1 = new ctx.FF(n),
                q1 = new ctx.FF(n);

            for (;;) {
                PRIV.p.random(rng);

                while (PRIV.p.lastbits(2) != 3) {
                    PRIV.p.inc(1);
                }

                while (!ctx.FF.prime(PRIV.p, rng)) {
                    PRIV.p.inc(4);
                }

                p1.copy(PRIV.p);
                p1.dec(1);

                if (p1.cfactor(e)) {
                    continue;
                }

                break;
            }

            for (;;) {
                PRIV.q.random(rng);

                while (PRIV.q.lastbits(2) != 3) {
                    PRIV.q.inc(1);
                }

                while (!ctx.FF.prime(PRIV.q, rng)) {
                    PRIV.q.inc(4);
                }

                q1.copy(PRIV.q);
                q1.dec(1);

                if (q1.cfactor(e)) {
                    continue;
                }

                break;
            }

            PUB.n = ctx.FF.mul(PRIV.p, PRIV.q);
            PUB.e = e;

            t.copy(p1);
            t.shr();
            PRIV.dp.set(e);
            PRIV.dp.invmodp(t);
            if (PRIV.dp.parity() === 0) {
                PRIV.dp.add(t);
            }
            PRIV.dp.norm();

            t.copy(q1);
            t.shr();
            PRIV.dq.set(e);
            PRIV.dq.invmodp(t);
            if (PRIV.dq.parity() === 0) {
                PRIV.dq.add(t);
            }
            PRIV.dq.norm();

            PRIV.c.copy(PRIV.p);
            PRIV.c.invmodp(PRIV.q);

            return;
        },

        /* Mask Generation Function */
        MGF1: function(sha, Z, olen, K) {
            var hlen = sha,
                B = [],
                k = 0,
                counter, cthreshold, i;

            for (i = 0; i < K.length; i++) {
                K[i] = 0;
            }

            cthreshold = Math.floor(olen / hlen);
            if (olen % hlen !== 0) {
                cthreshold++;
            }

            for (counter = 0; counter < cthreshold; counter++) {
                B = this.hashit(sha, Z, counter);

                if (k + hlen > olen) {
                    for (i = 0; i < olen % hlen; i++) {
                        K[k++] = B[i];
                    }
                } else {
                    for (i = 0; i < hlen; i++) {
                        K[k++] = B[i];
                    }
                }
            }
        },

        PKCS15: function(sha, m, w) {
            var olen = ctx.FF.FF_BITS / 8,
                hlen = sha,
                idlen = 19,
                H, i, j;

            if (olen < idlen + hlen + 10) {
                return false;
            }

            H = this.hashit(sha, m, -1);

            for (i = 0; i < w.length; i++) {
                w[i] = 0;
            }

            i = 0;
            w[i++] = 0;
            w[i++] = 1;
            for (j = 0; j < olen - idlen - hlen - 3; j++) {
                w[i++] = 0xFF;
            }
            w[i++] = 0;

            if (hlen == this.SHA256) {
                for (j = 0; j < idlen; j++) {
                    w[i++] = this.SHA256ID[j];
                }
            } else if (hlen == this.SHA384) {
                for (j = 0; j < idlen; j++) {
                    w[i++] = this.SHA384ID[j];
                }
            } else if (hlen == this.SHA512) {
                for (j = 0; j < idlen; j++) {
                    w[i++] = this.SHA512ID[j];
                }
            }

            for (j = 0; j < hlen; j++) {
                w[i++] = H[j];
            }

            return true;
        },

        /* OAEP Message Encoding for Encryption */
        OAEP_ENCODE: function(sha, m, rng, p) {
            var olen = RSA.RFS - 1,
                mlen = m.length,
                SEED = [],
                DBMASK = [],
                f = [],
                hlen,
                seedlen,
                slen,
                i, d, h;

            seedlen = hlen = sha;

            if (mlen > olen - hlen - seedlen - 1) {
                return null;
            }

            h = this.hashit(sha, p, -1);
            for (i = 0; i < hlen; i++) {
                f[i] = h[i];
            }

            slen = olen - mlen - hlen - seedlen - 1;

            for (i = 0; i < slen; i++) {
                f[hlen + i] = 0;
            }
            f[hlen + slen] = 1;
            for (i = 0; i < mlen; i++) {
                f[hlen + slen + 1 + i] = m[i];
            }

            for (i = 0; i < seedlen; i++) {
                SEED[i] = rng.getByte();
            }
            this.MGF1(sha, SEED, olen - seedlen, DBMASK);

            for (i = 0; i < olen - seedlen; i++) {
                DBMASK[i] ^= f[i];
            }
            this.MGF1(sha, DBMASK, seedlen, f);

            for (i = 0; i < seedlen; i++) {
                f[i] ^= SEED[i];
            }

            for (i = 0; i < olen - seedlen; i++) {
                f[i + seedlen] = DBMASK[i];
            }

            /* pad to length RFS */
            d = 1;
            for (i = RSA.RFS - 1; i >= d; i--) {
                f[i] = f[i - d];
            }
            for (i = d - 1; i >= 0; i--) {
                f[i] = 0;
            }

            return f;
        },

        /* OAEP Message Decoding for Decryption */
        OAEP_DECODE: function(sha, p, f) {
            var olen = RSA.RFS - 1,
                SEED = [],
                CHASH = [],
                DBMASK = [],
                comp,
                hlen,
                seedlen,
                x, t, d, i, k, h, r;

            seedlen = hlen = sha;

            if (olen < seedlen + hlen + 1) {
                return null;
            }

            for (i = 0; i < olen - seedlen; i++) {
                DBMASK[i] = 0;
            }

            if (f.length < RSA.RFS) {
                d = RSA.RFS - f.length;
                for (i = RSA.RFS - 1; i >= d; i--) {
                    f[i] = f[i - d];
                }
                for (i = d - 1; i >= 0; i--) {
                    f[i] = 0;
                }
            }

            h = this.hashit(sha, p, -1);
            for (i = 0; i < hlen; i++) {
                CHASH[i] = h[i];
            }

            x = f[0];

            for (i = seedlen; i < olen; i++) {
                DBMASK[i - seedlen] = f[i + 1];
            }

            this.MGF1(sha, DBMASK, seedlen, SEED);
            for (i = 0; i < seedlen; i++) {
                SEED[i] ^= f[i + 1];
            }
            this.MGF1(sha, SEED, olen - seedlen, f);
            for (i = 0; i < olen - seedlen; i++) {
                DBMASK[i] ^= f[i];
            }

            comp = true;
            for (i = 0; i < hlen; i++) {
                if (CHASH[i] != DBMASK[i]) {
                    comp = false;
                }
            }

            for (i = 0; i < olen - seedlen - hlen; i++) {
                DBMASK[i] = DBMASK[i + hlen];
            }

            for (i = 0; i < hlen; i++) {
                SEED[i] = CHASH[i] = 0;
            }

            for (k = 0;; k++) {
                if (k >= olen - seedlen - hlen) {
                    return null;
                }

                if (DBMASK[k] !== 0) {
                    break;
                }
            }

            t = DBMASK[k];

            if (!comp || x !== 0 || t != 0x01) {
                for (i = 0; i < olen - seedlen; i++) {
                    DBMASK[i] = 0;
                }
                return null;
            }

            r = [];

            for (i = 0; i < olen - seedlen - hlen - k - 1; i++) {
                r[i] = DBMASK[i + k + 1];
            }

            for (i = 0; i < olen - seedlen; i++) {
                DBMASK[i] = 0;
            }

            return r;
        },

        /* destroy the Private Key structure */
        PRIVATE_KEY_KILL: function(PRIV) {
            PRIV.p.zero();
            PRIV.q.zero();
            PRIV.dp.zero();
            PRIV.dq.zero();
            PRIV.c.zero();
        },

        /* RSA encryption with the public key */
        ENCRYPT: function(PUB, F, G) {
            var n = PUB.n.getlen(),
                f = new ctx.FF(n);

            ctx.FF.fromBytes(f, F);

            f.power(PUB.e, PUB.n);

            f.toBytes(G);
        },

        /* RSA decryption with the private key */
        DECRYPT: function(PRIV, G, F) {
            var n = PRIV.p.getlen(),
                g = new ctx.FF(2 * n),
                jp, jq, t;

            ctx.FF.fromBytes(g, G);

            jp = g.dmod(PRIV.p);
            jq = g.dmod(PRIV.q);

            jp.skpow(PRIV.dp, PRIV.p);
            jq.skpow(PRIV.dq, PRIV.q);

            g.zero();
            g.dscopy(jp);
            jp.mod(PRIV.q);
            if (ctx.FF.comp(jp, jq) > 0) {
                jq.add(PRIV.q);
            }
            jq.sub(jp);
            jq.norm();

            t = ctx.FF.mul(PRIV.c, jq);
            jq = t.dmod(PRIV.q);

            t = ctx.FF.mul(jq, PRIV.p);
            g.add(t);
            g.norm();

            g.toBytes(F);
        }
    };

    return RSA;
}

function rsa_private_key(ctx) {

    var rsa_private_key = function(n) {
        this.p = new ctx.FF(n);
        this.q = new ctx.FF(n);
        this.dp = new ctx.FF(n);
        this.dq = new ctx.FF(n);
        this.c = new ctx.FF(n);
    };

    return rsa_private_key;
}

function rsa_public_key(ctx) {

    var rsa_public_key = function(m) {
        this.e = 0;
        this.n = new ctx.FF(m);
    };

    return rsa_public_key;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/*
 * Implementation of the Secure Hashing Algorithm SHA-3

 * Generates a message digest. It should be impossible to come
 * come up with two messages that hash to the same value ("collision free").
 *
 * For use with byte-oriented messages only.
 */

function SHA3(ctx) {

    var SHA3 = function(olen) {
        this.length = 0;
        this.rate = 0;
        this.len = 0;
        this.S = [];
        this.init(olen);
    };

    SHA3.prototype = {

        transform: function() {
            var C = [],
                D = [],
                B = [],
                i, j, k;

            for (k = 0; k < SHA3.ROUNDS; k++) {
                C[0] = new ctx.UInt64(this.S[0][0].top ^ this.S[0][1].top ^ this.S[0][2].top ^ this.S[0][3].top ^ this.S[0][4].top, this.S[0][0].bot ^ this.S[0][1].bot ^ this.S[0][2].bot ^ this.S[0][3].bot ^ this.S[0][4].bot);
                C[1] = new ctx.UInt64(this.S[1][0].top ^ this.S[1][1].top ^ this.S[1][2].top ^ this.S[1][3].top ^ this.S[1][4].top, this.S[1][0].bot ^ this.S[1][1].bot ^ this.S[1][2].bot ^ this.S[1][3].bot ^ this.S[1][4].bot);
                C[2] = new ctx.UInt64(this.S[2][0].top ^ this.S[2][1].top ^ this.S[2][2].top ^ this.S[2][3].top ^ this.S[2][4].top, this.S[2][0].bot ^ this.S[2][1].bot ^ this.S[2][2].bot ^ this.S[2][3].bot ^ this.S[2][4].bot);
                C[3] = new ctx.UInt64(this.S[3][0].top ^ this.S[3][1].top ^ this.S[3][2].top ^ this.S[3][3].top ^ this.S[3][4].top, this.S[3][0].bot ^ this.S[3][1].bot ^ this.S[3][2].bot ^ this.S[3][3].bot ^ this.S[3][4].bot);
                C[4] = new ctx.UInt64(this.S[4][0].top ^ this.S[4][1].top ^ this.S[4][2].top ^ this.S[4][3].top ^ this.S[4][4].top, this.S[4][0].bot ^ this.S[4][1].bot ^ this.S[4][2].bot ^ this.S[4][3].bot ^ this.S[4][4].bot);

                D[0] = SHA3.xor(C[4], SHA3.rotl(C[1], 1));
                D[1] = SHA3.xor(C[0], SHA3.rotl(C[2], 1));
                D[2] = SHA3.xor(C[1], SHA3.rotl(C[3], 1));
                D[3] = SHA3.xor(C[2], SHA3.rotl(C[4], 1));
                D[4] = SHA3.xor(C[3], SHA3.rotl(C[0], 1));

                for (i = 0; i < 5; i++) {
                    B[i] = [];
                    for (j = 0; j < 5; j++) {
                        B[i][j] = new ctx.UInt64(0, 0);
                        this.S[i][j] = SHA3.xor(this.S[i][j], D[i]);
                    }
                }

                B[0][0] = this.S[0][0].copy();
                B[1][3] = SHA3.rotl(this.S[0][1], 36);
                B[2][1] = SHA3.rotl(this.S[0][2], 3);
                B[3][4] = SHA3.rotl(this.S[0][3], 41);
                B[4][2] = SHA3.rotl(this.S[0][4], 18);

                B[0][2] = SHA3.rotl(this.S[1][0], 1);
                B[1][0] = SHA3.rotl(this.S[1][1], 44);
                B[2][3] = SHA3.rotl(this.S[1][2], 10);
                B[3][1] = SHA3.rotl(this.S[1][3], 45);
                B[4][4] = SHA3.rotl(this.S[1][4], 2);

                B[0][4] = SHA3.rotl(this.S[2][0], 62);
                B[1][2] = SHA3.rotl(this.S[2][1], 6);
                B[2][0] = SHA3.rotl(this.S[2][2], 43);
                B[3][3] = SHA3.rotl(this.S[2][3], 15);
                B[4][1] = SHA3.rotl(this.S[2][4], 61);

                B[0][1] = SHA3.rotl(this.S[3][0], 28);
                B[1][4] = SHA3.rotl(this.S[3][1], 55);
                B[2][2] = SHA3.rotl(this.S[3][2], 25);
                B[3][0] = SHA3.rotl(this.S[3][3], 21);
                B[4][3] = SHA3.rotl(this.S[3][4], 56);

                B[0][3] = SHA3.rotl(this.S[4][0], 27);
                B[1][1] = SHA3.rotl(this.S[4][1], 20);
                B[2][4] = SHA3.rotl(this.S[4][2], 39);
                B[3][2] = SHA3.rotl(this.S[4][3], 8);
                B[4][0] = SHA3.rotl(this.S[4][4], 14);

                for (i = 0; i < 5; i++) {
                    for (j = 0; j < 5; j++) {
                        this.S[i][j] = SHA3.xor(B[i][j], SHA3.and(SHA3.not(B[(i + 1) % 5][j]), B[(i + 2) % 5][j]));
                    }
                }

                this.S[0][0] = SHA3.xor(this.S[0][0], SHA3.RC[k]);
            }
        },

        /* Initialize Hash function */
        init: function(olen) {
            var i, j;
            for (i = 0; i < 5; i++) {
                this.S[i] = [];
                for (j = 0; j < 5; j++) {
                    this.S[i][j] = new ctx.UInt64(0, 0);
                }
            }
            this.length = 0;
            this.len = olen;
            this.rate = 200 - 2 * olen;
        },

        /* process a single byte */
        process: function(byt) {
            var i, j, k, b, cnt, el;

            cnt = (this.length % this.rate);
            b = cnt % 8;
            cnt >>= 3;
            i = cnt % 5;
            /* process by columns! */
            j = Math.floor(cnt / 5);

            el = new ctx.UInt64(0, byt);
            for (k = 0; k < b; k++) {
                el.shlb();
            }
            this.S[i][j] = SHA3.xor(this.S[i][j], el);

            this.length++;
            if ((this.length % this.rate) == 0) {
                this.transform();
            }
        },

        /* squeeze the sponge */
        squeeze: function(buff, olen) {
            var done,
                m = 0,
                i, j, k, el;

            /* extract by columns */
            done = false;

            for (;;) {
                for (j = 0; j < 5; j++) {
                    for (i = 0; i < 5; i++) {
                        el = this.S[i][j].copy();
                        for (k = 0; k < 8; k++) {
                            buff[m++] = (el.bot & 0xff);
                            if (m >= olen || (m % this.rate) == 0) {
                                done = true;
                                break;
                            }
                            el = SHA3.rotl(el, 56);
                        }

                        if (done) {
                            break;
                        }
                    }

                    if (done) {
                        break;
                    }
                }

                if (m >= olen) {
                    break;
                }

                done = false;
                this.transform();
            }
        },
        /* pad message and finish - supply digest */
        hash: function(buff) {
            var q = this.rate - (this.length % this.rate);
            if (q == 1) {
                this.process(0x86);
            } else {
                /* 0x06 for SHA-3 */
                this.process(0x06);
                while (this.length % this.rate != this.rate - 1) {
                    this.process(0x00);
                }
                /* this will force a final transform */
                this.process(0x80);
            }
            this.squeeze(buff, this.len);
        },

        /* pad message and finish - supply digest */
        shake: function(buff, olen) {
            var q = this.rate - (this.length % this.rate);
            if (q == 1) {
                this.process(0x9f);
            } else {
                /* 0x06 for SHA-3 */
                this.process(0x1f);
                while (this.length % this.rate != this.rate - 1) {
                    this.process(0x00);
                }
                /* this will force a final transform */
                this.process(0x80);
            }
            this.squeeze(buff, olen);
        }
    };

    /* static functions */
    SHA3.rotl = function(x, n) {
        if (n == 0) {
            return x;
        }

        if (n < 32) {
            return new ctx.UInt64((x.top << n) | (x.bot >>> (32 - n)), (x.bot << n) | (x.top >>> (32 - n)));
        } else {
            return new ctx.UInt64((x.bot << (n - 32)) | (x.top >>> (64 - n)), (x.top << (n - 32)) | (x.bot >>> (64 - n)));
        }
    };

    SHA3.xor = function(a, b) {
        return new ctx.UInt64(a.top ^ b.top, a.bot ^ b.bot);
    };

    SHA3.and = function(a, b) {
        return new ctx.UInt64(a.top & b.top, a.bot & b.bot);
    };

    SHA3.not = function(a) {
        return new ctx.UInt64(~a.top, ~a.bot);
    };

    /* constants */
    SHA3.ROUNDS = 24;
    SHA3.HASH224 = 28;
    SHA3.HASH256 = 32;
    SHA3.HASH384 = 48;
    SHA3.HASH512 = 64;
    SHA3.SHAKE128 = 16;
    SHA3.SHAKE256 = 32;

    SHA3.RC = [new ctx.UInt64(0x00000000, 0x00000001), new ctx.UInt64(0x00000000, 0x00008082),
        new ctx.UInt64(0x80000000, 0x0000808A), new ctx.UInt64(0x80000000, 0x80008000),
        new ctx.UInt64(0x00000000, 0x0000808B), new ctx.UInt64(0x00000000, 0x80000001),
        new ctx.UInt64(0x80000000, 0x80008081), new ctx.UInt64(0x80000000, 0x00008009),
        new ctx.UInt64(0x00000000, 0x0000008A), new ctx.UInt64(0x00000000, 0x00000088),
        new ctx.UInt64(0x00000000, 0x80008009), new ctx.UInt64(0x00000000, 0x8000000A),
        new ctx.UInt64(0x00000000, 0x8000808B), new ctx.UInt64(0x80000000, 0x0000008B),
        new ctx.UInt64(0x80000000, 0x00008089), new ctx.UInt64(0x80000000, 0x00008003),
        new ctx.UInt64(0x80000000, 0x00008002), new ctx.UInt64(0x80000000, 0x00000080),
        new ctx.UInt64(0x00000000, 0x0000800A), new ctx.UInt64(0x80000000, 0x8000000A),
        new ctx.UInt64(0x80000000, 0x80008081), new ctx.UInt64(0x80000000, 0x00008080),
        new ctx.UInt64(0x00000000, 0x80000001), new ctx.UInt64(0x80000000, 0x80008008),
    ];

    return SHA3;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* rudimentary unsigned 64-bit type for SHA384 and SHA512 */

function UInt64() {

    var UInt64 = function(top, bot) {
        this.top = top;
        this.bot = bot;
    };

    UInt64.prototype = {
        add: function(y) {
            var t = (this.bot >>> 0) + (y.bot >>> 0),
                low = t >>> 0,
                high = (this.top >>> 0) + (y.top >>> 0);

            this.bot = low;

            if (low != t) {
                this.top = (high + 1) >>> 0;
            } else {
                this.top = high;
            }

            return this;
        },

        copy: function() {
            var r = new UInt64(this.top, this.bot);
            return r;
        },

        shlb: function() {
            var t = this.bot >>> 24;
            this.top = t + (this.top << 8);
            this.bot <<= 8;
            return this;
        }
    };

    return UInt64;
}

/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/


function CTX(input_parameter) {

    var ctx = this,
        CTXLIST;

    /**
     * Config fields:
     *  NB   : Number of bytes in Modulus
     *  BASE : Number base as power of 2
     *  NBT  : Number of bits in Modulus
     *  M8   : Modulus mod 8
     *  MT   : Modulus Type (Pseudo-Mersenne,...)
     *  CT   : Curve Type (Weierstrass,...)
     *  PF   : Pairing Friendly
     *  ST   : Sextic Twist Type
     *  SX   : Sign of x parameter
     *  HT   : Hash output size
     *  AK   : AES key size
     */
    CTXLIST = {
        "ED25519": {
            "BITS": "256",
            "FIELD": "25519",
            "CURVE": "ED25519",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 255,
            "@M8": 5,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 32,
            "@AK": 16
        },

        "C25519": {
            "BITS": "256",
            "FIELD": "25519",
            "CURVE": "C25519",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 255,
            "@M8": 5,
            "@MT": 1,
            "@CT": 2,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 32,
            "@AK": 16
        },

        "SECP256K1": {
            "BITS": "256",
            "FIELD": "SECP256K1",
            "CURVE": "SECP256K1",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 7,
            "@MT": 0,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 32,
            "@AK": 16
        },

        "NIST256": {
            "BITS": "256",
            "FIELD": "NIST256",
            "CURVE": "NIST256",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 7,
            "@MT": 0,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 32,
            "@AK": 16
        },

        "NIST384": {
            "BITS": "384",
            "FIELD": "NIST384",
            "CURVE": "NIST384",
            "@NB": 48,
            "@BASE": 23,
            "@NBT": 384,
            "@M8": 7,
            "@MT": 0,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 48,
            "@AK": 24
        },

        "BRAINPOOL": {
            "BITS": "256",
            "FIELD": "BRAINPOOL",
            "CURVE": "BRAINPOOL",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 7,
            "@MT": 0,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 32,
            "@AK": 16
        },

        "ANSSI": {
            "BITS": "256",
            "FIELD": "ANSSI",
            "CURVE": "ANSSI",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 7,
            "@MT": 0,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 32,
            "@AK": 16
        },

        "HIFIVE": {
            "BITS": "336",
            "FIELD": "HIFIVE",
            "CURVE": "HIFIVE",
            "@NB": 42,
            "@BASE": 23,
            "@NBT": 336,
            "@M8": 5,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 48,
            "@AK": 24
        },

        "GOLDILOCKS": {
            "BITS": "448",
            "FIELD": "GOLDILOCKS",
            "CURVE": "GOLDILOCKS",
            "@NB": 56,
            "@BASE": 23,
            "@NBT": 448,
            "@M8": 7,
            "@MT": 2,
            "@CT": 1,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 64,
            "@AK": 32
        },

        "C41417": {
            "BITS": "416",
            "FIELD": "C41417",
            "CURVE": "C41417",
            "@NB": 52,
            "@BASE": 22,
            "@NBT": 414,
            "@M8": 7,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 64,
            "@AK": 32
        },

        "NIST521": {
            "BITS": "528",
            "FIELD": "NIST521",
            "CURVE": "NIST521",
            "@NB": 66,
            "@BASE": 23,
            "@NBT": 521,
            "@M8": 7,
            "@MT": 1,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 64,
            "@AK": 32
        },

        "NUMS256W": {
            "BITS": "256",
            "FIELD": "256PM",
            "CURVE": "NUMS256W",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 3,
            "@MT": 1,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 32,
            "@AK": 16
        },

        "NUMS256E": {
            "BITS": "256",
            "FIELD": "256PM",
            "CURVE": "NUMS256E",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 3,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 32,
            "@AK": 16
        },

        "NUMS384W": {
            "BITS": "384",
            "FIELD": "384PM",
            "CURVE": "NUMS384W",
            "@NB": 48,
            "@BASE": 23,
            "@NBT": 384,
            "@M8": 3,
            "@MT": 1,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 48,
            "@AK": 24
        },

        "NUMS384E": {
            "BITS": "384",
            "FIELD": "384PM",
            "CURVE": "NUMS384E",
            "@NB": 48,
            "@BASE": 23,
            "@NBT": 384,
            "@M8": 3,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 48,
            "@AK": 24
        },

        "NUMS512W": {
            "BITS": "512",
            "FIELD": "512PM",
            "CURVE": "NUMS512W",
            "@NB": 64,
            "@BASE": 23,
            "@NBT": 512,
            "@M8": 7,
            "@MT": 1,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 64,
            "@AK": 32
        },

        "NUMS512E": {
            "BITS": "512",
            "FIELD": "512PM",
            "CURVE": "NUMS512E",
            "@NB": 64,
            "@BASE": 23,
            "@NBT": 512,
            "@M8": 7,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0,
            "@HT": 64,
            "@AK": 32
        },

        "FP256BN": {
            "BITS": "256",
            "FIELD": "FP256BN",
            "CURVE": "FP256BN",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 1,
            "@ST": 1,
            "@SX": 1,
            "@HT": 32,
            "@AK": 16
        },

        "FP512BN": {
            "BITS": "512",
            "FIELD": "FP512BN",
            "CURVE": "FP512BN",
            "@NB": 64,
            "@BASE": 23,
            "@NBT": 512,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 1,
            "@ST": 1,
            "@SX": 0,
            "@HT": 32,
            "@AK": 16
        },

        "BN254": {
            "BITS": "256",
            "FIELD": "BN254",
            "CURVE": "BN254",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 254,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 1,
            "@ST": 0,
            "@SX": 1,
            "@HT": 32,
            "@AK": 16
        },

        "BN254CX": {
            "BITS": "256",
            "FIELD": "BN254CX",
            "CURVE": "BN254CX",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 254,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 1,
            "@ST": 0,
            "@SX": 1,
            "@HT": 32,
            "@AK": 16
        },

        "BLS383": {
            "BITS": "384",
            "FIELD": "BLS383",
            "CURVE": "BLS383",
            "@NB": 48,
            "@BASE": 23,
            "@NBT": 383,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 2,
            "@ST": 1,
            "@SX": 0,
            "@HT": 32,
            "@AK": 16
        },

        "BLS24": {
            "BITS": "480",
            "FIELD": "BLS24",
            "CURVE": "BLS24",
            "@NB": 60,
            "@BASE": 23,
            "@NBT": 479,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 3,
            "@ST": 1,
            "@SX": 0,
            "@HT": 48,
            "@AK": 24
        },

        "BLS48": {
            "BITS": "560",
            "FIELD": "BLS48",
            "CURVE": "BLS48",
            "@NB": 70,
            "@BASE": 23,
            "@NBT": 556,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 4,
            "@ST": 1,
            "@SX": 0,
            "@HT": 64,
            "@AK": 32
        },

        "BLS381": {
            "BITS": "381",
            "FIELD": "BLS381",
            "CURVE": "BLS381",
            "@NB": 48,
            "@BASE": 23,
            "@NBT": 381,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 2,
            "@ST": 1,
            "@SX": 1,
            "@HT": 32,
            "@AK": 16
        },

        "BLS461": {
            "BITS": "464",
            "FIELD": "BLS461",
            "CURVE": "BLS461",
            "@NB": 58,
            "@BASE": 23,
            "@NBT": 461,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 2,
            "@ST": 1,
            "@SX": 1,
            "@HT": 32,
            "@AK": 16
        },

        "RSA2048": {
            "BITS": "1024",
            "TFF": "2048",
            "@NB": 128,
            "@BASE": 22,
            "@ML": 2,
        },

        "RSA3072": {
            "BITS": "384",
            "TFF": "3072",
            "@NB": 48,
            "@BASE": 23,
            "@ML": 8,
        },

        "RSA4096": {
            "BITS": "512",
            "TFF": "4096",
            "@NB": 64,
            "@BASE": 23,
            "@ML": 8,
        },
    };

    ctx["AES"] = AES();
    ctx["GCM"] = GCM(ctx);
    ctx["UInt64"] = UInt64();
    ctx["HASH256"] = HASH256();
    ctx["HASH384"] = HASH384(ctx);
    ctx["HASH512"] = HASH512(ctx);
    ctx["SHA3"] = SHA3(ctx);
    ctx["RAND"] = RAND(ctx);
    ctx["NHS"] = NHS(ctx);

    if (typeof input_parameter === "undefined") {
        return;
    }

    ctx.config = CTXLIST[input_parameter];

    // Set BIG parameters
    ctx["BIG"] = BIG(ctx);
    ctx["DBIG"] = DBIG(ctx);

    // Set RSA parameters
    if (typeof ctx.config["TFF"] !== "undefined") {
        ctx["FF"] = FF(ctx);
        ctx["RSA"] = RSA(ctx);
        ctx["rsa_public_key"] = rsa_public_key(ctx);
        ctx["rsa_private_key"] = rsa_private_key(ctx);
        return;
    }

    // Set Elliptic Curve parameters
    if (typeof ctx.config["CURVE"] !== "undefined") {
        ctx["ROM_CURVE"] = ROM_CURVE[ctx.config["CURVE"]];
        ctx["ROM_FIELD"] = ROM_FIELD[ctx.config["FIELD"]];

        ctx["FP"] = FP(ctx);
        ctx["ECP"] = ECP(ctx);
        ctx["ECDH"] = ECDH(ctx);

        if (ctx.config["@PF"] == 1 || ctx.config["@PF"] == 2) {
            ctx["FP2"] = FP2(ctx);
            ctx["FP4"] = FP4(ctx);
            ctx["FP12"] = FP12(ctx);
            ctx["ECP2"] = ECP2(ctx);
            ctx["PAIR"] = PAIR(ctx);
            ctx["MPIN"] = MPIN(ctx);
        }

        if (ctx.config["@PF"] == 3) {
            ctx["FP2"] = FP2(ctx);
            ctx["FP4"] = FP4(ctx);
            ctx["FP8"] = FP8(ctx);
            ctx["FP24"] = FP24(ctx);
            ctx["ECP4"] = ECP4(ctx);
            ctx["PAIR192"] = PAIR192(ctx);
            ctx["MPIN192"] = MPIN192(ctx);
        }

        if (ctx.config["@PF"] == 4) {
            ctx["FP2"] = FP2(ctx);
            ctx["FP4"] = FP4(ctx);
            ctx["FP8"] = FP8(ctx);
            ctx["FP16"] = FP16(ctx);
            ctx["FP48"] = FP48(ctx);
            ctx["ECP8"] = ECP8(ctx);
            ctx["PAIR256"] = PAIR256(ctx);
            ctx["MPIN256"] = MPIN256(ctx);
        }

        return;
    }
}

var CryptoContexts = {};

function Crypto(seed) {
    var self = this,
        entropyBytes;

    // Initialize RNG
    self.rng = new (self._crypto().RAND)();
    self.rng.clean();

    // Seed the RNG
    entropyBytes = self._hexToBytes(seed);
    self.rng.seed(entropyBytes.length, entropyBytes);
}

Crypto.prototype._crypto = function (curve) {
    // Set to default curve if not provided
    if (!curve) {
        curve = "BN254CX";
    }

    if (!CryptoContexts[curve]) {
        // Create a new curve context
        CryptoContexts[curve] = new CTX(curve);

        // Change maximum PIN length to 6 digits
        CryptoContexts[curve].MPIN.MAXPIN = 1000000;

        // Modify MPIN settings
        CryptoContexts[curve].MPIN.PBLEN = 20;
        CryptoContexts[curve].MPIN.TRAP = 2000;
    }

    return CryptoContexts[curve];
};

Crypto.prototype.generateKeypair = function (curve) {
    var self = this,
        privateKeyBytes = [],
        publicKeyBytes = [],
        errorCode;

    errorCode = self._crypto(curve).MPIN.GET_DVS_KEYPAIR(self.rng, privateKeyBytes, publicKeyBytes);
    if (errorCode != 0) {
        throw new Error("Could not generate key pair: " + errorCode);
    }

    return { publicKey: self._bytesToHex(publicKeyBytes), privateKey: self._bytesToHex(privateKeyBytes) };
};

/**
 * Add two points on the curve that are originally in hex format
 * This function is used to add client secret shares.
 * Returns a hex encoded sum of the shares
 * @private
 */
Crypto.prototype.addShares = function (privateKeyHex, share1Hex, share2Hex, curve) {
    var self = this,
        privateKeyBytes = [],
        share1Bytes = [],
        share2Bytes = [],
        clientSecretBytes = [],
        errorCode;

    privateKeyBytes = self._hexToBytes(privateKeyHex);
    share1Bytes = self._hexToBytes(share1Hex);
    share2Bytes = self._hexToBytes(share2Hex);

    errorCode = self._crypto(curve).MPIN.RECOMBINE_G1(share1Bytes, share2Bytes, clientSecretBytes);
    if (errorCode !== 0) {
        throw new Error("Could not combine the client secret shares: " + errorCode);
    }

    errorCode = self._crypto(curve).MPIN.GET_G1_MULTIPLE(null, 0, privateKeyBytes, clientSecretBytes, clientSecretBytes);
    if (errorCode != 0) {
        throw new Error("Could not combine private key with client secret: " + errorCode);
    }

    return self._bytesToHex(clientSecretBytes);
};

/**
 * Calculates the MPin Token
 * This function maps the M-Pin ID to a point on the curve,
 * multiplies this value by PIN and then subtractsit from
 * the client secret curve point to generate the M-Pin token.
 * Returns a hex encoded M-Pin Token
 * @private
 */
Crypto.prototype.extractPin = function (mpinId, publicKey, PIN, clientSecretHex, curve) {
    var self = this,
        clientSecretBytes = [],
        mpinIdBytes = [],
        errorCode;

    clientSecretBytes = self._hexToBytes(clientSecretHex);
    mpinIdBytes = self._hexToBytes(self._mpinIdWithPublicKey(mpinId, publicKey));

    errorCode = self._crypto(curve).MPIN.EXTRACT_PIN(self._crypto(curve).MPIN.SHA256, mpinIdBytes, PIN, clientSecretBytes);
    if (errorCode !== 0) {
        throw new Error("Could not extract PIN from client secret: " + errorCode);
    }

    return self._bytesToHex(clientSecretBytes);
};

Crypto.prototype.calculatePass1 = function (curve, mpinId, publicKey, token, userPin, X, SEC) {
    var self = this,
        mpinIdHex,
        errorCode,
        U = [],
        UT = [];

    mpinIdHex = self._mpinIdWithPublicKey(mpinId, publicKey);

    errorCode = self._crypto(curve).MPIN.CLIENT_1(
        self._crypto(curve).MPIN.SHA256,
        0,
        self._hexToBytes(mpinIdHex),
        self.rng,
        X,
        userPin,
        self._hexToBytes(token),
        SEC,
        U,
        UT,
        self._hexToBytes(0)
    );

    if (errorCode !== 0) {
        throw new Error("Could not calculate pass 1 request data: " + errorCode);
    }

    return {
        UT: self._bytesToHex(UT),
        U: self._bytesToHex(U)
    };
};

Crypto.prototype.calculatePass2 = function (curve, X, yHex, SEC) {
    var self = this,
        errorCode;

    errorCode = self._crypto(curve).MPIN.CLIENT_2(X, self._hexToBytes(yHex), SEC);

    if (errorCode !== 0) {
        throw new Error("Could not calculate pass 2 request data: " + errorCode);
    }

    return self._bytesToHex(SEC);
};

Crypto.prototype.sign = function (curve, mpinId, publicKey, token, userPin, message, timestamp) {
    var self = this,
        mpinIdHex,
        errorCode,
        SEC = [],
        X = [],
        Y1 = [],
        U = [];

    mpinIdHex = self._mpinIdWithPublicKey(mpinId, publicKey);

    errorCode = self._crypto(curve).MPIN.CLIENT(
        self._crypto(curve).MPIN.SHA256,
        0,
        self._hexToBytes(mpinIdHex),
        self.rng,
        X,
        userPin,
        self._hexToBytes(token),
        SEC,
        U,
        null,
        null,
        timestamp,
        Y1,
        self._hexToBytes(message)
    );

    if (errorCode != 0) {
        throw new Error("Could not sign message: " + errorCode);
    }

    return {
        U: self._bytesToHex(U),
        V: self._bytesToHex(SEC)
    };
};

/**
 * Returns the public key bytes appended to the MPin ID bytes in hex encoding
 * @private
 */
Crypto.prototype._mpinIdWithPublicKey = function (mpinId, publicKey) {
    var self = this,
        mpinIdBytes = self._hexToBytes(mpinId),
        publicKeyBytes = self._hexToBytes(publicKey),
        i;

    if (!mpinIdBytes) {
        return;
    }

    if (!publicKeyBytes) {
        return mpinId;
    }

    for (i = 0; i < publicKeyBytes.length; i++) {
        mpinIdBytes.push(publicKeyBytes[i]);
    }

    return self._bytesToHex(mpinIdBytes);
};

Crypto.prototype._hexToBytes = function (hexValue) {
    var len, byteValue, i;

    if (!hexValue) {
        return;
    }

    len = hexValue.length;
    byteValue = [];

    for (i = 0; i < len; i += 2) {
        byteValue[(i / 2)] = parseInt(hexValue.substr(i, 2), 16);
    }

    return byteValue;
};

Crypto.prototype._bytesToHex = function (b) {
    var s = "",
        len = b.length,
        ch, i;

    for (i = 0; i < len; i++) {
        ch = b[i];
        s += ((ch >>> 4) & 15).toString(16);
        s += (ch & 15).toString(16);
    }

    return s;
};

/**
 * User management utility. Initialized by {@link Client}
 * @class
 *
 * @param {Object} storage
 * @param {string} projectId
 * @param {string} storageKey
 */
function Users(storage, projectId, storageKey) {
    var self = this;

    if (typeof storage.getItem !== "function" || typeof storage.setItem !== "function") {
        throw new Error("Invalid user storage object");
    }

    if (!projectId) {
        throw new Error("Project ID must be provided when configuring storage");
    }

    if (!storageKey) {
        throw new Error("Storage key must be provided when configuring storage");
    }

    self.storage = storage;
    self.projectId = projectId;
    self.storageKey = storageKey;

    self.loadData();
}

Users.prototype.data = [],

Users.prototype.states = {
    start: "STARTED",
    register: "REGISTERED",
    revoked: "REVOKED"
};

Users.prototype.loadData = function () {
    var self = this;

    self.data = JSON.parse(self.storage.getItem(self.storageKey)) || [];

    self.store();

    // Sort list by last used timestamp
    self.data.sort(function (a, b) {
        if (a.lastUsed && (!b.lastUsed || a.lastUsed > b.lastUsed)) {
            return 1;
        }

        if (b.lastUsed && (!a.lastUsed || a.lastUsed < b.lastUsed)) {
            return -1;
        }

        return 0;
    });
};

Users.prototype.write = function (userId, userData) {
    var self = this, i, uKey;

    if (!self.exists(userId)) {
        self.data.push({
            userId: userId,
            projectId: self.projectId,
            state: self.states.invalid,
            created: Math.round(new Date().getTime() / 1000)
        });
    }

    for (i = 0; i < self.data.length; ++i) {
        if (self.data[i].userId === userId && (self.data[i].projectId === self.projectId || self.data[i].customerId === self.projectId)) {
            for (uKey in userData) {
                if (userData[uKey]) {
                    self.data[i][uKey] = userData[uKey];
                }
            }
        }
    }

    self.store();
};

Users.prototype.updateLastUsed = function (userId) {
    this.write(userId, { lastUsed: new Date().getTime() });
};

/**
 * Check if an user with the specified user ID exists
 * @param {string} userId - The ID of the user
 * @returns {boolean}
 */
Users.prototype.exists = function (userId) {
    return typeof this.get(userId, "userId") !== "undefined";
};

/**
 * Check if an user is in a specific state
 * @param {string} userId - The ID of the user
 * @param {string} state - The state to check for
 * @returns {boolean} - Returns true if the state of the user matches the state argument
 */
Users.prototype.is = function (userId, state) {
    return this.get(userId, "state") === state;
};

/**
 * Get a property of the user
 * @param {string} userId - The ID of the user
 * @param {string} userProperty - The name of the property to be fetched
 * @returns {string} - The value of the user property. Will return undefined if property doesn't exist
 */
Users.prototype.get = function (userId, userProperty) {
    var self = this, i;

    for (i = 0; i < self.data.length; ++i) {
        if (self.data[i].userId === userId && (self.data[i].projectId === self.projectId || self.data[i].customerId === self.projectId)) {
            if (userProperty) {
                // Return requested property
                return self.data[i][userProperty] || "";
            } else {
                // Return the whole user data if no property is requested
                return self.data[i];
            }
        }
    }
};

/**
 * List all identities
 * @returns {Object}
 */
Users.prototype.list = function () {
    var self = this, usersList = {}, i;

    for (i = 0; i < self.data.length; ++i) {
        if (self.data[i].projectId === self.projectId || self.data[i].customerId === self.projectId) {
            usersList[self.data[i].userId] = self.data[i].state;
        }
    }

    return usersList;
};

/**
 * Returns an array of all user objects
 * @returns {Array}
 */
Users.prototype.all = function () {
    var self = this,
        users = [],
        i;

    for (i = 0; i < self.data.length; ++i) {
        if (self.data[i].projectId === self.projectId || self.data[i].customerId === self.projectId) {
            users.push(self.data[i]);
        }
    }

    return users;
};

/**
 * Returns the number of registered identities
 * @return {number}
 */
Users.prototype.count = function () {
    return Object.keys(this.list()).length;
};

/**
 * Remove an identity
 * @param {string} userId - The ID of the user
 */
Users.prototype.remove = function (userId) {
    var self = this, i;

    if (!self.exists(userId)) {
        return;
    }

    for (i = 0; i < self.data.length; ++i) {
        if (self.data[i].userId === userId && (self.data[i].projectId === self.projectId || self.data[i].customerId === self.projectId)) {
            self.data.splice(i, 1);
        }
    }

    self.store();
};

Users.prototype.store = function () {
    var self = this,
        i;

    // Ensure that there is no sensitive data before storing it
    for (i = 0; i < self.data.length; ++i) {
        delete self.data[i].csHex;
        delete self.data[i].regOTT;
    }

    self.storage.setItem(self.storageKey, JSON.stringify(self.data));
};

function HTTP(timeout, clientName, projectId, cors) {
    this.requestTimeout = timeout;
    this.clientName = clientName;
    this.projectId = projectId;
    this.cors = cors;
}

/**
 * Make an HTTP request
 * @private
 */
HTTP.prototype.request = function (options, callback) {
    var self = this, url, type, request;

    if (typeof callback !== "function") {
        throw new Error("Bad or missing callback");
    }

    if (!options.url) {
        throw new Error("Missing URL for request");
    }

    request = new XMLHttpRequest();

    url = options.url;
    type = options.type || "GET";

    request.onreadystatechange = function () {
        var response;

        if (request.readyState === 4 && request.status === 200) {
            try {
                response = JSON.parse(request.responseText);
            } catch (e) {
                response = request.responseText;
            }

            callback(null, response);
        } else if (request.readyState === 4) {
            if (request.status === 0) {
                callback(new Error("The request was aborted"), { status: 0 });
                return;
            }

            try {
                response = JSON.parse(request.responseText);
            } catch (e) {
                callback(new Error(request.statusText), { status: request.status });
                return;
            }

            callback(new Error(response.info), {
                status: request.status,
                error: response.error,
                context: response.context
            });
        }
    };


    if (self.cors) {
        url += (url.indexOf("?") !== -1 ? "&" : "?") + "project_id=" + self.projectId;
    }

    request.open(type, url, true);

    request.timeout = self.requestTimeout;

    request.setRequestHeader("X-MIRACL-CID", self.projectId);
    request.setRequestHeader("X-MIRACL-CLIENT", self.clientName);

    // Set authorization header if provided
    if (options.authorization) {
        request.setRequestHeader("Authorization", options.authorization);
    }

    if (options.data) {
        request.setRequestHeader("Content-Type", "application/json");
        request.send(JSON.stringify(options.data));
    } else {
        request.send();
    }

    return request;
};

/**
 * @class
 * @param {Object} options
 * @param {string} options.projectUrl - MIRACL Trust Project URL that is used for communication with the MIRACL Trust API
 * @param {string} options.projectId - MIRACL Trust Project ID
 * @param {string} options.seed - Hex encoded random number generator seed
 * @param {string} options.deviceName - Name of the current device
 * @param {Object} options.userStorage - Storage for saving user data
 * @param {Object} options.oidc - Parameters for initializing an OIDC auth session
 * @param {string} options.oidc.client_id - OIDC client ID
 * @param {string} options.oidc.redirect_uri - OIDC redirect URI
 * @param {string} options.oidc.response_type - OIDC response type. Only 'code' is supported
 * @param {string} options.oidc.scope - OIDC scope. Must include 'openid'
 * @param {string} options.oidc.state - OIDC state
 * @param {bool}   options.cors - Enable CORS requests if set to 'true'
 * @param {number} options.requestTimeout - Time before a HTTP request times out in miliseconds
 * @param {string} options.applicationInfo - Sets additional information that will be sent via X-MIRACL-CLIENT HTTP header
 */
function Client(options) {
    var self = this;

    if (!options) {
        throw new Error("Invalid configuration");
    }

    if (!options.projectId) {
        throw new Error("Empty project ID");
    }

    if (!options.userStorage) {
        throw new Error("Invalid user storage");
    }

    if (!options.projectUrl) {
        options.projectUrl = "https://api.mpin.io";
    } else {
        // remove trailing slash from url, if there is one
        options.projectUrl = options.projectUrl.replace(/\/$/, "");
    }

    // Ensure that default PIN lenght is between 4 and 6
    if (!options.defaultPinLength || options.defaultPinLength > 6 || options.defaultPinLength < 4) {
        options.defaultPinLength = 4;
    }

    if (!options.requestTimeout || isNaN(options.requestTimeout)) {
        options.requestTimeout = 4000;
    }

    if (!options.oidc) {
        options.oidc = {};
    }

    // Set the client name using the current lib version and provided application info
    options.clientName = "MIRACL Client.js/8.8.0" + (options.applicationInfo ? " " + options.applicationInfo : "");

    self.options = options;

    self.http = new HTTP(options.requestTimeout, options.clientName, options.projectId, options.cors);

    self.crypto = new Crypto(options.seed);

    self.users = new Users(options.userStorage, options.projectId, "mfa");
}

Client.prototype.options = {};

Client.prototype.session = {};

/**
 * Set the access(session) ID
 *
 * @param {string} accessId
 */
Client.prototype.setAccessId = function (accessId) {
    this.session.accessId = accessId;
};

/**
 * Make a request to start a new session and fetch the access(session) ID
 *
 * @param {string} userId - The unique identifier of the user that will be authenticating (not required)
 * @param {function(Error, Object)} callback
 */
Client.prototype.fetchAccessId = function (userId, callback) {
    var self = this,
        reqData;

    reqData = {
        url: self.options.projectUrl + "/rps/v2/session",
        type: "POST",
        data: {
            projectId: self.options.projectId,
            userId: userId
        }
    };

    self.http.request(reqData, function (error, res) {
        if (error) {
            return callback(error, null);
        }

        self.session = res;

        callback(null, res);
    });
};

/**
 * Request for changes in status
 *
 * @param {function(Error, Object)} callback
 */
Client.prototype.fetchStatus = function (callback) {
    var self = this,
        reqData;

    reqData = {
        url: self.options.projectUrl + "/rps/v2/access",
        type: "POST",
        data: {
            webOTT: self.session.webOTT
        }
    };

    self.http.request(reqData, function (error, data) {
        if (error) {
            return callback(error, null);
        }

        callback(null, data);
    });
};

/**
 * Start the push authentication flow
 *
 * @param {string} userId - The unique identifier of the user that will be authenticating
 * @param {function(Error, Object)} callback
 */
Client.prototype.sendPushNotificationForAuth = function (userId, callback) {
    var self = this,
        reqData;

    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    reqData = {
        url: self.options.projectUrl + "/pushauth?" + self._urlEncode(self.options.oidc),
        type: "POST",
        data: {
            prerollId: userId
        }
    };

    self.http.request(reqData, function (err, result) {
        if (err) {
            if (result && result.error === "NO_PUSH_TOKEN") {
                return callback(new Error("No push token", { cause: err }));
            }

            return callback(err, null);
        }

        self.session.webOTT = result.webOTT;

        callback(null, result);
    });
};

/**
 * Start the verification process for a specified user ID (must be email)
 *
 * @param {string} userId - The email to start verification for
 * @param {function(Error, Object)} callback
 */
Client.prototype.sendVerificationEmail = function (userId, callback) {
    var self = this,
        reqData = {};

    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    reqData.url = self.options.projectUrl + "/verification/email";
    reqData.type = "POST";
    reqData.data = {
        userId: userId,
        mpinId: self.users.get(userId, "mpinId"),
        projectId: self.options.projectId,
        accessId: self.session.accessId,
        deviceName: self._getDeviceName(),
        clientId: self.options.oidc["client_id"],
        redirectURI: self.options.oidc["redirect_uri"],
        scope: self.options.oidc["scope"] ? self.options.oidc["scope"].split(" ") : [],
        state: self.options.oidc["state"],
        nonce: self.options.oidc["nonce"]
    };

    self.http.request(reqData, function (err, result) {
        if (err) {
            if (result && result.error === "REQUEST_BACKOFF") {
                return callback(new Error("Request backoff", { cause: err }), result);
            }

            return callback(new Error("Verification fail", { cause: err }), result);
        }

        callback(null, result);
    });
};

/**
 * Finish the verification process
 *
 * @param {string} verificationURI - The URI received in the email containing the verification code
 * @param {function(Error, Object)} callback
 */
Client.prototype.getActivationToken = function (verificationURI, callback) {
    var self = this,
        reqData = {},
        params;

    params = self._parseUriParams(verificationURI);

    if (!params["user_id"]) {
        return callback(new Error("Empty user ID"), null);
    }

    if (!params["code"]) {
        return callback(new Error("Empty verification code"), null);
    }

    reqData.url = self.options.projectUrl + "/verification/confirmation";
    reqData.type = "POST";
    reqData.data = {
        userId: params["user_id"],
        code: params["code"]
    };

    self.http.request(reqData, function (err, result) {
        if (err) {
            if (result && result.error === "UNSUCCESSFUL_VERIFICATION") {
                return callback(new Error("Unsuccessful verification", { cause: err }), result);
            }

            return callback(new Error("Get activation token fail", { cause: err }), result);
        }

        result.userId = params["user_id"];
        callback(null, result);
    });
};

/**
 * Create an identity for the specified user ID
 *
 * @param {string} userId - The unique identifier of the user
 * @param {string} activationToken - The code received from the verification process
 * @param {function} pinCallback - Called when the PIN code needs to be entered
 * @param {function(Error, Object)} callback
 */
Client.prototype.register = function (userId, activationToken, pinCallback, callback) {
    var self = this,
        keypair;

    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    if (!activationToken) {
        return callback(new Error("Empty activation token"), null);
    }

    keypair = self.crypto.generateKeypair("BN254CX");

    self._createMPinID(userId, activationToken, keypair, function (err, identityData) {
        if (err) {
            if (identityData && identityData.error === "INVALID_ACTIVATION_TOKEN") {
                return callback(new Error("Invalid activation token", { cause: err }), null);
            }

            return callback(new Error("Registration fail", { cause: err }), null);
        }

        if (identityData.projectId !== self.options.projectId) {
            return callback(new Error("Project mismatch"), null);
        }

        self._getSecret(identityData.secretUrls[0], function (err, sec1Data) {
            if (err) {
                return callback(new Error("Registration fail", { cause: err }), null);
            }

            self._getSecret(identityData.secretUrls[1], function (err, sec2Data) {
                if (err) {
                    return callback(new Error("Registration fail", { cause: err }), null);
                }

                var pinLength,
                    passPin;

                pinLength = identityData.pinLength;
                if (!pinLength) {
                    pinLength = self.options.defaultPinLength;
                }

                // should be called to continue the flow
                // after a PIN was provided
                passPin = function (userPin) {
                    self._createIdentity(userId, userPin, identityData, sec1Data, sec2Data, keypair, callback);
                };

                pinCallback(passPin, pinLength);
            });
        });
    });
};

Client.prototype._createMPinID = function (userId, activationToken, keypair, callback) {
    var self = this,
        regData = {};

    regData.url = self.options.projectUrl + "/registration";
    regData.type = "POST";
    regData.data = {
        userId: userId,
        deviceName: self._getDeviceName(),
        activationToken: activationToken,
        publicKey: keypair.publicKey
    };

    self.http.request(regData, function (err, result) {
        if (err) {
            return callback(err, result);
        }

        self.users.write(userId, { state: self.users.states.start });

        callback(null, result);
    });
};

Client.prototype._getDeviceName = function () {
    var self = this;

    if (self.options.deviceName) {
        return self.options.deviceName;
    }

    return "Browser";
};

Client.prototype._getSecret = function (secretUrl, callback) {
    var self = this,
        requestData = { url: secretUrl };

    self.http.request(requestData, function (err, result) {
        if (err) {
            if (err.message === "The request was aborted") {
                self.http.request(requestData, callback);
            } else {
                callback(err, result);
            }

            return;
        }

        callback(null, result);
    });
};

Client.prototype._createIdentity = function (userId, userPin, identityData, sec1Data, sec2Data, keypair, callback) {
    var self = this,
        userData,
        csHex,
        token;

    try {
        csHex = self.crypto.addShares(keypair.privateKey, sec1Data.dvsClientSecret, sec2Data.dvsClientSecret, identityData.curve);
        token = self.crypto.extractPin(identityData.mpinId, keypair.publicKey, userPin, csHex, identityData.curve);
    } catch (err) {
        return callback(err, null);
    }

    userData = {
        mpinId: identityData.mpinId,
        token: token,
        curve: identityData.curve,
        dtas: identityData.dtas,
        publicKey: keypair.publicKey,
        pinLength: identityData.pinLength,
        projectId: identityData.projectId,
        verificationType: identityData.verificationType,
        state: self.users.states.register,
        nowTime: identityData.nowTime,
        updated: Math.floor(Date.now() / 1000)
    };
    self.users.write(userId, userData);

    callback(null, userData);
};

/**
 * Authenticate the user with the specified user ID
 *
 * @param {string} userId - The unique identifier of the user
 * @param {string} userPin - The PIN associated with the userId
 * @param {function(Error, Object)} callback
 */
Client.prototype.authenticate = function (userId, userPin, callback) {
    this._authentication(userId, userPin, ["jwt"], callback);
};

/**
 * Authenticate the user for the session specified by the qrCode parameter
 *
 * @param {string} userId - The unique identifier of the user
 * @param {string} qrCode - The QR code URL that initiated the authentication
 * @param {string} userPin - The PIN associated with the userId
 * @param {function(Error, Object)} callback
 */
Client.prototype.authenticateWithQRCode = function (userId, qrCode, userPin, callback) {
    this.setAccessId(qrCode.split("#").pop());
    this._authentication(userId, userPin, ["oidc"], callback);
};

/**
 * Authenticate the user for the session specified by the appLink parameter
 *
 * @param {string} userId - The unique identifier of the user
 * @param {string} appLink - The app link that initiated the authentication
 * @param {string} userPin - The PIN associated with the userId
 * @param {function(Error, Object)} callback
 */
Client.prototype.authenticateWithAppLink = function (userId, appLink, userPin, callback) {
    this.setAccessId(appLink.split("#").pop());
    this._authentication(userId, userPin, ["oidc"], callback);
};

/**
 * Authenticate the session specified by the push notification payload
 *
 * @param {[key: string]: string} payload - The push notification payload
 * @param {string} userPin - The PIN associated with the userId
 * @param {function(Error, Object)} callback
 */
Client.prototype.authenticateWithNotificationPayload = function (payload, userPin, callback) {
    if (!payload || !payload["userID"] || !payload["qrURL"]) {
        return callback(new Error("Invalid push notification payload"), null);
    }

    this.setAccessId(payload["qrURL"].split("#").pop());
    this._authentication(payload["userID"], userPin, ["oidc"], callback);
};

/**
 * Fetch a registration (bootstrap) code for the specified user ID
 *
 * @param {string} userId - The unique identifier of the user
 * @param {string} userPin - The PIN associated with the userId
 * @param {function(Error, Object)} callback
 */
Client.prototype.generateQuickCode = function (userId, userPin, callback) {
    var self = this;

    self._authentication(userId, userPin, ["reg-code"], function (err, result) {
        if (err) {
            return callback(err, null);
        }

        self.http.request({
            url: self.options.projectUrl + "/verification/quickcode",
            type: "POST",
            data: {
                projectId: self.options.projectId,
                jwt: result.jwt,
                deviceName: self._getDeviceName()
            }
        }, function (err, result) {
            if (err) {
                return callback(err, null);
            }

            callback(null, {
                code: result.code,
                expireTime: result.expireTime,
                ttlSeconds: result.ttlSeconds,
                // Deprecated, kept for backward compatibility
                OTP: result.code
            });
        });
    });
};

Client.prototype._authentication = function (userId, userPin, scope, callback) {
    var self = this,
        identityData,
        SEC = [],
        X = [];

    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    if (!self.users.exists(userId)) {
        return callback(new Error("User not found"), null);
    }

    identityData = self.users.get(userId);

    self._getPass1(identityData, userPin, scope, X, SEC, function (err, pass1Data) {
        if (err) {
            if (pass1Data && pass1Data.error === "EXPIRED_MPINID") {
                self.users.write(userId, { state: self.users.states.revoked });
                return callback(new Error("Revoked", { cause: err }), null);
            }

            return callback(new Error("Authentication fail", { cause: err }), null);
        }

        self._getPass2(identityData, scope, pass1Data.y, X, SEC, function (err, pass2Data) {
            if (err) {
                return callback(new Error("Authentication fail", { cause: err }), null);
            }

            self._finishAuthentication(userId, userPin, scope, pass2Data.authOTT, function (err, result) {
                if (err) {
                    if (result && result.error === "UNSUCCESSFUL_AUTHENTICATION") {
                        return callback(new Error("Unsuccessful authentication", { cause: err }), null);
                    }

                    if (result && result.error === "REVOKED_MPINID") {
                        self.users.write(userId, { state: self.users.states.revoked });
                        return callback(new Error("Revoked", { cause: err }), null);
                    }

                    return callback(new Error("Authentication fail", { cause: err }), null);
                }

                callback(null, result);
            });
        });
    });
};

/**
 * Make a request for pass one of the M-Pin protocol
 *
 * This function assigns to the property X a random value. It assigns to
 * the property SEC the sum of the client secret and time permit. It also
 * calculates the values U and UT which are required for M-Pin authentication,
 * where U = X.(map_to_curve(MPIN_ID)) and UT = X.(map_to_curve(MPIN_ID) + map_to_curve(DATE|sha256(MPIN_ID))
 * UT is called the commitment. U is the required for finding the PIN error.
 *
 * Request data has the following structure:
 * {
 *    mpin_id: mpinIdHex,   // Hex encoded M-Pin ID
 *    dtas: dtaList         // Identifier of the DTAs used for this identity
 *    UT: UT_hex,           // Hex encoded UT
 *    U: U_hex,             // Hex encoded U
 *    publicKey: publicKey, // The public key used for DVS
 *    scope: ['oidc']       // Scope of the authentication
 * }
 * @private
 */
Client.prototype._getPass1 = function (identityData, userPin, scope, X, SEC, callback) {
    var self = this,
        res,
        requestData;

    try {
        res = self.crypto.calculatePass1(identityData.curve, identityData.mpinId, identityData.publicKey, identityData.token, userPin, X, SEC);
    } catch (err) {
        return callback(err, null);
    }

    requestData = {
        scope: scope,
        mpin_id: identityData.mpinId,
        dtas: identityData.dtas,
        publicKey: identityData.publicKey,
        UT: res.UT,
        U: res.U
    };

    self.http.request({ url: self.options.projectUrl + "/rps/v2/pass1", type: "POST", data: requestData }, callback);
};

/**
 * Make a request for pass two of the M-Pin protocol
 *
 * This function uses the random value y from the server, property X
 * and the combined client secret and time permit to calculate
 * the value V which is sent to the M-Pin server.
 *
 * Request data has the following structure:
 * {
 *    mpin_id: mpinIdHex, // Hex encoded M-Pin ID
 *    V: V_hex,           // Value required by the server to authenticate user
 *    WID: accessNumber   // Number required for mobile authentication
 * }
 * @private
 */
Client.prototype._getPass2 = function (identityData, scope, yHex, X, SEC, callback) {
    var self = this,
        vHex,
        requestData;

    try {
        vHex = self.crypto.calculatePass2(identityData.curve, X, yHex, SEC);
    } catch (err) {
        return callback(err, null);
    }

    requestData = {
        mpin_id: identityData.mpinId,
        WID: self.session.accessId,
        V: vHex
    };

    self.http.request({ url: self.options.projectUrl + "/rps/v2/pass2", type: "POST", data: requestData}, callback);
};

Client.prototype._finishAuthentication = function (userId, userPin, scope, authOTT, callback) {
    var self = this,
        requestData;

    requestData = {
        "authOTT": authOTT,
        "wam": "dvs"
    };

    self.http.request({ url: self.options.projectUrl + "/rps/v2/authenticate", type: "POST", data: requestData }, function (err, result) {
        if (err) {
            return callback(err, result);
        }

        if (result.dvsRegister) {
            self._renewSecret(userId, userPin, result.dvsRegister, function(err) {
                if (err) {
                    return callback(err, null);
                }

                self._authentication(userId, userPin, scope, callback);
            });
        } else {
            self.users.updateLastUsed(userId);
            callback(null, result);
        }
    });
};

Client.prototype._renewSecret = function (userId, userPin, activationData, callback) {
    var self = this,
        keypair;

    keypair = self.crypto.generateKeypair(activationData.curve);

    self._createMPinID(userId, activationData.token, keypair, function (err, identityData) {
        if (err) {
            return callback(err, null);
        }

        self._getSecret(identityData.secretUrls[0], function (err, sec1Data) {
            if (err) {
                return callback(err, null);
            }

            self._getSecret(identityData.secretUrls[1], function (err, sec2Data) {
                if (err) {
                    return callback(err, null);
                }

                self._createIdentity(userId, userPin, identityData, sec1Data, sec2Data, keypair, callback);
            });
        });
    });
};

/**
 * Create a cryptographic signature of a given message
 *
 * @param {string} userId - The unique identifier of the user
 * @param {string} userPin - The PIN associated with the userId
 * @param {string} message - The message that will be signed
 * @param {number} timestamp - The creation timestamp of the message
 * @param {function(Error, Object)} callback
 */
Client.prototype.sign = function (userId, userPin, message, timestamp, callback) {
    var self = this,
        identityData;

    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    if (!self.users.exists(userId)) {
        return callback(new Error("User not found"), null);
    }

    if (!message) {
        return callback(new Error("Empty message"), null);
    }

    identityData = self.users.get(userId);

    if (!identityData.publicKey) {
        return callback(new Error("Empty public key"), null);
    }

    this._authentication(userId, userPin, ["dvs-auth"], function (err) {
        var res,
            signatureData;

        if (err) {
            switch (err.message) {
                case "Unsuccessful authentication":
                case "Revoked":
                    return callback(err, null);

                default:
                    return callback(new Error("Signing fail", { cause: err.cause }), null);
            }
        }

        try {
            res = self.crypto.sign(identityData.curve, identityData.mpinId, identityData.publicKey, identityData.token, userPin, message, timestamp);
        } catch (err) {
            return callback(new Error("Signing fail", { cause: err }), null);
        }

        signatureData = {
            hash: message,
            u: res.U,
            v: res.V,
            mpinId: identityData.mpinId,
            publicKey: identityData.publicKey,
            dtas: identityData.dtas
        };

        callback(null, signatureData);
    });
};

Client.prototype._urlEncode = function (obj) {
    var str = [],
        p;

    for (p in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, p)) {
            str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
        }
    }

    return str.join("&");
};

Client.prototype._parseUriParams = function (uri) {
    var query = uri.split("?").pop(),
        queryArr = query.split("&"),
        params = {},
        pairArr,
        i;

    if (!query.length || !queryArr.length) {
        return params;
    }

    for (i = 0; i < queryArr.length; i++) {
        pairArr = queryArr[i].split("=");
        params[pairArr[0]] = decodeURIComponent(pairArr[1].replace(/\+/g, " "));
    }

    return params;
};

class PromiseInterface extends Client {
    fetchAccessId(userId) {
        return promisify(super.fetchAccessId.bind(this), userId);
    }

    fetchStatus() {
        return promisify(super.fetchStatus.bind(this));
    }

    sendPushNotificationForAuth(userId) {
        return promisify(super.sendPushNotificationForAuth.bind(this), userId);
    }

    sendVerificationEmail(userId) {
        return promisify(super.sendVerificationEmail.bind(this), userId);
    }

    getActivationToken(verificationURI) {
        return promisify(super.getActivationToken.bind(this), verificationURI);
    }

    register(userId, activationToken, pinCallback) {
        return promisify(super.register.bind(this), userId, activationToken, pinCallback);
    }

    authenticate(userId, userPin) {
        return promisify(super.authenticate.bind(this), userId, userPin);
    }

    authenticateWithQRCode(userId, qrCode, userPin) {
        return promisify(super.authenticateWithQRCode.bind(this), userId, qrCode, userPin);
    }

    authenticateWithAppLink(userId, appLink, userPin) {
        return promisify(super.authenticateWithAppLink.bind(this), userId, appLink, userPin);
    }

    authenticateWithNotificationPayload(payload, userPin) {
        return promisify(super.authenticateWithNotificationPayload.bind(this), payload, userPin);
    }

    generateQuickCode(userId, userPin) {
        return promisify(super.generateQuickCode.bind(this), userId, userPin);
    }

    sign(userId, userPin, message, timestamp) {
        return promisify(super.sign.bind(this), userId, userPin, message, timestamp);
    }
}

function promisify (original, ...args) {
    return new Promise((resolve, reject) => {
        original(...args, function (err, result) {
            if (err) {
                reject(err);
                return;
            }

            resolve(result);
        });
    });
}

module.exports = PromiseInterface;
