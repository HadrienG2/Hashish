/* CryptoHash class : implements an abstraction for managing several cryptographic hashes,
   which is useful as the software grows old and former hashes are broken.

      Copyright (C) 2011  Hadrien Grasland

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA */

#include <QFile>
#include <QTextStream>
#include <string.h>

#include <crypto_hash.h>
#include <error_management.h>
#include <parsing_tools.h>
#include <qstring_to_qwords.h>
#include <test_suite.h>

SHA512Hash sha_512_hash;
CryptoHash& default_hash = sha_512_hash;

CryptoHash* crypto_hash_database(const QString& hash_name) {
    if(hash_name == sha_512_hash.name()) {
        return &sha_512_hash;
    }

    return NULL;
}

bool test_crypto_hashes() {
    bool result = sha_512_hash.test();
    if(!result) return false;

    return true;
}

const QString CRYPTO_HASH_NAME("CryptoHash");

bool CryptoHash::test() {
    const QString file_path = TEST_VEC_FILEPATH.arg(name());
    QString line, result;
    size_t qw_message_length = 0;
    uint64_t* qw_message = NULL;
    size_t qw_result_length = hash_length();
    uint64_t qw_result[qw_result_length];

    //Open test file
    QFile test_file(file_path);
    if(test_file.exists() == false) {
        log_error(CRYPTO_HASH_NAME, ERR_FILE_NOT_FOUND.arg(file_path));
        return false;
    }
    if(test_file.open(QIODevice::ReadOnly) == false) {
        log_error(CRYPTO_HASH_NAME, ERR_FILE_OPEN_FAILURE.arg(file_path));
        return false;
    }
    QTextStream test_istream(&test_file);
    if(test_istream.readLine() != TEST_FILE_HEADER) {
        log_error(CRYPTO_HASH_NAME, ERR_FILE_HEADER_INCORRECT.arg(file_path));
        return false;
    }

    //Perform tests
    while(test_istream.atEnd() == false) {
        //Read and clean up a line of text, ignoring comments and spacing
        line = test_istream.readLine();
        isolate_content(line);
        if(line.isEmpty()) continue;

        if(has_id(line, ID_MESSAGE)) {
            //Convert message to qwords
            remove_id(line, ID_MESSAGE);
            qw_message_length = qword_length_hex(line);
            if(qw_message_length == 0) {
                log_error(CRYPTO_HASH_NAME, ERR_BAD_HEX_DATA.arg(line));
                return false;
            }
            qw_message = new uint64_t[qw_message_length];
            if(!qw_message) {
                log_error(CRYPTO_HASH_NAME, ERR_BAD_ALLOC.arg(QString("qw_message")));
                return false;
            }
            if(qwords_from_hex_str(line, qw_message) == false) {
                log_error(CRYPTO_HASH_NAME, ERR_BAD_HEX_DATA.arg(line));
                return false;
            }
            continue;
        }

        if(has_id(line, ID_RESULT)) {
            //Hash message, check result
            remove_id(line, ID_RESULT);
            hash(qw_message_length, qw_message, qw_result);
            qwords_to_hex_str(qw_result_length, qw_result, result);
            delete[] qw_message;

            if(result!=line) {
                log_error(CRYPTO_HASH_NAME, ERR_WRONG_RESULT.arg(result).arg(line));
                return false;
            }
            continue;
        }
    }

    return true;
}

const QString SHA_512_HASH_NAME("SHA512Hash");

SHA512Hash::SHA512Hash() {
    //Set initial hash value
    H0[0] = 0x6a09e667f3bcc908;
    H0[1] = 0xbb67ae8584caa73b;
    H0[2] = 0x3c6ef372fe94f82b;
    H0[3] = 0xa54ff53a5f1d36f1;
    H0[4] = 0x510e527fade682d1;
    H0[5] = 0x9b05688c2b3e6c1f;
    H0[6] = 0x1f83d9abfb41bd6b;
    H0[7] = 0x5be0cd19137e2179;

    //Set constants
    K[0] = 0x428a2f98d728ae22;
    K[1] = 0x7137449123ef65cd;
    K[2] = 0xb5c0fbcfec4d3b2f;
    K[3] = 0xe9b5dba58189dbbc;

    K[4] = 0x3956c25bf348b538;
    K[5] = 0x59f111f1b605d019;
    K[6] = 0x923f82a4af194f9b;
    K[7] = 0xab1c5ed5da6d8118;

    K[8] = 0xd807aa98a3030242;
    K[9] = 0x12835b0145706fbe;
    K[10] = 0x243185be4ee4b28c;
    K[11] = 0x550c7dc3d5ffb4e2;

    K[12] = 0x72be5d74f27b896f;
    K[13] = 0x80deb1fe3b1696b1;
    K[14] = 0x9bdc06a725c71235;
    K[15] = 0xc19bf174cf692694;

    K[16] = 0xe49b69c19ef14ad2;
    K[17] = 0xefbe4786384f25e3;
    K[18] = 0x0fc19dc68b8cd5b5;
    K[19] = 0x240ca1cc77ac9c65;

    K[20] = 0x2de92c6f592b0275;
    K[21] = 0x4a7484aa6ea6e483;
    K[22] = 0x5cb0a9dcbd41fbd4;
    K[23] = 0x76f988da831153b5;

    K[24] = 0x983e5152ee66dfab;
    K[25] = 0xa831c66d2db43210;
    K[26] = 0xb00327c898fb213f;
    K[27] = 0xbf597fc7beef0ee4;

    K[28] = 0xc6e00bf33da88fc2;
    K[29] = 0xd5a79147930aa725;
    K[30] = 0x06ca6351e003826f;
    K[31] = 0x142929670a0e6e70;

    K[32] = 0x27b70a8546d22ffc;
    K[33] = 0x2e1b21385c26c926;
    K[34] = 0x4d2c6dfc5ac42aed;
    K[35] = 0x53380d139d95b3df;

    K[36] = 0x650a73548baf63de;
    K[37] = 0x766a0abb3c77b2a8;
    K[38] = 0x81c2c92e47edaee6;
    K[39] = 0x92722c851482353b;

    K[40] = 0xa2bfe8a14cf10364;
    K[41] = 0xa81a664bbc423001;
    K[42] = 0xc24b8b70d0f89791;
    K[43] = 0xc76c51a30654be30;

    K[44] = 0xd192e819d6ef5218;
    K[45] = 0xd69906245565a910;
    K[46] = 0xf40e35855771202a;
    K[47] = 0x106aa07032bbd1b8;

    K[48] = 0x19a4c116b8d2d0c8;
    K[49] = 0x1e376c085141ab53;
    K[50] = 0x2748774cdf8eeb99;
    K[51] = 0x34b0bcb5e19b48a8;

    K[52] = 0x391c0cb3c5c95a63;
    K[53] = 0x4ed8aa4ae3418acb;
    K[54] = 0x5b9cca4f7763e373;
    K[55] = 0x682e6ff3d6b2b8a3;

    K[56] = 0x748f82ee5defb2fc;
    K[57] = 0x78a5636f43172f60;
    K[58] = 0x84c87814a1f0ab72;
    K[59] = 0x8cc702081a6439ec;

    K[60] = 0x90befffa23631e28;
    K[61] = 0xa4506cebde82bde9;
    K[62] = 0xbef9a3f7b2c67915;
    K[63] = 0xc67178f2e372532b;

    K[64] = 0xca273eceea26619c;
    K[65] = 0xd186b8c721c0c207;
    K[66] = 0xeada7dd6cde0eb1e;
    K[67] = 0xf57d4f7fee6ed178;

    K[68] = 0x06f067aa72176fba;
    K[69] = 0x0a637dc5a2c898a6;
    K[70] = 0x113f9804bef90dae;
    K[71] = 0x1b710b35131c471b;

    K[72] = 0x28db77f523047d84;
    K[73] = 0x32caab7b40c72493;
    K[74] = 0x3c9ebe0a15c9bebc;
    K[75] = 0x431d67c49c100d4c;

    K[76] = 0x4cc5d4becb3e42b6;
    K[77] = 0x597f299cfc657e2a;
    K[78] = 0x5fcb6fab3ad6faec;
    K[79] = 0x6c44198c4a475817;
}

uint64_t* SHA512Hash::hash(size_t data_length, uint64_t* data, uint64_t* dest_buffer) {
    //Set the initial hash value
    memcpy((void*) hash_value, (const void*) H0, 8*sizeof(uint64_t));

    //Generate a padded copy of the message
    size_t work_data_length = padded_message_length(data_length);
    uint64_t* work_data = new uint64_t[work_data_length];
    if(!work_data) {
        log_error(SHA_512_HASH_NAME, ERR_BAD_ALLOC.arg(QString("work_data")));
        return NULL;
    }
    gen_padded_message(data_length, data, work_data);

    //Slice padded data in blocks of 16 quadwords, process each block.
    uint64_t* final_block = work_data+work_data_length;
    for(uint64_t* current_block = work_data; current_block < final_block; current_block+=16) {
        prepare_message_schedule(current_block);

        a = hash_value[0];
        b = hash_value[1];
        c = hash_value[2];
        d = hash_value[3];
        e = hash_value[4];
        f = hash_value[5];
        g = hash_value[6];
        h = hash_value[7];

        for(int t=0; t<80; ++t) {
            T1 = h + capital_sigma_1(e) + ch(e,f,g) + K[t] + W[t];
            T2 = capital_sigma_0(a) + maj(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        hash_value[0]+= a;
        hash_value[1]+= b;
        hash_value[2]+= c;
        hash_value[3]+= d;
        hash_value[4]+= e;
        hash_value[5]+= f;
        hash_value[6]+= g;
        hash_value[7]+= h;
    }

    //Copy hash value to destination, clean up, return final hash value
    memcpy((void*) dest_buffer, (const void*) hash_value, 8*sizeof(uint64_t));

    memset((void*) W, 0, 80*sizeof(uint64_t));
    a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0, T1 = 0, T2 = 0;
    memset((void*) hash_value, 0, 8*sizeof(uint64_t));
    memset((void*) work_data, 0, work_data_length*sizeof(uint64_t));
    delete[] work_data;

    return dest_buffer;
}

uint64_t* SHA512Hash::gen_padded_message(size_t message_length, uint64_t* message, uint64_t* dest_buffer) {
    //Final padded message is made of
    // -Original message
    // -Bit "1" (endianness-dependent ?)
    // -k zeroed bits so that the final message is padded on a 1024 bits boundary
    // -Original message size in bits (128-bit number)

    //So in a quadword (QW) representation, we have :
    // -The original message
    // -Quadword "1 << 63"
    // -(k-63)/64 zeroed QWs so that final message is padded on a 16 QW boundary
    // -Original message size in bits (2 quadwords)

    //In the end, we know how much padding QWs we have, and we can allocate a
    //memory block of the right size for this new data
    memcpy((void*) dest_buffer, (const void*) message, message_length*sizeof(uint64_t));
    uint64_t* dest_buffer_parser = dest_buffer + message_length;
    *dest_buffer_parser = 1;
    *dest_buffer_parser<<= 63;
    dest_buffer_parser++;
    size_t zeroed_QWs = 16-((message_length+3)%16);
    if(zeroed_QWs == 16) zeroed_QWs = 0;
    memset((void*) dest_buffer_parser, 0, (zeroed_QWs+1)*sizeof(uint64_t));
    dest_buffer_parser+= zeroed_QWs+1;
    *dest_buffer_parser = message_length*64;

    return dest_buffer;
}

size_t SHA512Hash::padded_message_length(size_t message_length) {
    //Cf gen_padded_message() above for a description of the padded message
    size_t zeroed_QWs = 16-((message_length+3)%16);
    if(zeroed_QWs == 16) zeroed_QWs = 0;
    size_t total_padding_QWs = zeroed_QWs+3;
    return message_length + total_padding_QWs;
}

void SHA512Hash::prepare_message_schedule(uint64_t* current_block) {
    //Set W[0] to W[15] according to the current message block
    memcpy((void*) W, (const void*) current_block, 16*sizeof(uint64_t));

    //Set other values of W
    for(int t = 16; t<80; ++t) {
        W[t] = sigma_1(W[t-2]) + W[t-7] + sigma_0(W[t-15]) + W[t-16];
    }
}

uint64_t SHA512Hash::rotr(int n, uint64_t x) {
    //return (x >> n)|(x << (64-n));
    uint64_t tmp1 = x;
    tmp1>>= n;
    uint64_t tmp2 = x;
    tmp2<<= (64-n);
    tmp1|= tmp2;
    return tmp1;
}

uint64_t SHA512Hash::shr(int n, uint64_t x) {
    //return x >> n;
    uint64_t tmp = x;
    tmp>>= n;
    return tmp;
}
