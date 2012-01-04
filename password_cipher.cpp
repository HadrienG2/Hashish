/* PasswordCipher class : implements a method for storing legacy passwords in an encrypted form,
   using a generated hash as the encryption key and an OFB algorithm for block cipher chaining.

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
#include <string.h>

#include <error_management.h>
#include <parsing_tools.h>
#include <password_cipher.h>
#include <qstring_to_qwords.h>
#include <test_suite.h>

OFBChainedXorCipher ofb_chained_xor_cipher;
PasswordCipher& default_cipher = ofb_chained_xor_cipher;

PasswordCipher* cipher_database(const QString& cipher_name) {
    if(cipher_name == ofb_chained_xor_cipher.name()) {
        return &ofb_chained_xor_cipher;
    }

    return NULL;
}

bool test_password_ciphers() {
    bool result = ofb_chained_xor_cipher.test();
    if(!result) return false;

    return true;
}

const QString PASSWORD_CIPHER_NAME("PasswordCipher");

bool PasswordCipher::test() {
    const QString file_path = TEST_VEC_FILEPATH.arg(name());
    CryptoHash* hash = NULL;
    QString line, result;
    size_t qw_key_length = 0;
    uint64_t* qw_key = NULL;
    size_t qw_message_length = 0;
    uint64_t* qw_message = NULL;
    size_t qw_result_length = 0;
    uint64_t* qw_result = NULL;

    //Open test file
    QFile test_file(file_path);
    if(test_file.exists() == false) {
        log_error(PASSWORD_CIPHER_NAME, ERR_FILE_NOT_FOUND.arg(file_path));
        return false;
    }
    if(test_file.open(QIODevice::ReadOnly) == false) {
        log_error(PASSWORD_CIPHER_NAME, ERR_FILE_OPEN_FAILURE.arg(file_path));
        return false;
    }
    QTextStream test_istream(&test_file);
    if(test_istream.readLine() != TEST_FILE_HEADER) {
        log_error(PASSWORD_CIPHER_NAME, ERR_FILE_HEADER_INCORRECT.arg(file_path));
        return false;
    }

    while(test_istream.atEnd() == false) {
        //Read and clean up a line of text, ignoring comments and spacing
        line = test_istream.readLine();
        isolate_content(line);
        if(line.isEmpty()) continue;

        //When encountering a hash, use it
        if(has_id(line, ID_HASH)) {
            remove_id(line, ID_HASH);
            hash = crypto_hash_database(line);
            if(!hash) return false;
            continue;
        }

        //When encountering a hashed key, store it
        if(has_id(line, ID_KEY)) {
            remove_id(line, ID_KEY);
            qw_key_length = qword_length_hex(line);
            if(qw_key_length != hash->hash_length()) {
                if(qw_message) delete[] qw_message;
                log_error(PASSWORD_CIPHER_NAME, ERR_NOT_AN_HASHED_KEY.arg(line));
                return false;
            }
            qw_key = new uint64_t[qw_key_length];
            if(!qw_key) {
                if(qw_message) delete[] qw_message;
                log_error(PASSWORD_CIPHER_NAME, ERR_BAD_ALLOC.arg(QString("qw_key")));
                return false;
            }
            if(qwords_from_hex_str(line, qw_key) == false) {
                if(qw_message) delete[] qw_message;
                delete[] qw_key;
                log_error(PASSWORD_CIPHER_NAME, ERR_BAD_HEX_DATA.arg(line));
                return false;
            }
            continue;
        }

        //When encountering a message, store it
        if(has_id(line, ID_MESSAGE)) {
            //Convert message to qwords
            remove_id(line, ID_MESSAGE);
            qw_message_length = qword_length_hex(line);
            if(qw_message_length == 0) {
                if(qw_key) delete[] qw_key;
                log_error(PASSWORD_CIPHER_NAME, ERR_BAD_HEX_DATA.arg(line));
                return false;
            }
            qw_message = new uint64_t[qw_message_length];
            if(!qw_message) {
                if(qw_key) delete[] qw_key;
                log_error(PASSWORD_CIPHER_NAME, ERR_BAD_ALLOC.arg(QString("qw_message")));
                return false;
            }
            if(qwords_from_hex_str(line, qw_message) == false) {
                if(qw_key) delete[] qw_key;
                delete[] qw_message;
                log_error(PASSWORD_CIPHER_NAME, ERR_BAD_HEX_DATA.arg(line));
                return false;
            }

            continue;
        }

        if(has_id(line, ID_RESULT)) {
            //Compute encrypted message, check it against a known good result
            remove_id(line, ID_RESULT);
            qw_result_length = qw_message_length;
            qw_result = new uint64_t[qw_result_length];
            if(!qw_result) {
                delete[] qw_key;
                delete[] qw_message;
                log_error(PASSWORD_CIPHER_NAME, ERR_BAD_ALLOC.arg(QString("qw_result")));
                return false;
            }
            encrypt(qw_key, qw_message_length, qw_message, hash, qw_result);
            qwords_to_hex_str(qw_result_length, qw_result, result);
            delete[] qw_key;
            delete[] qw_message;
            delete[] qw_result;

            if(result!=line) {
                log_error(PASSWORD_CIPHER_NAME, ERR_WRONG_RESULT.arg(result).arg(line));
                return false;
            }
            continue;
        }
    }

    return true;
}

const QString OFB_CHAINED_XOR_CIPHER_NAME("OFBChainedXorCipher");

uint64_t* OFBChainedXorCipher::decrypt(uint64_t* hashed_key,
                                       size_t enc_message_length,
                                       uint64_t* enc_message,
                                       CryptoHash* hash,
                                       uint64_t* dest_buffer) {
    //This is a symmetric cipher, so decryption is rigorously identical to encryption
    return encrypt(hashed_key, enc_message_length, enc_message, hash, dest_buffer);
}

uint64_t* OFBChainedXorCipher::encrypt(uint64_t* hashed_key,
                                       size_t message_length,
                                       uint64_t* message,
                                       CryptoHash* hash,
                                       uint64_t* dest_buffer) {
    //Prepare the initial "key block", to be XORed with the password for encryption
    size_t key_block_length = hash->hash_length();
    uint64_t* key_block = new uint64_t[key_block_length];
    if(!key_block) {
        log_error(OFB_CHAINED_XOR_CIPHER_NAME, ERR_BAD_ALLOC.arg(QString("key_block")));
        return NULL;
    }
    uint64_t* hash_result = hash->hash(hash->hash_length(), hashed_key, key_block);
    if(!hash_result) {
        memset((void*) key_block, 0, key_block_length*sizeof(uint64_t));
        delete[] key_block;
        return NULL;
    }

    //Begin encryption. Algorithm cuts the message in a number of blocks, then uses an
    //OFB-chained XOR block cipher
    size_t remaining_len = message_length;
    uint64_t* source_block = message;
    uint64_t* dest_block = dest_buffer;
    while(remaining_len > key_block_length) {
        //encrypted[i] = data[i] ^ key_block[i]
        block_xor(key_block_length, source_block, key_block, dest_block);

        //key_block[i+1] = hash(key_block[i] ^ hashed_key)
        block_xor(key_block_length, key_block, hashed_key, key_block);
        hash_result = hash->hash(key_block_length, key_block, key_block);
        if(!hash_result) {
            memset((void*) key_block, 0, key_block_length*sizeof(uint64_t));
            delete[] key_block;
            memset((void*) dest_buffer, 0, message_length*sizeof(uint64_t));
            return NULL;
        }

        remaining_len-= key_block_length;
        source_block+= key_block_length;
        dest_block+= key_block_length;
    }
    //Final step uses block XOR too, but with a different block length
    block_xor(remaining_len, source_block, key_block, dest_block);

    memset((void*) key_block, 0, key_block_length*sizeof(uint64_t));
    delete[] key_block;
    return dest_buffer;
}

uint64_t* OFBChainedXorCipher::block_xor(size_t block_length,
                                    uint64_t* block1,
                                    uint64_t* block2,
                                    uint64_t* dest_buffer) {
    for(size_t i = 0; i < block_length; ++i) {
        dest_buffer[i] = block1[i] ^ block2[i];
    }
    return dest_buffer;
}
