/* HMAC class : implements a method for generating a single hash input using two input
   strings (a secret key + a service name) and a hash function.

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

#include <crypto_hash.h>
#include <error_management.h>
#include <hmac.h>
#include <parsing_tools.h>
#include <qstring_to_qwords.h>
#include <test_suite.h>

RFC2104HMAC rfc_2104_hmac;
HMAC& default_hmac = rfc_2104_hmac;

HMAC* hmac_database(const QString& hmac_name) {
    if(hmac_name == rfc_2104_hmac.name()) {
        return &rfc_2104_hmac;
    }

    return NULL;
}

bool test_hmacs() {
    bool result = rfc_2104_hmac.test();
    if(!result) return false;

    return true;
}

const QString HMAC_NAME("HMAC");

bool HMAC::test() {
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
        log_error(HMAC_NAME, ERR_FILE_NOT_FOUND.arg(file_path));
        return false;
    }
    if(test_file.open(QIODevice::ReadOnly) == false) {
        log_error(HMAC_NAME, ERR_FILE_OPEN_FAILURE.arg(file_path));
        return false;
    }
    QTextStream test_istream(&test_file);
    if(test_istream.readLine() != TEST_FILE_HEADER) {
        log_error(HMAC_NAME, ERR_FILE_HEADER_INCORRECT.arg(file_path));
        return false;
    }

    //Perform tests
    while(test_istream.atEnd() == false) {
        //Read and clean up a line of text, ignoring comments and spacing
        line = test_istream.readLine();
        isolate_content(line);
        if(line.isEmpty()) continue;

        if(has_id(line, ID_HASH)) {
            //When encountering a hash, prepare to use it
            remove_id(line, ID_HASH);
            hash = crypto_hash_database(line);
            if(!hash) {
                if(qw_result) delete[] qw_result;
                log_error(HMAC_NAME, ERR_UNSUPPORTED_HASH.arg(line));
                return false;
            }

            //Setup qw_result and its length
            qw_result_length = hash->hash_length();
            if(qw_result) delete[] qw_result;
            qw_result = new uint64_t[qw_result_length];
            if(!qw_result) {
                log_error(HMAC_NAME, ERR_BAD_ALLOC.arg(QString("qw_result")));
                return false;
            }
            continue;
        }

        //When encountering a key, store it
        if(has_id(line, ID_KEY)) {
            remove_id(line, ID_KEY);
            qw_key_length = qword_length_hex(line);
            if(qw_key_length == 0) {
                if(qw_message) delete[] qw_message;
                if(qw_result) delete[] qw_result;
                log_error(HMAC_NAME, ERR_BAD_HEX_DATA.arg(line));
                return false;
            }
            qw_key = new uint64_t[qw_key_length];
            if(!qw_key) {
                if(qw_message) delete[] qw_message;
                if(qw_result) delete[] qw_result;
                log_error(HMAC_NAME, ERR_BAD_ALLOC.arg(QString("qw_key")));
                return false;
            }
            if(qwords_from_hex_str(line, qw_key) == false) {
                if(qw_message) delete[] qw_message;
                if(qw_result) delete[] qw_result;
                delete[] qw_key;
                log_error(HMAC_NAME, ERR_BAD_HEX_DATA.arg(line));
                return false;
            }
            continue;
        }

        //When encountering a message, store it
        if(has_id(line, ID_MESSAGE)) {
            remove_id(line, ID_MESSAGE);
            qw_message_length = qword_length_hex(line);
            if(qw_message_length == 0) {
                if(qw_key) delete[] qw_key;
                if(qw_result) delete[] qw_result;
                log_error(HMAC_NAME, ERR_BAD_HEX_DATA.arg(line));
                return false;
            }
            qw_message = new uint64_t[qw_message_length];
            if(!qw_message) {
                if(qw_key) delete[] qw_key;
                if(qw_result) delete[] qw_result;
                log_error(HMAC_NAME, ERR_BAD_ALLOC.arg(QString("qw_message")));
                return false;
            }
            if(qwords_from_hex_str(line, qw_message) == false) {
                if(qw_key) delete[] qw_key;
                if(qw_result) delete[] qw_result;
                delete[] qw_message;
                log_error(HMAC_NAME, ERR_BAD_HEX_DATA.arg(line));
                return false;
            }

            continue;
        }

        if(has_id(line, ID_RESULT)) {
            //Compute HMAC, check result
            remove_id(line, ID_RESULT);
            hmac(qw_key_length, qw_key, qw_message_length, qw_message, hash, qw_result);
            qwords_to_hex_str(qw_result_length, qw_result, result);
            delete[] qw_key;
            delete[] qw_message;

            if(result!=line) {
                if(qw_result) delete[] qw_result;
                log_error(HMAC_NAME, ERR_WRONG_RESULT.arg(result).arg(line));
                return false;
            }
            continue;
        }
    }

    if(qw_result) delete[] qw_result;

    return true;
}

const QString RFC_2104_HMAC_NAME("RFC2104HMAC");

uint64_t* RFC2104HMAC::hmac(size_t secret_key_length,
                     uint64_t* secret_key,
                     size_t message_length,
                     uint64_t* message,
                     CryptoHash* hash,
                     uint64_t* dest_buffer) {
    //Generate a "key block" from the secret key, that has the hash's input block size
    size_t key_block_length = hash->block_length();
    uint64_t* key_block = new uint64_t[key_block_length];
    if(!key_block) {
        log_error(RFC_2104_HMAC_NAME, ERR_BAD_ALLOC.arg(QString("key_block")));
        return NULL;
    }
    if(!generate_key_block(secret_key_length, secret_key, hash, key_block)) {
        memset((void*) key_block, 0, key_block_length*sizeof(uint64_t));
        delete[] key_block;
        return NULL;
    }

    //Generate outer key pad
    size_t outer_key_pad_length = hash->block_length();
    uint64_t* outer_key_pad = new uint64_t[outer_key_pad_length];
    if(!outer_key_pad) {
        log_error(RFC_2104_HMAC_NAME, ERR_BAD_ALLOC.arg(QString("outer_key_pad")));
        memset((void*) key_block, 0, key_block_length*sizeof(uint64_t));
        delete[] key_block;
        return NULL;
    }
    generate_key_pad(hash->block_length(), key_block, 0x5c5c5c5c5c5c5c5c, outer_key_pad);

    //Generate inner key pad
    size_t inner_key_pad_length = hash->block_length();
    uint64_t* inner_key_pad = new uint64_t[inner_key_pad_length];
    if(!inner_key_pad) {
        log_error(RFC_2104_HMAC_NAME, ERR_BAD_ALLOC.arg(QString("inner_key_pad")));
        memset((void*) key_block, 0, key_block_length*sizeof(uint64_t));
        delete[] key_block;
        memset((void*) outer_key_pad, 0, outer_key_pad_length*sizeof(uint64_t));
        delete[] outer_key_pad;
        return NULL;
    }
    generate_key_pad(hash->block_length(), key_block, 0x3636363636363636, inner_key_pad);

    //Perform actual HMAC calculation
    uint64_t* result = compute_hmac(outer_key_pad,
                                    inner_key_pad,
                                    message_length,
                                    message,
                                    hash,
                                    dest_buffer);

    //Clean up and return result
    memset((void*) key_block, 0, key_block_length*sizeof(uint64_t));
    delete[] key_block;
    memset((void*) outer_key_pad, 0, outer_key_pad_length*sizeof(uint64_t));
    delete[] outer_key_pad;
    memset((void*) inner_key_pad, 0, inner_key_pad_length*sizeof(uint64_t));
    delete[] inner_key_pad;
    return result;
}

uint64_t* RFC2104HMAC::compute_hmac(uint64_t* outer_key_pad,
                                    uint64_t* inner_key_pad,
                                    size_t message_length,
                                    uint64_t* message,
                                    CryptoHash* hash,
                                    uint64_t* dest_buffer) {
    //Result = hash(outer_key_pad + hash(inner_key_pad + qw_service)) where + is concatenation

    //Concatenate inner_key_pad and message
    size_t concat_buffer_length = hash->block_length() + message_length;
    uint64_t* concat_buffer = new uint64_t[concat_buffer_length];
    if(!concat_buffer) {
        log_error(RFC_2104_HMAC_NAME, ERR_BAD_ALLOC.arg(QString("concat_buffer")));
        return NULL;
    }
    memcpy((void*) concat_buffer,
           (const void*) inner_key_pad,
           hash->block_length()*sizeof(uint64_t));
    memcpy((void*) (concat_buffer+hash->block_length()),
           (const void*) message,
           message_length*sizeof(uint64_t));

    //Compute the hash of the result. Use dest_buffer for temporary storage.
    size_t hash_length = hash->hash_length();
    uint64_t* hash_buffer = dest_buffer;
    uint64_t* result = hash->hash(concat_buffer_length, concat_buffer, hash_buffer);
    memset((void*) concat_buffer, 0, concat_buffer_length*sizeof(uint64_t));
    delete[] concat_buffer;
    if(!result) {
        memset((void*) hash_buffer, 0, hash_length*sizeof(uint64_t));
        return NULL;
    }

    //Concatenate outer_key_pad and that hash
    concat_buffer_length = hash->block_length() + hash->hash_length();
    concat_buffer = new uint64_t[concat_buffer_length];
    if(!concat_buffer) {
        log_error(RFC_2104_HMAC_NAME, ERR_BAD_ALLOC.arg(QString("concat_buffer")));
        memset((void*) hash_buffer, 0, hash_length*sizeof(uint64_t));
        return NULL;
    }
    memcpy((void*) concat_buffer,
           (const void*) outer_key_pad,
           hash->block_length()*sizeof(uint64_t));
    memcpy((void*) (concat_buffer+hash->block_length()),
           (const void*) hash_buffer,
           hash->hash_length()*sizeof(uint64_t));

    //Return the hash of the result in dest_buffer
    result = hash->hash(concat_buffer_length, concat_buffer, dest_buffer);
    memset((void*) concat_buffer, 0, concat_buffer_length*sizeof(uint64_t));
    delete[] concat_buffer;
    if(!result) {
        memset((void*) dest_buffer, 0, hash_length*sizeof(uint64_t));
        return NULL;
    }

    return result;
}

uint64_t* RFC2104HMAC::generate_key_block(size_t secret_key_length,
                                   uint64_t* secret_key,
                                   CryptoHash* hash,
                                   uint64_t* dest_buffer) {
    if(secret_key_length > hash->block_length()) {
        //If length is longer than the input block length of the hash,
        //hash the key and zero-pad the result on the right...
        if(hash->hash(secret_key_length, secret_key, dest_buffer) == NULL) return NULL;
        memset((void*) (dest_buffer+hash->hash_length()),
               0,
               (hash->block_length()-hash->hash_length())*sizeof(uint64_t));
    } else {
        //...and if length is shorter, just zero-pad the key on the right
        memcpy((void*) dest_buffer, (const void*) secret_key, secret_key_length*sizeof(uint64_t));
        memset((void*) (dest_buffer+secret_key_length),
               0,
               (hash->block_length()-secret_key_length)*sizeof(uint64_t));
    }

    return dest_buffer;
}

uint64_t* RFC2104HMAC::generate_key_pad(size_t block_length,
                                 uint64_t* key_block,
                                 uint64_t padding,
                                 uint64_t* dest_buffer) {
    //Compute periodized padding ^ key_block, return it in dest buffer
    for(unsigned int i = 0; i<block_length; ++i) {
        dest_buffer[i] = key_block[i]^padding;
    }

    return dest_buffer;
}
