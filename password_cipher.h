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

#ifndef PASSWORD_CIPHER_H
#define PASSWORD_CIPHER_H

#include <QString>
#include <stddef.h>
#include <stdint.h>

#include <crypto_hash.h>

class PasswordCipher {
  public:
    virtual uint64_t* decrypt(uint64_t* hashed_key,
                              size_t enc_message_length,
                              uint64_t* enc_message,
                              CryptoHash* hash,
                              uint64_t* dest_buffer) = 0;
    virtual uint64_t* encrypt(uint64_t* hashed_key,
                              size_t message_length,
                              uint64_t* message,
                              CryptoHash* hash,
                              uint64_t* dest_buffer) = 0;
    virtual QString name() = 0;
    bool test(); //Check the function against its known-good test vectors (if available)
};
extern PasswordCipher& default_cipher;
PasswordCipher* cipher_database(const QString& cipher_name);
bool test_password_ciphers(); //Check all finalized ciphers against their known test vectors


class OFBChainedXorCipher : public PasswordCipher {
  public:
    virtual uint64_t* decrypt(uint64_t* hashed_key,
                              size_t enc_message_length,
                              uint64_t* enc_message,
                              CryptoHash* hash,
                              uint64_t* dest_buffer);
    virtual uint64_t* encrypt(uint64_t* hashed_key,
                              size_t message_length,
                              uint64_t* message,
                              CryptoHash* hash,
                              uint64_t* dest_buffer);
    virtual QString name() {return "OFB-chained XOR cipher";}
  private:
    uint64_t* block_xor(size_t block_length,
                        uint64_t* block1,
                        uint64_t* block2,
                        uint64_t* dest_buffer);
};

#endif // PASSWORD_CIPHER_H
