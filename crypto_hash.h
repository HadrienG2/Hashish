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

#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#include <QString>
#include <stddef.h>
#include <stdint.h>

//Abstract interface to a cryptographic hash which acts on 64-bit data.
//A word of caution to hash implementers : dest_buffer may be equal to data.
class CryptoHash {
  public:
    virtual uint64_t* hash(size_t data_length, uint64_t* data, uint64_t* dest_buffer) = 0;
    virtual size_t block_length() = 0; //Input block size in quadwords.
    virtual size_t hash_length() = 0; //Hashed data length in quadwords
    virtual QString name() = 0; //Name of the hash (used in service descriptor files)
    bool test(); //Check the function against its known-good test vectors (if available)
};
extern CryptoHash& default_hash;
CryptoHash* crypto_hash_database(const QString& hash_name); //Fetch the hash that bears a given name, if it exists
bool test_crypto_hashes(); //Check all finalized cryptographic hashes against their known test vectors


//Implements a quadword variant of the 512-bit version of SHA-2 (cf NIST's Secure Hash Standard for extensive
//documentation on SHA-2 and the algorithms and constants at work)
class SHA512Hash : public CryptoHash {
  public:
    SHA512Hash();
    uint64_t* hash(size_t data_length, uint64_t* data, uint64_t* dest_buffer);
    size_t block_length() {return 16;}
    size_t hash_length() {return 8;}
    QString name() {return "SHA-512";}
  private:
    uint64_t a, b, c, d, e, f, g, h, T1, T2; //Working and temporary variables
    uint64_t hash_value[8];
    uint64_t H0[8];
    uint64_t K[80];
    uint64_t W[80];

    uint64_t capital_sigma_0(uint64_t x) {return rotr(28, x)^rotr(34, x)^rotr(39, x);}
    uint64_t capital_sigma_1(uint64_t x) {return rotr(14, x)^rotr(18, x)^rotr(41, x);}
    uint64_t ch(uint64_t x, uint64_t y, uint64_t z) {return (x&y)^((~x)&z);}
    uint64_t* gen_padded_message(size_t message_length, uint64_t* message, uint64_t* dest_buffer);
    uint64_t maj(uint64_t x, uint64_t y, uint64_t z) {return (x&y)^(x&z)^(y&z);}
    size_t padded_message_length(size_t message_length);
    void prepare_message_schedule(uint64_t* current_block);
    uint64_t rotr(int n, uint64_t x);
    uint64_t shr(int n, uint64_t x);
    uint64_t sigma_0(uint64_t x) {return rotr(1, x)^rotr(8, x)^shr(7, x);}
    uint64_t sigma_1(uint64_t x) {return rotr(19, x)^rotr(61, x)^shr(6, x);}
};

#endif // CRYPTO_HASH_H
