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

#ifndef HMAC_H
#define HMAC_H

#include <QString>
#include <stddef.h>
#include <stdint.h>

#include <crypto_hash.h>

//Abstract interface to a cryptographic Hash-based Message Authentication Code (HMAC) which
//operates on 64-bit data. Output length is the length of the provided hash.
class HMAC {
  public:
    virtual uint64_t* hmac(size_t secret_key_length,
                           uint64_t* secret_key,
                           size_t message_length,
                           uint64_t* message,
                           CryptoHash* hash,
                           uint64_t* dest_buffer) = 0;
    virtual QString name() = 0;
    bool test(); //Check the HMAC against known test vectors, if available
};
extern HMAC& default_hmac;
HMAC* hmac_database(const QString& hmac_name); //Fetch the HMAC that bears a given name, if it exists
bool test_hmacs(); //Check all finalized HMACs against their known test vectors


//Implementation of the RFC 2104 HMAC
class RFC2104HMAC : public HMAC {
  public:
    virtual uint64_t* hmac(size_t secret_key_length,
                           uint64_t* secret_key,
                           size_t message_length,
                           uint64_t* message,
                           CryptoHash* hash,
                           uint64_t* dest_buffer);
    virtual QString name() {return "RFC 2104";}
  private:
    uint64_t* compute_hmac(uint64_t* outer_key_pad,
                           uint64_t* inner_key_pad,
                           size_t message_length,
                           uint64_t* message,
                           CryptoHash* hash,
                           uint64_t* dest_buffer);
    uint64_t* generate_key_block(size_t secret_key_length,
                                 uint64_t* secret_key,
                                 CryptoHash* hash,
                                 uint64_t* dest_buffer);
    uint64_t* generate_key_pad(size_t block_length,
                               uint64_t* key_block,
                               uint64_t padding,
                               uint64_t* dest_buffer);
};

#endif // HMAC_H
