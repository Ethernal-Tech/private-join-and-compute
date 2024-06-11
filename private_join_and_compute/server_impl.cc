/*
 * Copyright 2019 Google LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "private_join_and_compute/server_impl.h"

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <cstdlib>

#include "absl/memory/memory.h"
#include "private_join_and_compute/crypto/ec_commutative_cipher.h"
#include "private_join_and_compute/crypto/paillier.h"
#include "private_join_and_compute/util/status.inc"
#include <sodium.h>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <fstream>

using ::private_join_and_compute::BigNum;
using ::private_join_and_compute::ECCommutativeCipher;

namespace private_join_and_compute
{

  StatusOr<PrivateIntersectionSumServerMessage::ServerRoundOne>
  PrivateIntersectionSumProtocolServerImpl::EncryptSet()
  {
    if (ec_cipher_ != nullptr)
    {
      return InvalidArgumentError("Attempted to call EncryptSet twice.");
    }
    StatusOr<std::unique_ptr<ECCommutativeCipher>> ec_cipher =
        ECCommutativeCipher::CreateWithNewKey(
            NID_X9_62_prime256v1, ECCommutativeCipher::HashType::SHA256);
    if (!ec_cipher.ok())
    {
      return ec_cipher.status();
    }
    ec_cipher_ = std::move(ec_cipher.value());

    PrivateIntersectionSumServerMessage::ServerRoundOne result;
    for (const std::string &input : inputs_)
    {
      EncryptedElement *encrypted =
          result.mutable_encrypted_set()->add_elements();
      StatusOr<std::string> encrypted_element = ec_cipher_->Encrypt(input);
      if (!encrypted_element.ok())
      {
        return encrypted_element.status();
      }
      *encrypted->mutable_element() = encrypted_element.value();
    }

    return result;
  }

  // Helper methods
  // Get current date/time, format is yyMMddHH:mm:ss
  const std::string currentDateTime()
  {
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);

    strftime(buf, sizeof(buf), "%y%m%d%X", &tstruct);

    return buf;
  }

  // This function takes a byte array and its length, converting each byte to a two-character hexadecimal representation, and returns the resulting string.
  std::string bytes_to_hex(const unsigned char *bytes, size_t length)
  {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i)
    {
      ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
  }

  // This function does hex string to bytes conversion
  std::vector<uint8_t> hex_to_bytes(const std::string &hex)
  {
    if (hex.length() % 2 != 0)
    {
      throw std::invalid_argument("Hex string must have an even length.");
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2)
    {
      uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
      bytes.push_back(byte);
    }

    return bytes;
  }

  StatusOr<PrivateIntersectionSumServerMessage::ServerRoundTwo>
  PrivateIntersectionSumProtocolServerImpl::ComputeIntersection(
      const PrivateIntersectionSumClientMessage::ClientRoundOne &client_message)
  {
    if (ec_cipher_ == nullptr)
    {
      return InvalidArgumentError(
          "Called ComputeIntersection before EncryptSet.");
    }
    PrivateIntersectionSumServerMessage::ServerRoundTwo result;
    BigNum N = ctx_->CreateBigNum(client_message.public_key());
    PublicPaillier public_paillier(ctx_, N, 2);

    std::vector<EncryptedElement> server_set, client_set, intersection;

    // First, we re-encrypt the client party's set, so that we can compare with
    // the re-encrypted set received from the client.
    for (const EncryptedElement &element :
         client_message.encrypted_set().elements())
    {
      EncryptedElement reencrypted;
      *reencrypted.mutable_associated_data() = element.associated_data();
      StatusOr<std::string> reenc = ec_cipher_->ReEncrypt(element.element());
      if (!reenc.ok())
      {
        return reenc.status();
      }
      *reencrypted.mutable_element() = reenc.value();
      client_set.push_back(reencrypted);
    }
    for (const EncryptedElement &element :
         client_message.reencrypted_set().elements())
    {
      server_set.push_back(element);
    }

    // std::set_intersection requires sorted inputs.
    std::sort(client_set.begin(), client_set.end(),
              [](const EncryptedElement &a, const EncryptedElement &b)
              {
                return a.element() < b.element();
              });
    std::sort(server_set.begin(), server_set.end(),
              [](const EncryptedElement &a, const EncryptedElement &b)
              {
                return a.element() < b.element();
              });
    std::set_intersection(
        client_set.begin(), client_set.end(), server_set.begin(),
        server_set.end(), std::back_inserter(intersection),
        [](const EncryptedElement &a, const EncryptedElement &b)
        {
          return a.element() < b.element();
        });

    // From the intersection we compute the sum of the associated values, which is
    // the result we return to the client.
    StatusOr<BigNum> encrypted_zero =
        public_paillier.Encrypt(ctx_->CreateBigNum(0));
    if (!encrypted_zero.ok())
    {
      return encrypted_zero.status();
    }
    BigNum sum = encrypted_zero.value();
    for (const EncryptedElement &element : intersection)
    {
      sum =
          public_paillier.Add(sum, ctx_->CreateBigNum(element.associated_data()));
    }

    // Generate computation proof semi-random number
    std::string date_time = currentDateTime();
    date_time.erase(remove(date_time.begin(), date_time.end(), ':'), date_time.end());
    int64_t proof_number;
    char *end;
    proof_number = strtoll(date_time.c_str(), &end, 10) * 1000000 + rand() % 1000000;

    *result.mutable_encrypted_sum() = sum.ToBytes();
    result.set_intersection_size(intersection.size());

    // Combine the proof_number and result in a string which will be signed
    std::string combined_output = std::to_string(intersection.size()) + "," + std::to_string(proof_number);

    if (sodium_init() == -1)
    {
      std::cerr << "Failed to initialize libsodium" << std::endl;
      return result;
    }

    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];
    // Load key files if they exist
    std::ifstream ifsp("pub_key.txt");
    if (ifsp.good())
    {
      std::string pub_key_content((std::istreambuf_iterator<char>(ifsp)),
                                  (std::istreambuf_iterator<char>()));
      std::vector<uint8_t> bytes = hex_to_bytes(pub_key_content);
      std::copy(bytes.begin(), bytes.end(), public_key);

      std::ifstream ifsq("priv_key.txt");
      std::string priv_key_content((std::istreambuf_iterator<char>(ifsq)),
                                   (std::istreambuf_iterator<char>()));
      bytes = hex_to_bytes(priv_key_content);
      std::copy(bytes.begin(), bytes.end(), private_key);
    }
    else
    {
      // Generate key pair
      crypto_sign_keypair(public_key, private_key);

      // Save generated keys
      std::string pub_key_hex = bytes_to_hex(public_key, crypto_sign_PUBLICKEYBYTES);
      std::string priv_key_hex = bytes_to_hex(private_key, crypto_sign_SECRETKEYBYTES);

      std::ofstream myfile;
      myfile.open("pub_key.txt");
      myfile << pub_key_hex;
      myfile.close();

      myfile.open("priv_key.txt");
      myfile << priv_key_hex;
      myfile.close();
    }

    // Convert combined_output to byte array
    const unsigned char *message = reinterpret_cast<const unsigned char *>(combined_output.c_str());
    unsigned long long message_len = combined_output.size();

    // Create signature
    unsigned char signature[crypto_sign_BYTES];
    unsigned long long signature_len;
    crypto_sign_detached(signature, &signature_len, message, message_len, private_key);

    // Convert signature to hex string for printing
    std::string signature_hex = bytes_to_hex(signature, crypto_sign_BYTES);

    result.set_computation_proof(signature_hex);
    std::cout << intersection.size() << ";" << signature_hex << ";" << combined_output;

    return result;
  }

  Status PrivateIntersectionSumProtocolServerImpl::Handle(
      const ClientMessage &request,
      MessageSink<ServerMessage> *server_message_sink)
  {
    if (protocol_finished())
    {
      return InvalidArgumentError(
          "PrivateIntersectionSumProtocolServerImpl: Protocol is already "
          "complete.");
    }

    // Check that the message is a PrivateIntersectionSum protocol message.
    if (!request.has_private_intersection_sum_client_message())
    {
      return InvalidArgumentError(
          "PrivateIntersectionSumProtocolServerImpl: Received a message for the "
          "wrong protocol type");
    }
    const PrivateIntersectionSumClientMessage &client_message =
        request.private_intersection_sum_client_message();

    ServerMessage server_message;

    if (client_message.has_start_protocol_request())
    {
      // Handle a protocol start message.
      auto maybe_server_round_one = EncryptSet();
      if (!maybe_server_round_one.ok())
      {
        return maybe_server_round_one.status();
      }
      *(server_message.mutable_private_intersection_sum_server_message()
            ->mutable_server_round_one()) =
          std::move(maybe_server_round_one.value());
    }
    else if (client_message.has_client_round_one())
    {
      // Handle the client round 1 message.
      auto maybe_server_round_two =
          ComputeIntersection(client_message.client_round_one());
      if (!maybe_server_round_two.ok())
      {
        return maybe_server_round_two.status();
      }
      *(server_message.mutable_private_intersection_sum_server_message()
            ->mutable_server_round_two()) =
          std::move(maybe_server_round_two.value());
      // Mark the protocol as finished here.
      protocol_finished_ = true;
    }
    else
    {
      return InvalidArgumentError(
          "PrivateIntersectionSumProtocolServerImpl: Received a client message "
          "of an unknown type.");
    }

    return server_message_sink->Send(server_message);
  }

} // namespace private_join_and_compute
