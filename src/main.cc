/*
 * Copyright (C) 2026 by The Forkbomb Company
 * designed, written and maintained by Denis Roio
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "sd_jwt_zk/presentation.h"

#include <algorithm>
#include <charconv>
#include <cerrno>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
using sd_jwt_zk::Bytes;
// A holder envelope contains five independently bounded proof/commitment
// components. Secret input formats remain much smaller and are checked again
// by their canonical decoders.
constexpr std::size_t kMaxCommandFile = 6 * 1024 * 1024;
constexpr std::size_t kMaxNonceEntries = 4096;

bool fsync_retry(int fd) {
  while (fsync(fd) != 0) {
    if (errno != EINTR) return false;
  }
  return true;
}

struct OutputPath {
  std::string parent;
  std::string name;
};

std::optional<OutputPath> split_output_path(std::string_view path) {
  if (path.empty() || path.size() > 4096 || path.back() == '/') return std::nullopt;
  const auto slash = path.rfind('/');
  OutputPath output{
      slash == std::string_view::npos ? "." : slash == 0 ? "/" : std::string(path.substr(0, slash)),
      std::string(path.substr(slash == std::string_view::npos ? 0 : slash + 1))};
  if (output.name.empty() || output.name == "." || output.name == "..") return std::nullopt;
  return output;
}

void usage() {
  std::cout << "usage:\n"
            << "  sd-jwt-zk challenge create --mode bearer|holder --audience A --purpose P"
               " --nonce-file FILE --issuer-key-file FILE --time-min N --time-max N --out FILE\n"
            << "  sd-jwt-zk prove --mode bearer|holder --challenge FILE --presentation-file FILE"
               " --issuer-key-file FILE --out FILE\n"
            << "  sd-jwt-zk verify --mode bearer|holder --challenge FILE --proof-file FILE"
               " --now N --nonce-store FILE\n"
            << "  sd-jwt-zk inspect --input FILE\n";
}

std::optional<Bytes> read_protected(std::string_view path) {
  if (path.empty() || path.size() > 4096) return std::nullopt;
  const int fd = open(std::string(path).c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return std::nullopt;
  struct stat st {};
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
      (st.st_mode & 077) != 0 ||
      static_cast<std::uintmax_t>(st.st_size) > kMaxCommandFile) {
    close(fd); return std::nullopt;
  }
  Bytes data(static_cast<std::size_t>(st.st_size));
  std::size_t offset = 0;
  while (offset < data.size()) {
    const auto received = read(fd, data.data() + offset, data.size() - offset);
    if (received < 0 && errno == EINTR) continue;
    if (received <= 0) { close(fd); return std::nullopt; }
    offset += static_cast<std::size_t>(received);
  }
  if (close(fd) != 0) return std::nullopt;
  return data;
}

void unlink_same_inode(int directory_fd, const std::string& name,
                       const struct stat& created) {
  struct stat current {};
  if (fstatat(directory_fd, name.c_str(), &current, AT_SYMLINK_NOFOLLOW) == 0 &&
      current.st_dev == created.st_dev && current.st_ino == created.st_ino) {
    unlinkat(directory_fd, name.c_str(), 0);
  }
}

bool write_new_owner_only(std::string_view path, const Bytes& data) {
  const auto output = split_output_path(path);
  if (!output) return false;
  const int directory_fd = open(output->parent.c_str(),
      O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
  if (directory_fd < 0) return false;
  const int fd = openat(directory_fd, output->name.c_str(),
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) { close(directory_fd); return false; }
  struct stat created {};
  if (fstat(fd, &created) != 0 || !S_ISREG(created.st_mode)) {
    close(fd);
    close(directory_fd);
    return false;
  }
  std::size_t offset = 0;
  bool ok = true;
  while (offset < data.size()) {
    const auto sent = write(fd, data.data() + offset, data.size() - offset);
    if (sent < 0 && errno == EINTR) continue;
    if (sent <= 0) { ok = false; break; }
    offset += static_cast<std::size_t>(sent);
  }
  if (ok) ok = fsync_retry(fd);
  if (close(fd) != 0) ok = false;
  if (ok) ok = fsync_retry(directory_fd);
  if (!ok) {
    unlink_same_inode(directory_fd, output->name, created);
    fsync_retry(directory_fd);
  }
  const bool directory_closed = close(directory_fd) == 0;
  return ok && directory_closed;
}

std::optional<std::string_view> option(int argc, char** argv, std::string_view key) {
  for (int index = 0; index + 1 < argc; ++index)
    if (argv[index] == key) return argv[index + 1];
  return std::nullopt;
}

std::optional<std::uint64_t> number(std::optional<std::string_view> value) {
  if (!value || value->empty()) return std::nullopt;
  std::uint64_t output{};
  const auto [where, error] = std::from_chars(value->data(), value->data() + value->size(), output);
  if (error != std::errc{} || where != value->data() + value->size()) return std::nullopt;
  return output;
}

std::optional<std::uint8_t> hex(char value) {
  if (value >= '0' && value <= '9') return static_cast<std::uint8_t>(value - '0');
  if (value >= 'a' && value <= 'f') return static_cast<std::uint8_t>(value - 'a' + 10);
  if (value >= 'A' && value <= 'F') return static_cast<std::uint8_t>(value - 'A' + 10);
  return std::nullopt;
}

std::optional<sd_jwt_zk::P256Key> issuer_key_file(std::string_view path) {
  const auto text = read_protected(path);
  if (!text || text->size() != 128) return std::nullopt;
  sd_jwt_zk::P256Key key{};
  for (std::size_t index = 0; index < 64; ++index) {
    const auto high = hex(static_cast<char>((*text)[index * 2]));
    const auto low = hex(static_cast<char>((*text)[index * 2 + 1]));
    if (!high || !low) return std::nullopt;
    const auto byte = static_cast<std::uint8_t>((*high << 4) | *low);
    (index < 32 ? key.x[index] : key.y[index - 32]) = byte;
  }
  return sd_jwt_zk::p256_key_is_valid(key) ? std::optional{key} : std::nullopt;
}

// `SPW1 || index || sibling[0] || sibling[1]`: this file is deliberately
// fixed-width and contains only private status path material.  The credential
// binding is derived from the credential witness, never supplied by the CLI.
std::optional<sd_jwt_zk::StatusMembershipWitnessV1> status_witness_file(
    std::optional<std::string_view> path) {
  if (!path) return std::nullopt;
  const auto bytes = read_protected(*path);
  constexpr std::size_t kSize = 4 + 1 + 2 * proofs::Digest::kLength;
  if (!bytes || bytes->size() != kSize ||
      (*bytes)[0] != 'S' || (*bytes)[1] != 'P' || (*bytes)[2] != 'W' ||
      (*bytes)[3] != '1' || (*bytes)[4] >= 4) return std::nullopt;
  sd_jwt_zk::StatusMembershipWitnessV1 witness;
  witness.private_index = (*bytes)[4];
  witness.compressed_proof.resize(2);
  for (std::size_t sibling = 0; sibling < witness.compressed_proof.size(); ++sibling)
    std::copy_n(bytes->begin() + static_cast<std::ptrdiff_t>(5 + sibling * proofs::Digest::kLength),
                proofs::Digest::kLength, witness.compressed_proof[sibling].data);
  return witness;
}

std::string nonce_entry_name(std::string_view audience, std::string_view nonce,
                             std::uint64_t expires_at) {
  std::string material{"sd-jwt-zk/cli-nonce-store/v1"};
  auto append = [&material](std::string_view value) {
    for (int shift = 56; shift >= 0; shift -= 8)
      material.push_back(static_cast<char>(value.size() >> shift));
    material.append(value);
  };
  append(audience);
  append(nonce);
  for (int shift = 56; shift >= 0; shift -= 8)
    material.push_back(static_cast<char>(expires_at >> shift));
  const auto digest = sd_jwt_zk::sha256_ascii(material);
  static constexpr char digits[] = "0123456789abcdef";
  std::string name(16, '0');
  for (std::size_t index = 0; index < 16; ++index)
    name[index] = digits[(expires_at >> ((15 - index) * 4)) & 0x0f];
  name.push_back('-');
  name.reserve(17 + digest.size() * 2);
  for (const auto byte : digest) {
    name.push_back(digits[byte >> 4]);
    name.push_back(digits[byte & 0x0f]);
  }
  return name;
}

std::optional<std::uint64_t> nonce_entry_expiry(std::string_view name) {
  if (name.size() != 81 || name[16] != '-') return std::nullopt;
  std::uint64_t expiry = 0;
  for (std::size_t index = 0; index < 16; ++index) {
    const auto digit = hex(name[index]);
    if (!digit) return std::nullopt;
    expiry = (expiry << 4) | *digit;
  }
  for (std::size_t index = 17; index < name.size(); ++index)
    if (!hex(name[index])) return std::nullopt;
  return expiry;
}

std::optional<std::size_t> collect_expired_nonces(int directory_fd,
                                                   std::uint64_t now) {
  const int scan_fd = dup(directory_fd);
  if (scan_fd < 0) return std::nullopt;
  DIR* directory = fdopendir(scan_fd);
  if (!directory) { close(scan_fd); return std::nullopt; }
  std::size_t active = 0;
  errno = 0;
  while (const auto* entry = readdir(directory)) {
    const std::string_view name(entry->d_name);
    if (name == "." || name == "..") continue;
    const auto expiry = nonce_entry_expiry(name);
    if (!expiry) { closedir(directory); return std::nullopt; }
    if (*expiry < now) {
      if (unlinkat(directory_fd, entry->d_name, 0) != 0 && errno != ENOENT) {
        closedir(directory);
        return std::nullopt;
      }
    } else {
      ++active;
      if (active > kMaxNonceEntries) { closedir(directory); return std::nullopt; }
    }
    errno = 0;
  }
  const bool read_ok = errno == 0;
  const bool close_ok = closedir(directory) == 0;
  return read_ok && close_ok ? std::optional{active} : std::nullopt;
}

bool consume_nonce(std::string_view path, std::string_view audience,
                   std::string_view nonce, std::uint64_t expires_at,
                   std::uint64_t now) {
  if (path.empty() || path.size() > 4096) return false;
  const std::string directory(path);
  if (mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST) return false;
  const int directory_fd = open(directory.c_str(),
      O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
  if (directory_fd < 0) return false;
  struct stat st {};
  if (fstat(directory_fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
      (st.st_mode & 077) != 0 || st.st_uid != geteuid()) {
    close(directory_fd);
    return false;
  }
  if (flock(directory_fd, LOCK_EX) != 0) { close(directory_fd); return false; }
  const auto active = collect_expired_nonces(directory_fd, now);
  if (!active || *active >= kMaxNonceEntries) {
    flock(directory_fd, LOCK_UN);
    close(directory_fd);
    return false;
  }
  const auto name = nonce_entry_name(audience, nonce, expires_at);
  const int fd = openat(directory_fd, name.c_str(),
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) {
    flock(directory_fd, LOCK_UN);
    close(directory_fd);
    return false;
  }
  static constexpr char marker[] = "sd-jwt-zk nonce consumed\n";
  std::size_t offset = 0;
  bool ok = true;
  while (offset < sizeof(marker) - 1) {
    const auto sent = write(fd, marker + offset, sizeof(marker) - 1 - offset);
    if (sent < 0 && errno == EINTR) continue;
    if (sent <= 0) { ok = false; break; }
    offset += static_cast<std::size_t>(sent);
  }
  ok = ok && fsync_retry(fd);
  ok = close(fd) == 0 && ok;
  ok = ok && fsync_retry(directory_fd);
  if (!ok) unlinkat(directory_fd, name.c_str(), 0);
  const bool unlocked = flock(directory_fd, LOCK_UN) == 0;
  const bool directory_closed = close(directory_fd) == 0;
  return ok && unlocked && directory_closed;
}

class NonceFileReplay final : public sd_jwt_zk::FlatBearerReplayStoreV1 {
 public:
  NonceFileReplay(std::string_view path, std::uint64_t now) : path_(path), now_(now) {}
  bool consume(std::string_view audience, std::string_view nonce,
               std::uint64_t expires_at) override {
    return consume_nonce(path_, audience, nonce, expires_at, now_);
  }
 private:
  std::string path_;
  std::uint64_t now_;
};

class HolderNonceFileReplay final : public sd_jwt_zk::HolderBoundReplayStoreV1 {
 public:
  HolderNonceFileReplay(std::string_view path, std::uint64_t now) : path_(path), now_(now) {}
  bool consume(std::string_view audience, std::string_view nonce,
               std::uint64_t expires_at) override {
    return consume_nonce(path_, audience, nonce, expires_at, now_);
  }
 private:
  std::string path_;
  std::uint64_t now_;
};

int challenge_create(int argc, char** argv) {
  const auto mode = option(argc, argv, "--mode"), audience = option(argc, argv, "--audience");
  const auto purpose = option(argc, argv, "--purpose"), nonce_path = option(argc, argv, "--nonce-file");
  const auto key_path = option(argc, argv, "--issuer-key-file"), output = option(argc, argv, "--out");
  const auto status_path = option(argc, argv, "--status-policy-file");
  const auto min = number(option(argc, argv, "--time-min")), max = number(option(argc, argv, "--time-max"));
  if (!mode || !audience || !purpose || !nonce_path || !key_path || !output || !min || !max ||
      (*mode != "bearer" && *mode != "holder")) return 2;
  const auto nonce = read_protected(*nonce_path);
  const auto key = issuer_key_file(*key_path);
  if (!nonce || !key || nonce->empty() || nonce->size() > 4096) return 2;
  std::optional<sd_jwt_zk::StatusPolicyV1> status;
  if (status_path) {
    const auto encoded_status = read_protected(*status_path);
    if (!encoded_status) return 2;
    const auto decoded_status = sd_jwt_zk::decode_status_policy_v1(*encoded_status);
    if (!decoded_status) return 2;
    status = *decoded_status.value;
  }
  sd_jwt_zk::PresentationPolicyV1 policy{std::string(*audience), std::string(*purpose),
      std::string(nonce->begin(), nonce->end()), *min, *max, *key,
      status ? sd_jwt_zk::StatusRequirementV1::required : sd_jwt_zk::StatusRequirementV1::forbidden,
      status};
  sd_jwt_zk::Result<Bytes> encoded = sd_jwt_zk::Result<Bytes>::fail(
      sd_jwt_zk::ErrorCode::unsupported, "request construction failed");
  if (*mode == "bearer") {
    const auto request = sd_jwt_zk::BuildBearerPresentationRequestV1(policy);
    if (request) encoded = sd_jwt_zk::encode_request(request.value->request);
  } else {
    const auto request = sd_jwt_zk::BuildHolderPresentationRequestV1(policy);
    if (request) encoded = sd_jwt_zk::encode_request(request.value->policy.request);
  }
  return encoded && write_new_owner_only(*output, *encoded.value) ? 0 : 2;
}

int status_snapshot_build(int argc, char** argv) {
  const auto key_path = option(argc, argv, "--issuer-key-file");
  const auto entries_path = option(argc, argv, "--entries-file");
  const auto output = option(argc, argv, "--out");
  const auto epoch = number(option(argc, argv, "--epoch"));
  const auto valid_from = number(option(argc, argv, "--valid-from"));
  const auto valid_until = number(option(argc, argv, "--valid-until"));
  if (!key_path || !entries_path || !output || !epoch || !valid_from || !valid_until) return 2;
  const auto key = issuer_key_file(*key_path);
  const auto input = read_protected(*entries_path);
  if (!key || !input || input->size() != 4 * 33) return 2;
  std::vector<sd_jwt_zk::LocalStatusEntryV1> entries;
  for (std::size_t index = 0; index < input->size(); index += 33) {
    sd_jwt_zk::LocalStatusEntryV1 entry{};
    std::copy_n(input->begin() + static_cast<std::ptrdiff_t>(index), 32,
                entry.credential_binding.begin());
    if ((*input)[index + 32] == 1) entry.status = sd_jwt_zk::CredentialStatusV1::valid;
    else if ((*input)[index + 32] == 2) entry.status = sd_jwt_zk::CredentialStatusV1::revoked;
    else return 2;
    entries.push_back(entry);
  }
  const auto snapshot = sd_jwt_zk::build_local_status_snapshot_v1(
      sd_jwt_zk::status_issuer_v1(*key), *epoch, *valid_from, *valid_until, entries);
  if (!snapshot) return 2;
  const auto encoded = sd_jwt_zk::encode_status_policy_v1({snapshot.value->public_part});
  return write_new_owner_only(*output, encoded) ? 0 : 2;
}

int inspect(int argc, char** argv) {
  const auto input = option(argc, argv, "--input");
  if (!input) return 2;
  const auto encoded = read_protected(*input);
  if (!encoded) return 2;
  const auto bearer = sd_jwt_zk::decode_envelope(*encoded);
  if (bearer) {
    std::cout << "mode=bearer\naudience=" << bearer.value->request.audience
              << "\nnonce=" << bearer.value->request.nonce
              << "\nstatus=" << (!bearer.value->request.status_public.empty()) << '\n';
    return 0;
  }
  const auto holder = sd_jwt_zk::decode_holder_bound_envelope(*encoded);
  if (!holder) return 2;
  std::cout << "mode=holder-bound\naudience=" << holder.value->request.audience
            << "\nnonce=" << holder.value->request.nonce
            << "\nstatus=" << (!holder.value->request.status_public.empty()) << '\n';
  return 0;
}

int prove(int argc, char** argv) {
  const auto challenge = option(argc, argv, "--challenge");
  const auto presentation = option(argc, argv, "--presentation-file");
  const auto key_path = option(argc, argv, "--issuer-key-file");
  const auto output = option(argc, argv, "--out");
  if (!challenge || !presentation || !key_path || !output) return 2;
  const auto request_bytes = read_protected(*challenge);
  const auto presentation_bytes = read_protected(*presentation);
  const auto key = issuer_key_file(*key_path);
  if (!request_bytes || !presentation_bytes || !key) return 2;
  const auto request = sd_jwt_zk::decode_request(*request_bytes);
  if (!request || request.value->identity.binding != sd_jwt_zk::Binding::bearer) return 2;
  const auto witness = sd_jwt_zk::flat_bearer_witness_from_presentation(
      std::string_view(reinterpret_cast<const char*>(presentation_bytes->data()), presentation_bytes->size()), *key);
  if (!witness) { std::cerr << "prove: credential witness rejected\n"; return 2; }
  const auto status = request.value->status_public.empty()
                          ? std::optional<sd_jwt_zk::StatusMembershipWitnessV1>{}
                          : status_witness_file(option(argc, argv, "--status-witness-file"));
  if (!request.value->status_public.empty() && !status) { std::cerr << "prove: status witness rejected\n"; return 2; }
  const auto envelope = status
      ? sd_jwt_zk::prove_flat_bearer_v1(*request.value, *witness.value, *status)
      : sd_jwt_zk::prove_flat_bearer_v1(*request.value, *witness.value);
  if (!envelope) { std::cerr << "prove: relation rejected\n"; return 2; }
  const auto encoded = sd_jwt_zk::encode_envelope(*envelope.value);
  return encoded && write_new_owner_only(*output, *encoded.value) ? 0 : 2;
}

int prove_holder(int argc, char** argv) {
  const auto challenge = option(argc, argv, "--challenge");
  const auto presentation = option(argc, argv, "--presentation-file");
  const auto key_path = option(argc, argv, "--issuer-key-file");
  const auto output = option(argc, argv, "--out");
  if (!challenge || !presentation || !key_path || !output) return 2;
  const auto request_bytes = read_protected(*challenge);
  const auto presentation_bytes = read_protected(*presentation);
  const auto issuer = issuer_key_file(*key_path);
  if (!request_bytes || !presentation_bytes || !issuer) return 2;
  const auto request = sd_jwt_zk::decode_request(*request_bytes);
  if (!request || request.value->identity.binding != sd_jwt_zk::Binding::holder_bound) return 2;
  const std::string_view source(reinterpret_cast<const char*>(presentation_bytes->data()),
                                presentation_bytes->size());
  const auto credential = sd_jwt_zk::holder_credential_witness_from_presentation_v1(source, *issuer);
  const auto native = sd_jwt_zk::build_native_witness(source);
  if (!credential || !native || !native.value->kb_jwt || !credential.value->credential.payload.holder_key)
    return 2;
  const auto& compact = *native.value->kb_jwt;
  const std::string kb = compact.protected_header + "." + compact.payload + "." + compact.signature;
  const auto& holder = *credential.value->credential.payload.holder_key;
  const auto kb_witness = sd_jwt_zk::holder_kb_witness_from_compact_jwt_v1(
      kb, sd_jwt_zk::base64url_encode(Bytes(holder.x.begin(), holder.x.end())),
      sd_jwt_zk::base64url_encode(Bytes(holder.y.begin(), holder.y.end())));
  if (!kb_witness) return 2;
  const auto status = request.value->status_public.empty()
                          ? std::optional<sd_jwt_zk::StatusMembershipWitnessV1>{}
                          : status_witness_file(option(argc, argv, "--status-witness-file"));
  if (!request.value->status_public.empty() && !status) return 2;
  const auto policy = sd_jwt_zk::holder_bound_verifier_policy_v1(*request.value);
  const auto envelope = status
      ? sd_jwt_zk::prove_holder_bound_v1(policy, *credential.value, *kb_witness.value, *status)
      : sd_jwt_zk::prove_holder_bound_v1(policy, *credential.value, *kb_witness.value);
  if (!envelope) return 2;
  const auto encoded = sd_jwt_zk::encode_holder_bound_envelope(*envelope.value);
  return encoded && write_new_owner_only(*output, *encoded.value) ? 0 : 2;
}

int verify(int argc, char** argv) {
  const auto challenge = option(argc, argv, "--challenge");
  const auto proof = option(argc, argv, "--proof-file");
  const auto nonce_store = option(argc, argv, "--nonce-store");
  const auto now = number(option(argc, argv, "--now"));
  if (!challenge || !proof || !nonce_store || !now) return 2;
  const auto request_bytes = read_protected(*challenge);
  const auto proof_bytes = read_protected(*proof);
  if (!request_bytes || !proof_bytes) return 2;
  const auto request = sd_jwt_zk::decode_request(*request_bytes);
  const auto envelope = sd_jwt_zk::decode_envelope(*proof_bytes);
  if (!request || !envelope || request.value->identity.binding != sd_jwt_zk::Binding::bearer) return 2;
  NonceFileReplay replay(*nonce_store, *now);
  const auto verified = sd_jwt_zk::verify_flat_bearer_v1(*envelope.value, *request.value,
                                                          *now, replay);
  return verified && *verified.value ? 0 : 2;
}

int verify_holder(int argc, char** argv) {
  const auto challenge = option(argc, argv, "--challenge");
  const auto proof = option(argc, argv, "--proof-file");
  const auto nonce_store = option(argc, argv, "--nonce-store");
  const auto now = number(option(argc, argv, "--now"));
  if (!challenge || !proof || !nonce_store || !now) return 2;
  const auto request_bytes = read_protected(*challenge);
  const auto proof_bytes = read_protected(*proof);
  if (!request_bytes || !proof_bytes) return 2;
  const auto request = sd_jwt_zk::decode_request(*request_bytes);
  const auto envelope = sd_jwt_zk::decode_holder_bound_envelope(*proof_bytes);
  if (!request || !envelope || request.value->identity.binding != sd_jwt_zk::Binding::holder_bound) return 2;
  HolderNonceFileReplay replay(*nonce_store, *now);
  const auto verified = sd_jwt_zk::verify_holder_bound_v1(
      *envelope.value, sd_jwt_zk::holder_bound_verifier_policy_v1(*request.value),
      *now, replay);
  return verified && *verified.value ? 0 : 2;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc == 2 && std::string_view(argv[1]) == "--help") { usage(); return 0; }
  if (argc >= 3 && std::string_view(argv[1]) == "challenge" && std::string_view(argv[2]) == "create")
    return challenge_create(argc - 2, argv + 2);
  if (argc >= 2 && std::string_view(argv[1]) == "inspect") return inspect(argc - 1, argv + 1);
  if (argc >= 2 && std::string_view(argv[1]) == "prove") {
    const auto mode = option(argc - 1, argv + 1, "--mode");
    if (!mode || (*mode != "bearer" && *mode != "holder")) {
      std::cerr << (mode ? "prove: unsupported mode\n" : "prove: mode is required\n");
      return 2;
    }
    return mode && *mode == "holder" ? prove_holder(argc - 1, argv + 1) : prove(argc - 1, argv + 1);
  }
  if (argc >= 2 && std::string_view(argv[1]) == "verify") {
    const auto mode = option(argc - 1, argv + 1, "--mode");
    if (!mode || (*mode != "bearer" && *mode != "holder")) {
      std::cerr << (mode ? "verify: unsupported mode\n" : "verify: mode is required\n");
      return 2;
    }
    return mode && *mode == "holder" ? verify_holder(argc - 1, argv + 1) : verify(argc - 1, argv + 1);
  }
  if (argc >= 3 && std::string_view(argv[1]) == "status-snapshot" &&
      std::string_view(argv[2]) == "build") return status_snapshot_build(argc - 2, argv + 2);
  usage(); return 2;
}
