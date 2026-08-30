#include "sd_jwt_zk/full_disclosure_family.h"

namespace sd_jwt_zk {
CircuitIdentity full_disclosure_circuit_identity_v1(Binding binding, Trust trust) {
  CircuitIdentity id{binding, trust, FullDisclosureFamilyV1::kCapacity, {},
                     "p256-base", 0, 0};
  const char* label = nullptr;
  if (binding == Binding::bearer && trust == Trust::exact_key)
    label = "sd-jwt-zk/full-disclosure-v1/4096/256/8/32/bearer/exact";
  else if (binding == Binding::holder_bound && trust == Trust::exact_key)
    label = "sd-jwt-zk/full-disclosure-v1/4096/256/8/32/holder/exact";
  else
    return {};
  id.circuit_digest = sha256_ascii(label);
  return id;
}

CircuitIdentity full_disclosure_authenticated_focused_circuit_identity_v1(
    Binding binding, Trust trust) {
  CircuitIdentity id{binding, trust,
                     FullDisclosureAuthenticatedFocusedV1::kIssuerCapacity,
                     {}, "p256-base", 0, 0};
  const char* binding_label = binding == Binding::bearer ? "bearer" : "holder";
  if (trust != Trust::exact_key) return {};
  const char* trust_label = "exact";
  const std::string label =
      std::string("sd-jwt-zk/full-disclosure-authenticated-focused-v1/") +
      "issuer128/disclosure64/tokens13/depth13/slots1/" + binding_label +
      "/" + trust_label;
  id.circuit_digest = sha256_ascii(label);
  return id;
}
}  // namespace sd_jwt_zk
