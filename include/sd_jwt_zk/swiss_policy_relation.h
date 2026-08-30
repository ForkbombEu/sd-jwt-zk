#pragma once
#include <array>
#include <cstddef>
namespace sd_jwt_zk {
template<class LogicCircuit> class SwissPolicyRelation {
 public: using BitW=typename LogicCircuit::BitW; using v8=typename LogicCircuit::v8;
 explicit SwissPolicyRelation(const LogicCircuit& l):l_(l){}
 void assert_boolean(const BitW& result,const BitW& value){l_.assert_is_bit(result);l_.assert_is_bit(value);l_.assert_eq(result,value);}
  template<std::size_t N> void assert_equality(const std::array<v8,N>& private_value,const std::array<v8,N>& requested,const BitW& result){BitW same=l_.bit(1);for(std::size_t i=0;i<N;++i)same=l_.land(same,l_.veq(private_value[i],requested[i]));l_.assert_eq(result,same);}
  template<class Integer> void assert_integer_range(const Integer& value,const Integer& low,const Integer& high,const BitW& result){const auto valid=l_.land(l_.lnot(l_.vlt(value,low)),l_.lnot(l_.vlt(high,value)));l_.assert_eq(result,valid);}
  template<class Integer> void assert_date_range(const Integer& value,const Integer& low,const Integer& high,const BitW& result){assert_integer_range(value,low,high,result);}
  template<class Integer> void assert_time_window(const Integer& nbf,const Integer& exp,const Integer& now,const BitW& result){const auto valid=l_.land(l_.lnot(l_.vlt(now,nbf)),l_.lnot(l_.vlt(exp,now)));l_.assert_eq(result,valid);}
  template<std::size_t N,std::size_t Set> void assert_set_membership(const std::array<v8,N>& value,const std::array<std::array<v8,N>,Set>& options,const BitW& result){BitW any=l_.bit(0);for(const auto& option:options){BitW same=l_.bit(1);for(std::size_t i=0;i<N;++i)same=l_.land(same,l_.veq(value[i],option[i]));any=l_.lor_exclusive(any,same);}l_.assert_eq(result,any);}
  template<std::size_t N> void assert_fixed_text(const std::array<v8,N>& value,const std::array<unsigned char,N>& expected){for(std::size_t i=0;i<N;++i)l_.vassert_eq(value[i],expected[i]);}
  template<std::size_t N> void assert_top_level_vct(const std::array<v8,N>& name){assert_fixed_text(name,std::array<unsigned char,N>{'v','c','t'});}
  template<std::size_t N> void assert_distinct_paths(const std::array<v8,N>& left,const std::array<v8,N>& right){BitW same=l_.bit(1);for(std::size_t i=0;i<N;++i)same=l_.land(same,l_.veq(left[i],right[i]));l_.assert1(l_.lnot(same));}
  // The tokenizer supplies these bits only after it has bound the claim name,
  // location and JSON kind to the private payload token table.
  void assert_disclosed_registered_claim(const BitW& top_level,
                                         const BitW& is_string,
                                         const BitW& present) {
    l_.assert_is_bit(top_level); l_.assert_is_bit(is_string); l_.assert_is_bit(present);
    l_.assert_eq(l_.land(present, l_.lnot(top_level)), present);
    l_.assert_eq(l_.land(present, is_string), present);
  }
  void assert_top_level_time_claim(const BitW& top_level,
                                   const BitW& is_integer,
                                   const BitW& present) {
    l_.assert_is_bit(top_level); l_.assert_is_bit(is_integer); l_.assert_is_bit(present);
    l_.assert_eq(l_.land(present, top_level), present);
    l_.assert_eq(l_.land(present, is_integer), present);
  }
 private: const LogicCircuit& l_;
};
}
