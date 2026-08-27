#include "sd_jwt_zk/api.h"
#include <iostream>
int main(int argc,char** argv) { if(argc==2 && std::string_view(argv[1])=="--help") { std::cout<<"sd-jwt-zk: bounded SD-JWT ZK envelope tooling (no proof circuit in bootstrap)\n"; return 0; } std::cerr<<"usage: sd-jwt-zk --help\n"; return 2; }
