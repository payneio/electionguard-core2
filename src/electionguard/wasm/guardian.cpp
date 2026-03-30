#include "electionguard/guardian.hpp"

#include "../log.hpp"

#include <emscripten/bind.h>
#include <iostream>

using namespace emscripten;
using namespace electionguard;
using namespace std;

EMSCRIPTEN_BINDINGS(electionguard)
{
    class_<GuardianKeySet>("GuardianKeySet")
      .class_function("generate", &GuardianKeySet::generate)
      .function("getVotePublicKey", &GuardianKeySet::getVotePublicKey, allow_raw_pointers())
      .function("getDataPublicKey", &GuardianKeySet::getDataPublicKey, allow_raw_pointers())
      .function("getCommunicationPublicKey", &GuardianKeySet::getCommunicationPublicKey,
                allow_raw_pointers())
      ;
}
