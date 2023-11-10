
#ifndef ZOK_COUNTER_HEADER
#define ZOK_COUNTER_HEADER

#include <iostream>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <gmpxx.h>
#include "FABuilder.H"

// helper struct
struct OpCount {
  size_t o_and = 0;
  size_t o_free_or = 0;
  size_t o_or = 0;
  size_t o_isZero = 0;
};

// addition operator for OpCount
OpCount operator+(const OpCount &a, const OpCount &b);

struct ZokCounter {
  // set of character classes found
  std::set<std::set<char>> classFound;
  // entrypoint
  void faToCount(const FABuilder &fa, const std::vector<std::pair<int, int>> &proximityPairs, bool altArith, bool tapes);
  // no tape dispatch
  OpCount countNoTapes(const FABuilder &fa, const std::vector<std::pair<int, int>> &proximityPairs);
  // tape dispatch
  OpCount countTapes(const FABuilder &fa, const std::vector<std::pair<int, int>> &proximityPairs);
  // build tapeless pattern costs
  std::map<int, OpCount> buildTapelessPatternCosts(const FABuilder &fa);
  // count tape costs
  OpCount tapeCosts(const FABuilder &fa);
};

#endif
