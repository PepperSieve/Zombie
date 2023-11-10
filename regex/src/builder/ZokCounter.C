
#include "ZokCounter.H"

// addition operator for OpCount
OpCount operator+(const OpCount &a, const OpCount &b) {
  return {a.o_and + b.o_and,
          a.o_free_or + b.o_free_or,
          a.o_or + b.o_or,
          a.o_isZero + b.o_isZero};
}

// select count function based on booleans
void ZokCounter::faToCount(const FABuilder &fa, const std::vector<std::pair<int, int>> &proximityPairs, bool altArith, bool tapes) {
  OpCount totalCost = {0, 0, 0, 0};
  if (tapes) {
    totalCost = countTapes(fa, proximityPairs);
  } else {
    totalCost = countNoTapes(fa, proximityPairs);
  }
  std::cout << "AND: " << totalCost.o_and << std::endl;
  if (altArith) {
    std::cout << "OR: " << totalCost.o_or << std::endl;
    std::cout << "FREE ORs: " << totalCost.o_free_or << std::endl;
  } else {
    std::cout << "OR: " << totalCost.o_or + totalCost.o_free_or << std::endl;
  }
  std::cout << "ISZERO: " << totalCost.o_isZero << std::endl;
  if (altArith) {
    std::cout << "Total cost: " << totalCost.o_and + totalCost.o_or + 2 * totalCost.o_isZero << " Constraints per byte" << std::endl;
  } else {
    std::cout << "Total cost: " << totalCost.o_and + totalCost.o_or + totalCost.o_free_or + 2 * totalCost.o_isZero << " Constraints per byte" << std::endl;
  }
}

std::map<int, OpCount> ZokCounter::buildTapelessPatternCosts(const FABuilder &fa) {
  std::map<int, OpCount> patIdToCost;
  // loop over patterns
  for (const auto &kv : fa.patToId) {
    OpCount tmpCost = {0, 0, 0, 0};
    // loop over characters in pattern
    for (const auto &c : kv.first) {
      // if character class
      if (c.size() > 1 && c.size() < 255) {
        tmpCost = tmpCost + OpCount{0, 0, c.size() - 1, 1};
      }
    }
    // handle pattern directly (assume length bounds)
    if (kv.first.size() > 32) {
      std::cerr << "ERROR: long strings not yet implemented for ZokCounter" << std::endl;
      exit(1);
    }
    // if pattern is not a pure 1 symbol long character class then do string match
    if (kv.first.size() != 1 || kv.first[0].size() == 1) {
      tmpCost = tmpCost + OpCount{0, 0, 0, 1};
    }
    patIdToCost[kv.second] = tmpCost;
  }
  return patIdToCost;
}

OpCount ZokCounter::tapeCosts(const FABuilder &fa) {
  OpCount totalCost = {0, 0, 0, 0};
  // loop over patterns
  for (const auto &kv : fa.patToId) {
    // loop over characters in pattern
    for (const auto &c : kv.first) {
      // if character class
      if (c.size() > 1 && c.size() < 255) {
        // if it hasn't been seen before (and not full character class)
        if (classFound.count(c) == 0) {
          // create new tape for it
          classFound.insert(c);
          totalCost = totalCost + OpCount{0, 0, c.size() - 1, 1};
        }
      }
    }
    // handle pattern directly (assume length bounds)
    if (kv.first.size() > 32) {
      std::cerr << "ERROR: long strings not yet implemented for ZokCounter" << std::endl;
      exit(1);
    }
    // if pattern is not a pure 1 symbol long character class then do string match
    if (kv.first.size() != 1 || kv.first[0].size() == 1) {
      totalCost = totalCost + OpCount{0, 0, 0, 1};
    }
  }
  return totalCost;
}

// no tapes and no alternative arithmetization
OpCount ZokCounter::countNoTapes(const FABuilder &fa, const std::vector<std::pair<int, int>> &proximityPairs) {
  // loop over patterns and calculate costs
  std::map<int, OpCount> patIdToCost = buildTapelessPatternCosts(fa);
  // loop over states
  // keep track of final states
  OpCount totalCost = {0, 0, 0};
  for (uint i = 0; i < fa.states.size(); i++) {
    if (fa.states[i].patId != -1) {
      totalCost = totalCost + patIdToCost[fa.states[i].patId] + OpCount{1, fa.getPstateClosure(i).size() - 1, 0, 0};
    } else if (fa.finalStates.count(i) > 0) {
      totalCost = totalCost + patIdToCost[fa.states[i].patId] + OpCount{0, fa.getPstateClosure(i).size() - 1, 0, 0};
    }
  }
  return totalCost;
}

OpCount ZokCounter::countTapes(const FABuilder &fa, const std::vector<std::pair<int, int>> &proximityPairs) {
  // loop over patterns and calculate costs
  OpCount totalCost = tapeCosts(fa);
  // loop over states
  // keep track of final states
  for (uint i = 0; i < fa.states.size(); i++) {
    if (fa.states[i].patId != -1) {
      totalCost = totalCost + OpCount{1, fa.getPstateClosure(i).size() - 1, 0, 0};
    } else if (fa.finalStates.count(i) > 0) {
      totalCost = totalCost + OpCount{0, fa.getPstateClosure(i).size() - 1, 0, 0};
    }
  }
  return totalCost;
}
