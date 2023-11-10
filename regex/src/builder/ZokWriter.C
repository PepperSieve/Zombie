
#include "ZokWriter.H"

void ZokWriter::faToZok(const FABuilder &fa, const std::vector<std::pair<int, int>> &proximityPairs) {
  // loop over proximity pairs and add left and right for each to a set
  std::set<int> proximitySet;
  for (const auto &pp : proximityPairs) {
    proximitySet.insert(pp.first);
    proximitySet.insert(pp.second);
  }
  // print boilerplate
  printBoilerplate();
  // loop over patterns and print them to tapes
  for (const auto &kv : fa.patToId) {
    patternToTape(kv.first, kv.second);
  }
  // loop over states
  // keep track of final states
  std::vector<int> regNumToFinalId;
  for (uint i = 0; i < fa.states.size(); i++) {
    // if state's patId is not -1 (or it is a finalState), print it to a loop
    if (fa.states[i].patId != -1 || fa.finalStates.count(i) > 0) {
      stateToLoop(fa, i, fa.finalStates.count(i) > 0, proximitySet.count(i) == 0);
      if (fa.finalStates.count(i) > 0) { regNumToFinalId.push_back(i); }
    }
  }
  // loop over proximityPairs
  for (const auto &pp : proximityPairs) {
    // if pp.first or pp.second is out of range, error out
    if (pp.first < 0 || pp.first >= (int)regNumToFinalId.size() || pp.second < 0 || pp.second >= (int)regNumToFinalId.size()) {
      std::cerr << "Error: proximity pair (" << pp.first << " " << pp.second << ") out of range" << std::endl;
      exit(1);
    }
    std::cout << "\tassert(procCheck(f_" << regNumToFinalId[pp.first] << ", f_" << regNumToFinalId[pp.second] <<  "))" << std::endl;
  }
  // finally assert accum is 0
  std::cout << "\tassert(accum == 0)" << std::endl;
  // finally close function with dummy return for now
  std::cout << "\treturn false" << std::endl;
}

void ZokWriter::printBoilerplate() {
  std::cout << "const u32 STR_LENGTH = 1000" << std::endl;
  std::cout << "const u32 PROXY_DIST = 300\n" << std::endl;
  std::cout << "def isZero(field x) -> field:\n\tfield y = if x == 0 then 1 else 0 fi\n\treturn y\n" << std::endl;
  std::cout << "def isNotZero(field x) -> field:\n\tfield y = if x != 0 then 1 else 0 fi\n\treturn y\n" << std::endl;
  std::cout << "def inRange(u8 x, u8 l, u8 h) -> field:\n\tfield y = if l <= x && x <= h then 1 else 0 fi\n\treturn y\n" << std::endl;
  std::cout << "def spread(field[STR_LENGTH] x) -> field[STR_LENGTH]:\n\tfield[STR_LENGTH] y = [0;STR_LENGTH]\n\tfor u32 i in PROXY_DIST..(STR_LENGTH-PROXY_DIST) do\n\t\tfield sum = 0\n\t\tfor u32 j in (i-PROXY_DIST)..(i+PROXY_DIST) do\n\t\t\tsum = sum + x[j]\n\t\tendfor\n\t\ty[i] = sum\n\tendfor\n\treturn y\n" << std::endl;
  std::cout << "def procCheck(field[STR_LENGTH] l, field[STR_LENGTH] r) -> bool:\n\tfield[STR_LENGTH] ls = spread(l)\n\tfor u32 i in 0..STR_LENGTH do\n\t\tassert(ls[i] * r[i] == 0)\n\tendfor\n\treturn true\n" << std::endl;
  std::cout << "def parseExtract(field[STR_LENGTH] s) -> field[STR_LENGTH]:\n\tfield[STR_LENGTH] ls = [0; STR_LENGTH]\n\tfor u32 i in 4..STR_LENGTH do\n\t\tls[i] = ls[i - 1] + isZero((s[i - 4] - 13) + 256 * (s[i - 3] - 10) + 65536 * (s[i - 2] - 13) + 16777216 * (s[i - 1] - 10))\n\tendfor\n\treturn ls\n" << std::endl;
  std::cout << "def main(field[STR_LENGTH] t, u8[STR_LENGTH] tu) -> bool:" << std::endl;
  std::cout << "\tfield[STR_LENGTH] start = parseExtract(t)" << std::endl;
  std::cout << "\tfield accum = 0" << std::endl;
}

void ZokWriter::rangePrint(const std::vector<DPRange_t> &ranges) {
  std::cout << "(";
  std::set<char> inSet;
  bool tFlag = false;
  for (const auto &r : ranges) {
    // if the range is small add to inSet, otherwise print inRange
    if (r.max - r.min + 1 <= 17) {
      for (int i = r.min; i <= r.max; i++) { inSet.insert((char)i); }
    } else {
      std::cout << "inRange(tu[i], " << (int)r.min << ", " << (int)r.max << ")";
      tFlag = true;
      if (&r != &ranges.back()) { std::cout << " + "; }
    }
  }
  if (tFlag && inSet.size() > 0) { std::cout << " + "; }
  // loop over characters in inSet and call isZero on product of exact matches
  if (inSet.size() > 0) {
    std::cout << "isZero(";
    for (const auto &ch : inSet) {
      if (ch != *inSet.begin()) { std::cout << " * "; }
      std::cout << "(t[i] - " << (int)ch << ")";
    }
    std::cout << ")";
  }
  std::cout << ")";
}

// currently uses naive approach of independently constructing sets
// optimal independent set construction is VERY hard (maybe NP-hard)
// also creates aliases when it doesn't need to ex. pattern [0-9] is same as class [0-9]
// this has no material effect on constraints or parsing time so it's not a priority
void ZokWriter::patternToTape(const std::vector<std::set<char>> &pattern, int patId) {
  // initial loop over pattern to see if any class tapes need to be built
  for (const auto &c : pattern) {
    // if c is not a singleton and not the full set, and it hasn't been seen before, build a tape for it
    if (c.size() > 1 && c.size() < 256 && classToId.find(c) == classToId.end()) {
      // assign a new id to c
      classToId[c] = classToId.size();
      // print tape header
      std::cout << "\tfield[STR_LENGTH] t_" << classToId[c] << " = [0; STR_LENGTH]" << std::endl;
      // print main loop header
      std::cout << "\tfor u32 i in 0..STR_LENGTH do" << std::endl;
      // print tape body
      std::cout << "\t\tt_" << classToId[c] << "[i] = ";
      // print loop body
      if (c.size() <= 17) {
        // print is zero call
        std::cout << "isZero(";
        // loop over characters in c and take the product of exact matches
        for (const auto &ch : c) {
          if (ch != *c.begin()) {
            std::cout << " * ";
          }
          std::cout << "(t[i] - " << (int)ch << ")";
        }
        std::cout << ")" << std::endl;
      } else if (256 - c.size() <= 17) {
        // loop over characters not in c and take the product of exact matches
        bool first = true;
        for (int i = 0; i < 256; i++) {
          if (c.find(i) == c.end()) {
            if (!first) { std::cout << " * "; } else { first = false; }
            std::cout << "(t[i] - " << i << ")";
          }
        }
        std::cout << std::endl;
      } else {
        // THIS IS NOT OPTIMAL, but it's not a priority to fix
        // maintain continuous ranges
        std::vector<DPRange_t> ranges;
        // maintain vector of excluded ranges
        std::vector<DPRange_t> negRanges;
        // start of search
        char start = *c.begin();
        // get first element from c
        DPRange_t curr = {start, start};
        // loop over characters in c
        for (const auto &ch : c) {
          // if ch matches last or is connected to curr, update curr
          // otherwise ch starts new group and we need to resolve curr group
          if (ch - curr.max <= 1) { curr.max = ch; }
          if (ch - curr.max > 1 || ch == *c.rbegin()) {
            // if ranges contains at least 1 element
            if (ranges.size() > 0) {
              // check the cost of excluding the cells between ranges.back().max and curr.min
              // if it's cheaper than including the cells in curr, exclude them and update ranges.back().max, otherwise just add curr to ranges
              int lastSize = ranges.back().max - ranges.back().min + 1;
              int currSize = curr.max - curr.min + 1;
              int betweenSize = curr.min - ranges.back().max - 1;
              int oldCost = std::min(lastSize, 17) + std::min(currSize, 17);
              int newCost = 20 + std::min(betweenSize, 20);
              if (newCost < oldCost) {
                DPRange_t negRange = {ranges.back().max + 1, curr.min - 1};
                ranges.back().max = curr.max;
                negRanges.push_back(negRange);
              } else {
                ranges.push_back(curr);
              }
            } else {
              ranges.push_back(curr);
            }
            curr = {ch, ch};
          }
        }
        // handle normal ranges
        rangePrint(ranges);
        // handle excluded ranges
        if (negRanges.size() > 0) {
          std::cout << " * isZero("; // TO DO, if we have time, handle double isZero case (no range in negRange)
          rangePrint(negRanges);
          std::cout << ")";
        }
        std::cout << std::endl;
      }
      // close up loop
      std::cout << "\tendfor" << std::endl;
    }
  }
  // if this pattern is exclusively free characters, handle that directly
  bool allFree = true;
  for (const auto &c : pattern) { if (c.size() != 256) { allFree = false; break; } }
  if (allFree) {
    std::cout << "\tfield[STR_LENGTH] p_" << patId << " = [1; STR_LENGTH]" << std::endl;
    return;
  }
  // zero out initial tape entries
  std::cout << "\tfield[STR_LENGTH] p_" << patId << " = [0; STR_LENGTH]" << std::endl;
  // print main loop header
  // TO DO URGENT!, modify loop start
  std::cout << "\tfor u32 i in " << pattern.size() - 1 << "..STR_LENGTH do" << std::endl;
  // if this tape just aliases a single character pattern, handle that directly
  if (pattern.size() == 1 && 1 < pattern[0].size() && pattern[0].size() < 256) {
    std::cout << "\t\tp_" << patId << "[i] = 1 - t_" << classToId[pattern[0]] << "[i]" << std::endl;
    std::cout << "\tendfor" << std::endl;
    return;
  }
  // start line 
  std::cout << "\t\tp_" << patId << "[i] = isZero(";
  // maintain powers of 256 for building sum
  mpz_class p = 1;
  int pCount = 0;
  // loop over patterns
  for (uint i = 0; i < pattern.size(); i++) {
    if (pattern[i].size() == 1) { // if pattern[i] is a singleton
      std::cout << "(t[i - " << pattern.size() - i - 1 << "] - " << (int)*pattern[i].begin() << ")";
    } else if (pattern[i].size() < 256) { // if pattern[i] is a set but not the full set
      std::cout << "(1 - t_" << classToId[pattern[i]] << "[i - " << pattern.size() - i - 1 << "])";
    } else { // if pattern[i] is the full set
      // continue
      continue;
    }
    // if i is not the first pattern then print "* p"
    if (pCount != 0) { std::cout << " * " << p.get_str(); }
    // if i is not the last pattern then print " + " otherwise end line
    if (i != pattern.size() - 1) { std::cout << " + "; }
    // update p
    if (pattern[i].size() == 1) { p *= 256; } else { p *= 2; }
    pCount++;
    // TO DO, adjust this to be based on field size and p variable size
    if (pCount > 32 && i != pattern.size() - 1) {
      std::cout << ") * isZero("; p = 1; pCount = 0;
    }
  }
  std::cout << ")" << std::endl;
  // print loop footer
  std::cout << "\tendfor" << std::endl;
}

void ZokWriter::stateToLoop(const FABuilder &fa, int stateId, bool isFinal, bool forcedFalse) {
  // get name of state
  std::string stateName = (isFinal ? "f_" : "s_") + std::to_string(stateId);
  // print tape header
  std::cout << "\tfield[STR_LENGTH] " << stateName << " = [0; STR_LENGTH]" << std::endl;
  // print main loop header
  // TO DO (lower order concern), add offsets to slightly trim constraints (requires getting closure first and then taking min of all offsets)
  std::cout << "\tfor u32 i in " << fa.patIdToLen[fa.states[stateId].patId] << "..STR_LENGTH do" << std::endl;
  // print left side of assignment
  std::cout << "\t\t" << stateName << "[i] = ";
  // if pattern is not empty, print pattern
  if (fa.states[stateId].patId != -1) {
    std::cout << "p_" << fa.states[stateId].patId << "[i]";
  }
  // call getPstateClosure
  std::set<int> pstateClosure = fa.getPstateClosure(stateId);
  // if closure doesn't contain -1, loop over closure and print transitions
  if (pstateClosure.find(-1) == pstateClosure.end()) {
    // if pattern is not empty, print " * "
    if (fa.states[stateId].patId != -1) { std::cout << " * "; }
    std::cout << "(";
    // loop over closure
    for (const auto &pstateId : pstateClosure) {
      // print " + " if not first element
      if (pstateId != *pstateClosure.begin()) { std::cout << " + "; }
      // print pstate name
      std::cout << "s_" << pstateId;
      // get length
      int len = fa.patIdToLen[fa.states[stateId].patId];
      // if len is 0, print without offset, otherwise print with offset 
      if (len == 0) { std::cout << "[i]"; }
      else { std::cout << "[i - " << len << "]"; }
    }
    std::cout << ")";
  } else { // otherwise require start state to be 1 in start tape
    std::cout << " * start";
    int len = fa.patIdToLen[fa.states[stateId].patId];
    if (len == 0) { std::cout << "[i]"; }
    else { std::cout << "[i - " << len << "]"; }
  }
  // end line
  std::cout << std::endl;
  // if state is final and not in a proximity pair, print "assert(t[i] == 0)"
  // replaced with accumulator for now
  //if (isFinal && forcedFalse) { std::cout << "\t\tassert(" << stateName << "[i] == 0)" << std::endl; }
  if (isFinal && forcedFalse) { std::cout << "\t\taccum = accum + " << stateName << "[i]" << std::endl; }
  // end loop
  std::cout << "\tendfor" << std::endl;
}
