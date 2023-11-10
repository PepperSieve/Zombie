
#ifndef ZOKWRITER_HEADER
#define ZOKWRITER_HEADER

#include <iostream>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <gmpxx.h>
#include "FABuilder.H"

/*
High level idea is we have 3 types of arrays
Lowest level:
  -1. tape array which is a 1 array of characters
  0+. class array
Medium level:
  0+. pattern array
Highest level:
  0+. state array
*/

struct DPRange_t { int min, max; };

// struct to encapsulate data to write a Zokrates file given an FABuilder as input
struct ZokWriter {
  // map from character class to tape id
  std::map<std::set<char>, int> classToId;
  // main print function
  void faToZok(const FABuilder &fa, const std::vector<std::pair<int, int>> &proximityPairs);
  // print boilerplate functions
  void printBoilerplate();
  // dp helper function
  void rangePrint(const std::vector<DPRange_t> &ranges);
  // pattern to tape (extracting subgroups)
  void patternToTape(const std::vector<std::set<char>> &pattern, int patId);
  // state to tape
  void stateToLoop(const FABuilder &fa, int stateId, bool isFinal, bool forcedFalse);
};

#endif
