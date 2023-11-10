
#ifndef FABUILDER_HEADER
#define FABUILDER_HEADER

#include <iostream>
#include <vector>
#include <stack>
#include <set>
#include <map>
#include <cassert>
#include "RegTree.H"

struct State {
  int patId; // id of pattern for incoming transitions
  std::vector<int> pstates; // ids of previous states
};

struct FABuilder {
  // map each pattern to an id to avoid duplicates
  std::map<std::vector<std::set<char>>, int> patToId;
  std::vector<int> patIdToLen;
  // each state has an index
  std::vector<State> states;
  // set of final states
  std::set<int> finalStates;
  // get the id of a pattern
  int getPatId(std::vector<std::set<char>> pat);
  // functions for adding states
  int addState(int patId, std::vector<int> pstates);
  void addTransition(int fromId, int toId, int patId);
  // function for getting pstate closure (all children without epsilon transitions, and all pstates reachable beyond children though epsilon transitions)
  std::set<int> getPstateClosure(int stateId) const;
  // functions for building the automaton
  void parseForest(std::vector<RegTree> forest);
  int parseTree(RegTree tree, int prevId = -1); // returns the id of the final state
  int parseConcat(RegTree tree, int prevId);
  int parseUnion(RegTree tree, int prevId);
  int parseStar(RegTree tree, int prevId);
  int parseMore(RegTree tree, int prevId);
  int parseRepeat(RegTree tree, int prevId);
  int parseAtom(RegTree tree, int prevId);
  // printing for debugging
  void print();
  void graphVizPrint();
};

#endif
