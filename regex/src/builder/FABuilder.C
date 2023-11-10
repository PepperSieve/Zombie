
#include "FABuilder.H"

int FABuilder::getPatId(std::vector<std::set<char>> pat) {
  if (patToId.find(pat) == patToId.end()) {
    patToId[pat] = patToId.size();
    patIdToLen.push_back(pat.size());
  }
  return patToId[pat];
}

int FABuilder::addState(int patId, std::vector<int> pstates) {
  State s;
  s.patId = patId;
  s.pstates = pstates;
  states.push_back(s);
  return states.size() - 1;
}

void FABuilder::addTransition(int fromId, int toId, int patId) {
  // check that fromId and toId are valid
  assert(0 <= fromId && fromId < (int)states.size());
  assert(0 <= toId && toId < (int)states.size());
  // check that toId's patId is the same as patId
  assert(states[toId].patId == patId);
  // add transition from fromId to toId with pattern patId
  states[toId].pstates.push_back(fromId);
}

std::set<int> FABuilder::getPstateClosure(int stateId) const {
  // maintain set of states with non-epsilon incoming transitions
  std::set<int> closure;
  // loop over children
  for (const auto &childId : states[stateId].pstates) {
    // if childId is -1 then return -1
    if (childId == -1) { return {-1}; }
    // if I am a top node or my child is an epsilon transition, recurse and add set to closure
    if (states[childId].patId == -1) {
      std::set<int> childClosure = getPstateClosure(childId);
      closure.insert(childClosure.begin(), childClosure.end());
    } else {
      // otherwise, add child to closure and don't recurse
      closure.insert(childId);
    }
  }
  // return closure
  return closure;
}

void FABuilder::parseForest(std::vector<RegTree> forest) {
  for (const auto &tree : forest) {
    finalStates.insert(parseTree(tree));
  }
}

// concat () ensures a set of patterns are matched in order
int FABuilder::parseConcat(RegTree tree, int prevId) {
  // if children are ATOMS, accumulate them into vector and create a state when a non-ATOM is encountered
  std::vector<std::set<char>> pat;
  for (const auto &child : tree.children) {
    if (child.type == RegTree::ATOM) {
      // accumulate symbols
      pat.push_back(child.symbols);
    } else {
      // if pat is not empty, create state
      if (!pat.empty()) {
        // create state
        prevId = addState(getPatId(pat), {prevId});
        // clear pat
        pat.clear();
      }
      // create state
      prevId = parseTree(child, prevId);
    }
  }
  // if pat is not empty, create one additional state
  if (!pat.empty()) {
    // create state
    prevId = addState(getPatId(pat), {prevId});
  }
  // return prevId
  return prevId;
}

// union (|) ensures at least 1 of a set of patterns is matched
int FABuilder::parseUnion(RegTree tree, int prevId) {
  // create a state for each child
  std::vector<int> childIds;
  for (const auto &child : tree.children) {
    // create state
    childIds.push_back(parseTree(child, prevId));
  }
  // create a state with epsilon transition from all childIds
  return addState(-1, childIds);
}

// star (*) ensures a pattern occurs 0 or more times
int FABuilder::parseStar(RegTree tree, int prevId) {
  // assert tree invariant for checking
  assert(tree.children.size() == 1);
  // add epsilon state from prevId
  int startId = addState(-1, {prevId});
  // recuse on child
  int childId = parseTree(tree.children[0], startId);
  // add transition from childId to startId
  addTransition(childId, startId, -1);
  // return startId
  return startId;
}

// more (+) ensures a pattern occurs 1 or more times
int FABuilder::parseMore(RegTree tree, int prevId) {
  // assert tree invariant for checking
  assert(tree.children.size() == 1);
  // add epsilon state from prevId
  int startId = addState(-1, {prevId});
  // recuse on child
  int childId = parseTree(tree.children[0], startId);
  // add epsilon state from childId
  int endId = addState(-1, {childId});
  // add transition from endId to startId
  addTransition(endId, startId, -1);
  // return endId
  return endId;
}

// repeat (?) ensures a pattern occurs 0 or 1 times
int FABuilder::parseRepeat(RegTree tree, int prevId) {
  // assert tree invariant for checking
  assert(tree.children.size() == 1);
  // recuse on child
  int childId = parseTree(tree.children[0], prevId);
  // create epsilon state combining prevId and childId and return
  return addState(-1, {prevId, childId});
}

int FABuilder::parseAtom(RegTree tree, int prevId) {
  // assert tree invariant for checking
  assert(tree.children.size() == 0);
  // symbol set to pattern
  std::vector<std::set<char>> pat = {tree.symbols};
  // get id of pattern
  int patId = getPatId(pat);
  // create state and return id
  return addState(patId, {prevId});
}

int FABuilder::parseTree(RegTree tree, int prevId) {
  int finalId = -1;
  switch (tree.type) {
    case RegTree::CONCAT: finalId = parseConcat(tree, prevId); break;
    case RegTree::UNION:  finalId = parseUnion(tree, prevId); break;
    case RegTree::STAR:   finalId = parseStar(tree, prevId); break;
    case RegTree::MORE:   finalId = parseMore(tree, prevId); break;
    case RegTree::REPEAT: finalId = parseRepeat(tree, prevId); break;
    case RegTree::ATOM:   finalId = parseAtom(tree, prevId); break;
    default: assert(false); break;
  }
  return finalId;
}

void FABuilder::print() {
  // print patterns
  std::cout << "Patterns:" << std::endl;
  for (const auto &kv : patToId) {
    std::cout << kv.second << ": ";
    for (const auto &s : kv.first) {
      std::cout << "[";
      if (s.size() == 256) {
        std::cout << "_ANY_";
      } else {
        for (const auto &c : s) {
          if (32 <= c && c <= 126) {
            std::cout << c;
          } else {
            std::cout << "\\x" << std::hex << (int)c << std::dec;
          }
        }
      }
      std::cout << "] ";
    }
    std::cout << std::endl;
  }
  // print states
  std::cout << "State:" << std::endl;
  for (uint i = 0; i < states.size(); i++) {
    std::cout << i << " (patId = " << states[i].patId << "): ";
    for (uint j = 0; j < states[i].pstates.size(); j++) {
      std::cout << states[i].pstates[j] << " ";
    }
    std::cout << std::endl;
  }
}
  
void FABuilder::graphVizPrint() {
  std::cout << "digraph {" << std::endl;
  for (uint i = 0; i < states.size(); i++) {
    for (uint j = 0; j < states[i].pstates.size(); j++) {
      std::cout << "\t" << states[i].pstates[j] << " -> " << i << " [label=\"" << states[i].patId << "\"];" << std::endl;
    }
  }
  std::cout << "}" << std::endl;
}

