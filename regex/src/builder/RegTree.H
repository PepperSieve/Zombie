
#ifndef REGTREE_HEADER
#define REGTREE_HEADER

#include <iostream>
#include <string>
#include <vector>
#include <set>

struct RegTree {
  // boolean to indicate Kleene star in subtree
  bool starFree;
  // node type
  enum Type { CONCAT, UNION, STAR, MORE, REPEAT, ATOM };
  Type type;
  // node data (if ATOM)
  std::set<char> symbols;
  // vector of children (if NOT ATOM)
  std::vector<RegTree> children;
  // default constructor (should not be used)
  RegTree() {}
  // constructor from Type
  RegTree(Type t) : type(t) { starFree = (t != STAR && t != MORE && t != REPEAT); }
  // util functions
  void addChild(RegTree child);
  void addSymbol(char c);
  void removeSymbol(char c);
  void addAllSymbols();
  void print(std::string indent = "");
  // optimization functions
  void optimize();
  bool emptyCull();
  bool soloConcat();
  bool doubleUnionCat();
  bool atomInUnion();
  // debug obliterate
  void obliterate();
  void nostring();
};

#endif