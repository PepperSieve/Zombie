
#include "RegTree.H"

// function to add child
void RegTree::addChild(RegTree child) {
  children.push_back(child);
  starFree = starFree && child.starFree;
}

void RegTree::addSymbol(char c) {
  symbols.insert(c);
}

void RegTree::removeSymbol(char c) {
  symbols.erase(c);
}

void RegTree::addAllSymbols() {
  for (int c = 0; c < 256; c++) { symbols.insert((char)c); }
}

// function to print tree
void RegTree::print(std::string indent) {
  switch (type) {
    case CONCAT:
      std::cout << indent << "CONCAT" << std::endl;
      break;
    case UNION:
      std::cout << indent << "UNION" << std::endl;
      break;
    case STAR:
      std::cout << indent << "STAR" << std::endl;
      break;
    case MORE:
      std::cout << indent << "MORE" << std::endl;
      break;
    case REPEAT:
      std::cout << indent << "REPEAT" << std::endl;
      break;
    case ATOM:
      std::cout << indent << "ATOM: ";
      if (symbols.size() == 256) {
        std::cout << "ANY";
      } else {
        for (const auto &c : symbols) {
          if (32 <= c && c <= 126) {
            std::cout << c << " "; 
          } else {
            std::cout << (int)c << " ";
          }
        }
      }
      std::cout << std::endl;
      break;
  }
  for (uint i = 0; i < children.size(); i++) {
    children[i].print(indent + "  ");
  }
}

void RegTree::optimize() {
  // create vector of optimization functions
  std::vector<bool (RegTree::*)()> optFuncs = {
    &RegTree::emptyCull,
    &RegTree::soloConcat,
    &RegTree::doubleUnionCat,
    &RegTree::atomInUnion
  };
  // walk forward through vector, return to the beginning if a function returns true
  // if all functions return false, return
  size_t i = 0;
  while (i < optFuncs.size()) {
    if ((this->*optFuncs[i])()) {
      i = 0;
    } else {
      i++;
    }
  }
}

bool RegTree::emptyCull() {
  // loop over children
  for (uint i = 0; i < children.size(); i++) {
    // recurse into child
    if (children[i].emptyCull()) { return true; }
    // if child is not an atom and has no children, remove it
    if (children[i].type != ATOM && children[i].children.size() == 0) {
      children.erase(children.begin() + i);
      return true;
    }
  }
  return false;
}

bool RegTree::soloConcat() {
  // loop over children
  for (uint i = 0; i < children.size(); i++) {
    // recurse into child
    if (children[i].soloConcat()) { return true; }
    // if child is a concat and only has one child, remove it and add its child
    if (children[i].type == CONCAT && children[i].children.size() == 1) {
      RegTree child = children[i].children[0];
      children[i] = child;
      return true;
    }
  }
  return false;
}

bool RegTree::doubleUnionCat() {
  // loop over children
  for (uint i = 0; i < children.size(); i++) {
    // recurse into child
    if (children[i].doubleUnionCat()) { return true; }
    // if I am a concat or union and child is the same
    if ((type == CONCAT || type == UNION) && type == children[i].type) {
      // insert all of child's children at current position in my children
      std::vector<RegTree> newChildren;
      for (uint j = 0; j < children.size(); j++) {
        if (i == j) {
          for (uint k = 0; k < children[j].children.size(); k++) {
            newChildren.push_back(children[j].children[k]);
          }
        } else {
          newChildren.push_back(children[j]);
        }
      }
      children = newChildren;
      return true;
    }
  }
  return false;
}

bool RegTree::atomInUnion() {
  // loop over children
  for (uint i = 0; i < children.size(); i++) {
    // recurse into child
    if (children[i].atomInUnion()) { return true; }
    // if child is an atom and next child is union then make a new union of concats, replace the union, and remove the child
    if (i + 1 < children.size() && children[i].type == ATOM && children[i + 1].type == UNION) {
      RegTree bigUnion = RegTree(UNION);
      for (auto child : children[i + 1].children) {
        RegTree concat = RegTree(CONCAT);
        concat.addChild(children[i]);
        concat.addChild(child);
        bigUnion.addChild(concat);
      }
      children[i] = bigUnion;
      children.erase(children.begin() + i + 1);
      return true;
    }
    if (i + 1 < children.size() && children[i].type == UNION && children[i + 1].type == ATOM) {
      RegTree bigUnion = RegTree(UNION);
      for (auto child : children[i].children) {
        RegTree concat = RegTree(CONCAT);
        concat.addChild(child);
        concat.addChild(children[i + 1]);
        bigUnion.addChild(concat);
      }
      children[i] = bigUnion;
      children.erase(children.begin() + i + 1);
      return true;
    }
  }
  return false;
}

// loop over children, if I am a concat and I have multiple children and one of them is a class then turn the class into a grandchild
void RegTree::obliterate() {
  std::cerr << "deprecated obliterate" << std::endl;
  exit(-1);
  // loop over children
  for (uint i = 0; i < children.size(); i++) {
    // if child is a class
    if (children.size() >= 2 && children[i].type == ATOM && children[i].symbols.size() != 1) {
      // create a new concat
      RegTree concat = RegTree(CONCAT);
      // add current child to concat
      concat.addChild(children[i]);
      // replace the current child with the new concat
      children[i] = concat;
    }
    // recurse into child
    children[i].obliterate();
  }
}

void RegTree::nostring() {
  // loop over children
  for (uint i = 0; i < children.size(); i++) {
    // if more than 1 child and child is ATOM, turn child into concat
    if (children.size() >= 2 && children[i].type == ATOM) {
      // create a new concat
      RegTree concat = RegTree(CONCAT);
      // add current child to concat
      concat.addChild(children[i]);
      // replace the current child with the new concat
      children[i] = concat;
    }
    // recurse into child
    children[i].nostring();
  }
}