/* -*- c++ -*- File generated by the BNF Converter (bnfc 2.9.4). */

/* Lexer definition for use with FLex */

%option noyywrap noinput nounput
%option reentrant bison-bridge bison-locations

%{
#include "Absyn.H"
#include "Bison.H"

#define initialize_lexer regex__initialize_lexer

static void update_loc(YYLTYPE* loc, char* text)
{
  loc->first_line = loc->last_line;
  loc->first_column = loc->last_column;
  int i = 0;
  for (; text[i] != '\0'; ++i) {
      if (text[i] == '\n') {
          ++loc->last_line;
          loc->last_column = 0;
      } else {
          ++loc->last_column;
      }
  }
}
#define YY_USER_ACTION update_loc(yylloc, yytext);

%}

LETTER [a-zA-Z]
CAPITAL [A-Z]
SMALL [a-z]
DIGIT [0-9]
IDENT [a-zA-Z0-9'_]
%START CHAR CHARESC CHAREND STRING ESCAPED

%%  /* Rules. */

<INITIAL>"&"      	 return _AMP;
<INITIAL>"("      	 return _LPAREN;
<INITIAL>")"      	 return _RPAREN;
<INITIAL>"|"      	 return _BAR;
<INITIAL>"*"      	 return _STAR;
<INITIAL>"+"      	 return _PLUS;
<INITIAL>"?"      	 return _QUESTION;
<INITIAL>"["      	 return _LBRACK;
<INITIAL>"]"      	 return _RBRACK;



<INITIAL>\-|\.|\^|({DIGIT}|{LETTER})|\\x(A|B|C|D|E|F|a|b|c|d|e|f|{DIGIT})(A|B|C|D|E|F|a|b|c|d|e|f|{DIGIT})    	 yylval->_string = strdup(yytext); return T_Symb;
<INITIAL>\{({DIGIT}+|{DIGIT}*\,{DIGIT}*)\}    	 yylval->_string = strdup(yytext); return T_Rang;
<INITIAL>[ \t\r\n\f]      	 /* ignore white space. */;
<INITIAL>.      	 return _ERROR_;

%%  /* Initialization code. */

yyscan_t initialize_lexer(FILE *inp)
{
  yyscan_t scanner;
  if (yylex_init_extra(NULL, &scanner)) return 0;
  if (inp) yyrestart(inp, scanner);
  return scanner;
}
