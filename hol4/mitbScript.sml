(**********************************************************************)
(* Formalization of a revised version of Robert's MITB state machine  *)
(**********************************************************************)

(*

Description of MITB state:

 |----------|-----------|-----------|
 | control  | permanent | volatile  |
 |----------|-----------|-------++++|

 control: two states: Ready, Absorbing;

 permanent: 1600-bit requester storing the Keccak-f permution of an
            initial 1152-bit key padded with 448 zeros. In the HOL
            notation defined below: f(K++(Zeros 448))

 volatile:  1600-bit register storing MITB state

The initial manufacturer state:

 |---------|-----------|----------|
 | Ready   |f(K||0...0)| 0        |
 |---------|-----------|----------|

 - the control state is initially Ready;

 - the permanent memory contains the Keccak-f permution of an initial
   manufacturer-supplied 1152-bit key padded with 448 zeros. In the
   HOL notation defined below: f(K++(Zeros 448));

 - the volatile memory contains 1600-bit 0 (Zeros 1600);

Commands (inputs from user/attacker):

 - Skip : {Ready -> Ready} + {Absorbing -> Absorbing}
   State unchanged (stutter, no-op).

 - Move : {Ready->Absorbing} + {Absorbing->Ready}.
   In Ready: start to hash a new message.
   In Absorbing: abandon absorbing, set vmem to zeros.

 - Input bits len : {Ready->Ready} + {Absorbing->{Absorbing,AbsorbEnd,Ready}}.
   In Ready installs f(key++(Zeros c)) in permanent memory.
   In Absorbing inputs a block and continues absorbing if the block
   isn't the last one (indicated by len < r - where r is the bitrate,
   1152 for SHA-3). If the block being input is the last one, then
   goes into AbsorbEnd (len=r-1) or Ready (len < r-s).

State-transition diagram

                    |-----------|                |-----------|
                    |           |      Move      |           |
                    |           |<-------------->|           |
                +---|           |                |           |---+
                |   |           |                |           |   |
 Input key len  |   |  Ready    |                | Absorbing |   | Input blk len
                |   |           |  Input blk len |           |   |   (len = r)
                |-->|           |   (len < r-1)  |           |<--|
                    |           |<---------------|           |
                    |           |                |           |
                    |-----+-----|                |-----------|
                         /|\                           |
                          |                            | Input blk len
                          |                            |   (len = r-1)
                          |                           \|/
                          |                      |-----+-----|
                          |                      |           |
                          |                      |           |
                          |                      |           |
                          |                      |           |
                          |----------------------| AbsorbEnd |
                                                 |           |
                                                 |           |
                                                 |           |
                                                 |           |
                                                 |-----+-----|

The changes to Robert's original design are:

 - added Skip command that does nothing

 - old Setup state is now subsumed by Ready;

 - added addition state AbsorbEnd for len = r-1 case;

 - both key and message block are input using Input command;

 - remove the transition (Setup to Ready in old version) that allows
   the digest corresponding to a partially hashed key
   (e.g. without the padding added) to be read;

 - old commands ButtonSetup, ButtonReady roughly correspond to
   new Input, Move, respectively;

 - Move abandons absorbing, discards vmem memory and moved to Ready;

 - explicit outputs now omitted - it is assumed that in the Ready
   state the control state and digest (bottom 224 bits of volatle
   memory) are displayed.

The changes to Mike's modelling of the MITB are:

 - MITB operates on words now. The parameters (r,c,n) are now part of the
   types.

 *)

(* HOL_Interactive.toggle_quietdec(); *)
open HolKernel boolLib bossLib Parse; 
open listTheory rich_listTheory arithmeticTheory Arith numLib;
open computeLib wordsTheory wordsLib lcsymtacs schneiderUtils;
open uccomTheory spongeTheory tacLib;
(* HOL_Interactive.toggle_quietdec(); *)

(**********************************************************************)
(* Start new theory MITB                                              *)
(**********************************************************************)

val _ = new_theory "mitb";

val _ = numLib.prefer_num();

(*
Bit sizes:
 digest   (n): 224
 capacity (c): 448
 bitrate  (r): 1152 (block and key size)
 width    (b): 1600 (SHA-3 state size = r+c)
*)

val _ = type_abbrev("bits", ``:bool list``);

(*
Datatype of control states
*)
val _ = Datatype
  `control = Ready | Absorbing | AbsorbEnd0S1 | AbsorbEnd10S1 | AbsorbEnd110S1`;

(*
Datatype of input commands
*)
val _ =
 Datatype
  `command = Move
           | Skip
           | Input ('r word) num`;

(*
Type abbreviation for MITB states
*)
val _ =
  (* ('c,'r) mitb_state is *)
 type_abbrev
  ("mitb_state",
   ``:control # ('r+'c) word # ('r+'c) word ``);
(*              permanent       volatile      *)

(*
Type abbreviation for MITB inputs
*)
val _ =
 type_abbrev
  ("mitb_inp",
   ``:bool # bool # 'r word # num``);
(*    skip   move   block     size     *)

(*
Type abbreviation for MITB outputs
*)
val _ =
 type_abbrev
  ("mitb_out",
   ``:bool # 'n word``);


(*
Extract components of an MITB state
*)
val cntlOf_def =
 Define
  `cntlOf((cntl,pmem,vmem): ('r, 'c) mitb_state) = cntl`;

val pmemOf_def =
 Define
  `pmemOf((cntl,pmem,vmem): ('r, 'c) mitb_state) = pmem`;

val vmemOf_def =
 Define
  `vmemOf((cntl,pmem,vmem): ('r, 'c) mitb_state) = vmem`;

(*
Type abbreviation for MITB device
Given a permutation on b=r+c words, moves from one state, via a command
to another state
*)
val _ =
 type_abbrev
 (* ('c,'r) mitb is *)
  ("mitb",
   ``: ( ('r+'c) word -> ('r+'c) word) (* permutation *)
       -> (('c,'r) mitb_state) (* prev. state *)
       -> ('r command) (* command *)
       -> (('c,'r) mitb_state) (* next state *)
      ``);

(*
Type abbreviation for MITB step-function
Given a permutation on b=r+c words, a state and an input, gives
following state and the output.
*)
val _ =
 type_abbrev
 (* ('c, 'n,'r) mitbstepfunction is *)
  ("mitbstepfunction",
``: (('r+'c) word -> ('r+'c) word)  (* permutation *)
  -> ('c, 'r) mitb_state # 'r mitb_inp
  -> ('c, 'r) mitb_state # 'n mitb_out
      ``);

(*
Zero word: Alternative name for the zero word.
REMARK: Zeros is a bool list (bitstring) defined in spongeTheory
*)
val ZERO_def =
 Define
  `ZERO = (0w: 'a word) `;

(*
We first establish some lemmas to fascilitate  relating a translation of
a padded bitstring into a word to a the translation of the same word
padded by the MITB.
*)

(*
Every element in a Zeros-bitstring is F
*)
val EL_Zeros = store_thm("EL_Zeros",
  ``! n m. m < n ⇒ (EL m (Zeros n) = F)``,
  Induct >> simp[Zeros_def] >> Cases >> simp[] )

  
(*
Make rewrites for Zeros-bitstring easier.
*)
val LENGTH_Zeros = store_thm("LENGTH_Zeros",
  ``∀n. LENGTH (Zeros n) = n``,
  Induct >> simp[Zeros_def]);
val _ = export_rewrites["LENGTH_Zeros"]


val zero_splitting_lemma = store_thm("zero_splitting_lemma",
``! n m . (m <= n) ==> ((Zeros n) = (Zeros m) ++ (Zeros (n-m)))``,
  Induct_on `m`
 >-
  simp[Zeros_def]
 >>
 (
  strip_tac >>
  strip_tac >>
  qpat_abbrev_tac `X = (Zeros n)` >>
  qpat_abbrev_tac `Y = (Zeros (n - (SUC m)))` >>
  PURE_REWRITE_TAC [(Once Zeros_def)] >>
  qpat_x_assum `!n. p` ( assume_tac o (Q.SPEC `(n-1)` )) >>
  rw [Abbr`Y`] >>
  `(n - SUC m) = (n-1) - m` by simp [] >>
  pop_assum (fn thm => rw [thm]) >>
  `m <= n-1` by simp [] >>
  pop_assum (fn thm => fs [thm]) >>
  pop_assum (fn thm => rw [SYM thm]) >>
  rw [Abbr`X`,(GSYM (CONJUNCT2 Zeros_def))] >>
  `n>0` by simp [] >>
  simp [ADD1]
  )
  );

(*
At every position, the bit in a word constructed using
word_from_bin_list concides with the value at the same position in the
original bitstring.
*)
val word_bit_word_from_bin_list = store_thm("word_bit_word_from_bin_list",
  ``∀ls b.
      EVERY ($> 2) ls ∧ b < LENGTH ls ⇒
      (word_bit b ((word_from_bin_list ls):'a word) ⇔ b < dimindex (:'a) ∧ (EL b ls = 1))``,
  rw[word_from_bin_list_def,l2w_def,word_bit_n2w] >>
  rw[GSYM numposrepTheory.num_from_bin_list_def] >>
  rw[numposrepTheory.BIT_num_from_bin_list] >>
  rw[EQ_IMP_THM] >>
  assume_tac DIMINDEX_GT_0 >>
  DECIDE_TAC);

val l2n_APPEND = store_thm("l2n_APPEND",
`` ! a c d.
l2n b (c ++ d)  = (l2n b c) + (l2n b d) * b ** (LENGTH  c) ``,
strip_tac >> Induct
>- (rw [numposrepTheory.l2n_def] >> simp [])
>>
rw [numposrepTheory.l2n_def] >>
simp [EXP]
);

(*
The previous statement holds for BITS_TO_WORD, too.
REMARK: word_from_bin_list translates from num list, where BITS_TO_WORD
translates from bool list. We have chosen the latter representation in
spongeTheory, hence the "indirection".
*)
val word_bit_BITS_TO_WORD = store_thm("word_bit_BITS_TO_WORD",
  ``∀ls x. x < LENGTH ls ⇒ (word_bit x ((BITS_TO_WORD ls):'a word) ⇔ x < dimindex (:'a) ∧ EL x ls)``,
  rw[BITS_TO_WORD_def] >>
  qmatch_abbrev_tac`word_bit x (word_from_bin_list l) ⇔ y` >>
  `EVERY ($> 2) l` by (
    simp[Abbr`l`,EVERY_MAP,EVERY_MEM] >> rw[] ) >>
  fs[Abbr`l`] >> simp[word_bit_word_from_bin_list] >>
  simp[EL_MAP,Abbr`y`] >> rw[])


val l2n_Zeros_helper = prove(
``!l. l2n 2 (MAP (λe. if e then 1 else 0) (Zeros (l))) = 0``,
Induct >>
rw [numposrepTheory.l2n_def, Zeros_def]);

(* See whether this can go .. *)
(* val num_to_bool_conversion_helper = prove( *)
(* `` (($> 2) n) ==> (((λe. if e then 1 else 0) o (λe. e = 1)) n = n)``, *)
(* simp [] ); *)

val n2l_st = prove(
``! b n. b> 0 ==> EVERY ($> b) (n2l b n)``,
recInduct(fetch "numposrep" "n2l_ind") >>
rw [] >>
rw [(Once numposrepTheory.n2l_def)]  >>
assume_tac ( Q.SPECL [`n`,`b`] MOD_LESS ) >>
simp []
);

val MAP_num_to_bool_conversion = prove(
`` (EVERY ($> 2) l)
==>
(MAP ((λe. if e then 1 else 0) o (λe. e = (1:num))) l = l)``,
Induct_on `l` >>
simp [] );


val BITS_TO_WORD_WORD_TO_BITS = store_thm("BITS_TO_WORD_WORD_TO_BITS",
  `` ! (k:'r word ).
  dimindex (:'r) > 1 ==>
   (BITS_TO_WORD (WORD_TO_BITS k) = k )``,
rw [GSYM WORD_EQ,
    WORD_TO_BITS_def,
    BITS_TO_WORD_def,
    word_from_bin_list_def,
    l2w_def] >>
rw [l2n_APPEND, l2n_Zeros_helper] >>
rw [GSYM l2w_def,
    word_to_bin_list_def,
    MAP_MAP_o] >>
rw [w2l_def] >>
qspecl_then [`2`,`w2n k`] assume_tac n2l_st >>
rw [MAP_num_to_bool_conversion,
    GSYM w2l_def,
    l2w_w2l]
);


(*
SHA-3 requires to add the bits 01 after the message and before the padding 
The next to definitions handle this: 

  SHA3_APPEND_ZERO_WORD returns a word which is one except at the position 
  given as parameter 

  SHA3_APPEND_ONE_WORD returns a word which is zero expect at the position
  given as paramter + 1
*)
val SHA3_APPEND_ZERO_WORD_def = 
 Define 
  `(SHA3_APPEND_ZERO_WORD l): 'a word = FCP i. (i <> l)`;

val SHA3_APPEND_ONE_WORD_def = 
 Define 
  `(SHA3_APPEND_ONE_WORD l): 'a word = FCP i. (i = (l+1))`;


(*
The word we use for padding. It is Zero at each position, except for the
last-position (MSB) and the position given as a parameter.


(l >< 0) w || PAD_WORD l
produces a padded word of length l from w and l.
REMARK: For l=dimindex(:'a), PAD_WORD has only the MSB set to 1, which
is useful for the definition in case l is one short to the block length.
In this case, the block needs to be followed by a 1w block.

unfortunatly, this is not the case anymore when adding the 01 of sha3. now we need 
to consider some more cases and have to bitwise add and or SHA3-APPEND_ZERO 
and SHA3-APPEND_ONE depending on the case.
check MITB_FUN and the following lemmas for all cases.
*)
val PAD_WORD_def =
 Define
  `(PAD_WORD l):'a word = FCP i. (i=dimindex(:'a)-1) \/ (i=l)`;


(* The two following simplifications are used in padding_lemma *)
val word_bit_or  = prove (
`` (x < dimindex(:'a)) ==> ((a:'a word || b) ' x ⇔ a ' x \/ b ' x) ``,
rw [word_or_def] >>
simp [fcpTheory.FCP_BETA] );

val word_bit_T  = prove (
`` (b < dimindex(:'a) ) ==> ((01w:'a word) ' b = (b=0))``,
rw [word_index] );

val word_bit_and = prove (
`` (x < dimindex(:'a)) ==> ((a:'a word && b) ' x <=> a ' x /\ b ' x) ``,
rw [word_and_def] >>
simp [fcpTheory.FCP_BETA] );

(*
This Theorem shows how to construct a correct padding (w.r.t. to
PAD_WORD from spongeTheory) for words smaller than the blocklength minus
3. , i.e  m @@ 01 @@ PAD_WORD(length m +2)
*)
val padding_lemma = prove (
``
!m.
(LENGTH(m) < dimindex(:'r)-3)
==>
( 2 < dimindex(:'r))
==>
(LENGTH(m) <> 0 )
==>
(
(BITS_TO_WORD (m ++ (F::T::T::(Zeros (dimindex(:'r)-4-LENGTH (m)))++[T]))):'r word
=  (((LENGTH m)-1 -- 0 ) (BITS_TO_WORD m):'r word) &&  
       (SHA3_APPEND_ZERO_WORD(LENGTH m):'r word) ||
       (SHA3_APPEND_ONE_WORD(LENGTH m):'r  word) ||
       (PAD_WORD ((LENGTH m) +2))
)
``,
ntac 4 strip_tac >>
qmatch_abbrev_tac`(BITS_TO_WORD ls) =  word` >>
simp[GSYM WORD_EQ] >>
rw [] >>
`x < (LENGTH ls) ` by ( simp[Abbr`ls`,LengthZeros] ) >>
simp[word_bit_BITS_TO_WORD, word_bit_def,Abbr`word`,word_bit_or,
PAD_WORD_def, fcpTheory.FCP_BETA,word_bits_def,
SHA3_APPEND_ZERO_WORD_def, SHA3_APPEND_ONE_WORD_def, word_bit_and ]  >>
Cases_on `x = LENGTH m + 2`
>- 
(
  simp [word_bit, word_bit_BITS_TO_WORD, Abbr`ls`, EL_APPEND2]
)
>>
Cases_on `x = LENGTH m + 1`
>-
(
  simp[word_bit, word_bit_BITS_TO_WORD, Abbr`ls`, EL_APPEND2]
)
>> Cases_on `x = dimindex(:'r) -1`
>-
( 
  rw [] >> 
  `LENGTH ls = dimindex(:'r)` by simp[LengthZeros, Zeros_def, Abbr`ls`] >>
  simp [Abbr`ls`] >>
  qpat_abbrev_tac `ls = m ++ F::T::T::Zeros(dimindex(:'r) - (LENGTH m + 4))` >>
  `LENGTH ls = dimindex(:'r) -1` by simp [Zeros_def, LengthZeros, Abbr`ls`] >>
  simp [word_bit, word_bit_BITS_TO_WORD, Abbr`ls`, EL_APPEND2] 
)
>>
rw [] >>
Cases_on `x <= LENGTH(m) -1` >> rw [] 
>-
( 
  simp [Abbr`ls`, EL_APPEND1, word_bit, word_bit_BITS_TO_WORD]
)
>>
( 
  `x >= LENGTH(m)` by simp[NOT_LESS_EQUAL] >>
  simp [EL_APPEND2]  >>
  Cases_on `x = LENGTH(m)`
  >-
  (
  simp [EL_APPEND2, Abbr`ls`] 
  )
  >>
  `x > LENGTH(m) +2` by simp[] >>
  simp [EL_APPEND1, LengthZeros, Zeros_def, Abbr`ls`] >>
  `F::T::T::Zeros (dimindex(:'r) - (LENGTH m + 4)) = [F;T;T] ++ Zeros(dimindex(:'r) - (LENGTH m +4))`
    by simp[] >>
  pop_assum (fn thm => ONCE_REWRITE_TAC [thm]) >>
  simp [EL_APPEND2, LengthZeros, Zeros_def] >>
  rw[EL_Zeros] 
));


(*
This Theorem shows how to construct a correct padding (w.r.t. to
PAD_WORD from spongeTheory) for empty words with appending 01
i.e 01 @@ PAD_WORD(2)
*)
val full_padding_append_lemma = prove (
``
(2 < dimindex(:'r)) 
==> 
(
(BITS_TO_WORD (F::T::T::((Zeros (dimindex(:'r) -4)) ++ [T]))):'r word 
= 
(
  (SHA3_APPEND_ZERO_WORD(0):'r word) &&
  (SHA3_APPEND_ONE_WORD(0):'r  word) ||
  (PAD_WORD(2): 'r word)
)) ``,
strip_tac >>
qmatch_abbrev_tac `(BITS_TO_WORD ls) = word` >> 
simp [GSYM WORD_EQ] >>
rw [] >>
`x < (LENGTH ls)` by simp [Abbr`ls`, LengthZeros] >>
simp [word_bit_BITS_TO_WORD, word_bit_def,word_bits_def, 
      Abbr`word`, word_bit_and, word_bit_or,
      SHA3_APPEND_ZERO_WORD_def, SHA3_APPEND_ONE_WORD_def,
      LengthZeros, fcpTheory.FCP_BETA, PAD_WORD_def] >> 
Cases_on `x=0`
>- simp[Abbr`ls`]  >>
Cases_on `x=1` 
>- simp[Abbr`ls`] >>
Cases_on `x=2` 
>- simp[Abbr`ls`] >>
rw [] >>
simp [Abbr `ls`, Zeros_def, LengthZeros] >>
`(F::T::T::(Zeros (dimindex(:'r) -4 ) ++ [T])) = (F::T::T::(Zeros(dimindex(:'r) -4)) ++ [T])`
  by simp[EL_APPEND2] >>
pop_assum (fn thm => ONCE_REWRITE_TAC [thm]) >>
qpat_abbrev_tac `ls = F::T::T::Zeros (dimindex(:'r) -4)` >>
`LENGTH (ls) = dimindex(:'r) -1` by simp[Abbr`ls`, LengthZeros] >>
Cases_on `x = dimindex(:'r) -1`
>- simp [EL_APPEND2]
>>
(
  simp [EL_APPEND1] >>
  simp [Abbr`ls`]  >>
  `F::T::T::Zeros(dimindex(:'r)-4) = [F;T;T] ++ Zeros(dimindex(:'r)-4)` by simp[] >>
  pop_assum(fn thm => ONCE_REWRITE_TAC[thm]) >>
  simp [EL_APPEND2] >>
  `x > 2 /\ x < dimindex(:'r)` by simp[] >>
  simp [Zeros_def, LengthZeros] >>
  `x < dimindex(:'r) -1` by simp[] >>
  rw [EL_Zeros]
));


(*
The following three lemmas show how to construct a padding for a word that is 
one, two or three bits smaller than the blocklength

  one_short_lemma: m++0, followed by a new block 11*0
  two_short_lemma: m++01 followed by a new block 1*0
  three_short_lemma: m++1 followed by a new block 0*1 
*)


val one_short_lemma = prove (
  ``
  (LENGTH(m) = dimindex(:'r)-1)
  /\
  (2 < dimindex(:'r))
  ==>
  (
  (BITS_TO_WORD (m ++ [F]):'r word) =
    ((LENGTH(m)-1 -- 0) (BITS_TO_WORD m) && 
       SHA3_APPEND_ZERO_WORD (LENGTH(m)))
  )``,
strip_tac >>
simp [GSYM WORD_EQ] >>
rw [] >>
`x < LENGTH (m) +1` by simp[] >>
simp[word_bit_BITS_TO_WORD] >>
simp [word_bit_def, word_bits_def, SHA3_APPEND_ZERO_WORD_def, word_bit_and,
      SHA3_APPEND_ONE_WORD_def, word_bit_or, PAD_WORD_def] >>
Cases_on `(LENGTH m) <= x`
>-
(
  `x = dimindex(:'r) -1` by simp [] >>
  SRW_TAC [fcpLib.FCP_ss] [EL_APPEND2] >>
  simp[] 
)
>>
(
  fs [NOT_LESS_EQUAL] >> 
  `x <> dimindex(:'r) -1` by simp[] >>
  SRW_TAC [fcpLib.FCP_ss] [EL_APPEND1] >>
  first_assum (assume_tac o MATCH_MP 
    ( INST_TYPE [alpha |-> Type `:'r`]  word_bit_BITS_TO_WORD)) >>
  rfs [] >>
  `x <= dimindex(:'r) -1` by simp[] >>
  fs [word_bit_def]
));

val two_short_lemma = prove (
  ``
  (LENGTH(m) = dimindex(:'r)-2) 
  /\ 
  (2 < dimindex(:'r))
  ==>
  (
  (BITS_TO_WORD (m ++ [F;T]): 'r word) =
    ((LENGTH(m)-1 -- 0) (BITS_TO_WORD m) &&
        SHA3_APPEND_ZERO_WORD(LENGTH(m)) || 
        SHA3_APPEND_ONE_WORD(LENGTH(m)) ||
        PAD_WORD (LENGTH(m) +2))
  )``,
qpat_abbrev_tac `ls = (m ++ [F;T])` >>
strip_tac >>
simp [GSYM WORD_EQ] >>
rw [] >>
`x < LENGTH(m) + 2` by simp [] >>
simp [word_bit_BITS_TO_WORD, Abbr`ls`] >>
simp [word_bit_def, word_bits_def, SHA3_APPEND_ZERO_WORD_def, word_bit_and,
        SHA3_APPEND_ONE_WORD_def, word_bit_or, PAD_WORD_def] >>
Cases_on `(LENGTH m) <= x`
>- 
(
  `(x = dimindex(:'r)-1) \/ (x = dimindex(:'r)-2)` by simp [] >> 
  rw [] >>
  simp [EL_APPEND2] >>
  SRW_TAC [fcpLib.FCP_ss] [EL_APPEND2] >> 
  simp []
)
>>
(
  fs [NOT_LESS_EQUAL] >>
  `x <> dimindex(:'r) -2` by simp[] >>
  SRW_TAC [fcpLib.FCP_ss] [EL_APPEND1] >>
  simp [EL_APPEND1] >>
  first_assum (assume_tac o MATCH_MP 
    ( INST_TYPE [alpha |-> Type `:'r`] word_bit_BITS_TO_WORD )) >>
  `x <= dimindex(:'r) -1` by simp[] >>
  fs [word_bit_def] 
));

val three_short_lemma = prove (
  ``
  (LENGTH(m) = dimindex(:'r) -3)
  /\ 
  (2 < dimindex (:'r))
  ==>
  (
  (BITS_TO_WORD (m ++ [F;T;T]):'r word) = 
    ((LENGTH(m)-1 -- 0) (BITS_TO_WORD m) && 
        SHA3_APPEND_ZERO_WORD(LENGTH(m)) ||
        SHA3_APPEND_ONE_WORD(LENGTH(m)) || 
        PAD_WORD(LENGTH(m) + 2))
  )``,
qpat_abbrev_tac `ls = (m ++ [F;T;T])` >>
strip_tac >>
simp [GSYM WORD_EQ] >>
rw [] >>
`x < LENGTH(m) + 3` by simp [] >>
simp [word_bit_BITS_TO_WORD, Abbr`ls`] >>
simp [word_bit_def, word_bits_def, SHA3_APPEND_ZERO_WORD_def, word_bit_and,
        SHA3_APPEND_ONE_WORD_def, word_bit_or, PAD_WORD_def] >>
Cases_on `LENGTH(m) <= x` 
>-
(
    `(x = dimindex(:'r) -1)
  \/ (x = dimindex(:'r)- 2)
  \/ (x = dimindex(:'r) -3)` by simp[] >> 
  rw [] >>
  simp [EL_APPEND2] >>
  SRW_TAC [fcpLib.FCP_ss] [EL_APPEND2] >> 
  simp [] 
)
>>
(
  fs [NOT_LESS_EQUAL] >>
  `x <> dimindex(:'r) -2` by simp[] >>
  SRW_TAC [fcpLib.FCP_ss] [EL_APPEND1] >>
  simp [EL_APPEND1] >>
  first_assum (assume_tac o MATCH_MP 
    ( INST_TYPE [alpha |-> Type `:'r`] word_bit_BITS_TO_WORD )) >>
  `x <= dimindex(:'r) -1` by simp[] >>
  fs [word_bit_def]
));


(*
The following three lemmas describe the words for the blocks following 
those described above

  int_min_lemma: INT_MINw expresses the 0*1 block
  full_padding_lemma: 10*1 = PAD_WORD 0
  one_padding_lemma: 
  
  
*)
val int_min_lemma = prove (
  ``
  (dimindex(:'n) > 0)
  ==>
  ((BITS_TO_WORD ((Zeros (dimindex(:'n)-1))++[T])):'n word
  = INT_MINw)
  ``,
  strip_tac >>
  simp[GSYM WORD_EQ] >>
  rw[] >>
  qmatch_abbrev_tac`word_bit x (BITS_TO_WORD ls) ⇔ word_bit x INT_MINw` >>
  `x < LENGTH ls` by ( simp[Abbr`ls`] ) >>
  simp[word_bit_BITS_TO_WORD] >>
  simp[word_bit_def,word_L,Abbr`ls`] >>
  rev_full_simp_tac(srw_ss()++ARITH_ss)[] >>
  Cases_on`x = dimindex(:'n)-1`>>
  fs[]>>
  simp[EL_APPEND1,EL_APPEND2] >>
  simp[EL_Zeros]);

val full_padding_lemma = prove (
``
( 2 < dimindex(:'r))
==>
(
(BITS_TO_WORD (T::((Zeros (dimindex(:'r)-2))++[T]))):'r word
=  PAD_WORD (0)
)
``,
strip_tac >>
qmatch_abbrev_tac`(BITS_TO_WORD ls) =  word` >>
simp[GSYM WORD_EQ] >>
rw [] >>
`x < (LENGTH ls) ` by ( simp[Abbr`ls`,LengthZeros] ) >>
simp[word_bit_BITS_TO_WORD, word_bit_def,Abbr`word`,word_bit_or,
PAD_WORD_def, fcpTheory.FCP_BETA,word_bits_def,LengthZeros] >>
Cases_on `x=0`
>- simp [Abbr`ls`]
>>
`x>0` by simp[] >>
simp [ Abbr`ls`,LengthZeros ,EL_CONS]  >>
Cases_on `x< LENGTH(m)` >>
pop_assum (fn thm => `0<x` by simp [thm]) >>
Cases_on `x< dimindex(:'r)-1` >>
lrw [EL_CONS,PRE_SUB1,EL_APPEND1, EL_APPEND2,EL_Zeros,LengthZeros]  >>
`x+1-dimindex(:'r)=0` by simp [] >>
rw []
);

(* this lemma shows how to create the the word 110*1 *)
val one_padding_lemma = prove(
``
( 2 < dimindex(:'r))
==>
(
(BITS_TO_WORD (T::T::((Zeros (dimindex(:'r) -3)) ++ [T]))):'r word 
= PAD_WORD(0) || SHA3_APPEND_ONE_WORD(0))
``,
strip_tac >>
simp [GSYM WORD_EQ] >>
rw [] >>
simp [word_bit_BITS_TO_WORD, word_bit_def, word_bit_or, 
fcpTheory.FCP_BETA, word_bits_def, LengthZeros, SHA3_APPEND_ONE_WORD_def] >>
Cases_on `x=1` >> (* the trivial case *)
rw [] >>
Cases_on `x = 0` 
>- (* first bit is T *)
(
  simp [PAD_WORD_def, fcpTheory.FCP_BETA]
)
>>
Cases_on `x=dimindex(:'r) -1` >>
 `(T::T::(Zeros (dimindex(:'r) -3) ++ [T])) = (T::T::(Zeros(dimindex(:'r) -3)) ++ [T])`
  by simp[EL_APPEND2] >>
  pop_assum(fn thm => ONCE_REWRITE_TAC [thm])
>-
(
  qpat_abbrev_tac `ls = T::T::Zeros(dimindex(:'r) -3)`>>
  `LENGTH ls = dimindex(:'r) -1` by simp [Abbr`ls`, LengthZeros] >>
  simp [EL_APPEND2, PAD_WORD_def, fcpTheory.FCP_BETA]
) 
>> 
(
  rw[EL_APPEND1] >>
  `x > 1` by simp [] >>
  `T::T::Zeros(dimindex(:'r) -3) = [T;T] ++ Zeros(dimindex(:'r) -3) ` by simp[] >>
  pop_assum (fn thm => ONCE_REWRITE_TAC [thm]) >>
  simp [EL_APPEND2, PAD_WORD_def, fcpTheory.FCP_BETA, EL_Zeros, EL_CONS] 
)
);


(*
Defines one step of MITB  with permutation function f
MITB_FUN  f : 'b mitb_state -> 'r inputs -> 'b mitb_state
 *)
    
val MITB_FUN_def =
 Define
  `(* Skip : {Ready -> Ready} + {Absorbing -> Absorbing} *)
   (
   (MITB_FUN: ('c,'r) mitb)
     f ((cntl,pmem,vmem)) Skip
    = (cntl,pmem,vmem))
   /\
   (* Input : Ready -> Ready *)
   (MITB_FUN f (Ready,pmem,vmem) (Input key len)
    = (Ready, f((ZERO:'c word) @@ key ),ZERO))
   /\
   (* Move: {Ready -> Absorbing} *)
   (MITB_FUN f (Ready,pmem,vmem) Move
    = (Absorbing,pmem,pmem))
   /\
   (* Move: {Absorbing -> Ready} *)
   (MITB_FUN f (Absorbing,pmem,vmem) Move
    = (Ready,pmem,ZERO))
   /\
   (* Input: Absorbing ->
   {Absorbing,AbsorbEnd110S1,AbsorbEnd10S1,AbsorbEnd0S1,Ready} *)
   (MITB_FUN f (Absorbing,pmem,vmem) (Input blk len)
    =
    let apply x = f(vmem ??  ( (ZERO: 'c word) @@  x)) in
    let g len = ( (len-1 -- 0) 
              (blk) && 
              (SHA3_APPEND_ZERO_WORD(len)) || 
              (SHA3_APPEND_ONE_WORD(len)) || 
              (PAD_WORD(len +2))
          ) in
    let r=dimindex(:'r) in
      if len = 0 then (* 0110*1 *)
            (Ready, pmem,  apply (
            (SHA3_APPEND_ZERO_WORD(len)): 'r word && 
            (SHA3_APPEND_ONE_WORD(len)): 'r word ||
            (PAD_WORD(len +2)): 'r word
            ))
      else  if len <= r - 4 then (* append 01 and Padding *)
          (Ready, pmem, apply 
	    (g len)
	  )
      else  if len = r - 3 then (* append 011 and move to AbsorbEnd0S1 *)
	  (AbsorbEnd0S1, pmem, apply 
	    (g len)
	  )
      else  if len = r - 2 then (* append 01 and move to AbsorbEnd10S1 *)
          (AbsorbEnd10S1, pmem, apply 
	   (g len)
	  )
      else if len = r - 1 then (* append 0 and move to AbsorbEnd110S1 *)
          (AbsorbEnd110S1, pmem, apply 
              ( (len -1 --0) 
                   (blk) && 
                   (SHA3_APPEND_ZERO_WORD(len))
              ))
      else if len = r  then (* Normal case: move into absorbing and wait for more input *)
          (Absorbing, pmem, apply blk)
           else (* behave like skip *)
          (Absorbing,pmem,vmem)
   ) /\
   (* Move: AbsorbEnd -> Ready} *)
   (MITB_FUN f (AbsorbEnd0S1,pmem,vmem) Move  = (Ready, pmem, ZERO)) /\
   (MITB_FUN f (AbsorbEnd10S1,pmem,vmem) Move  = (Ready, pmem, ZERO)) /\
   (MITB_FUN f (AbsorbEnd110S1,pmem,vmem) Move  = (Ready, pmem, ZERO)) /\
   (MITB_FUN  f (AbsorbEnd0S1,pmem,vmem) (Input blk len)
    = 
    (Ready, pmem, 
         f(vmem ?? (( ZERO: 'c word) @@ (INT_MINw:'r word)))
    )
   )
   /\
   (MITB_FUN  f (AbsorbEnd10S1,pmem,vmem) (Input blk len)
    =
    (Ready, pmem, 
           f(vmem ?? ((ZERO: 'c word) @@ (PAD_WORD(0):'r word)))
    )
   )
   /\
   (MITB_FUN  f (AbsorbEnd110S1,pmem,vmem) (Input blk len)
    =
    (Ready, pmem,
           f(vmem ?? ((ZERO:'c word) @@ 
            (PAD_WORD(0):'r word || SHA3_APPEND_ONE_WORD(0)): 'r word
    )))
   )
`;

   (* pro tip: use wordsLib.output_words_as_bin(); *)

(*
Predicate to test for well-formed Keccak parameters
*)
val GoodParameters_def =
 Define
  `GoodParameters (r:num,c:num,n:num)
    ⇔ 4 < r /\ 0 < c /\ n <= r`;

(*
Functional version as in the paper
*)
val MITB_def =
 Define
  `MITB  f ((skip,move,block,size), (cntl,pmem,vmem)) =
    MITB_FUN  f
     (cntl, pmem, vmem)
     (if skip = T
       then Skip else
      if move = T
       then Move
       else
         if (size <=dimindex(:'r)) then
          Input (block: 'r word) size
         else Skip)`;

(*
We define a step function that behaves like MITB, but defines the
output, too.
Parametric in:
 f - compression function used inside MITB
 Input:
  (cnt,pmem,vmem) - current state of the MITB
  (skip,move,block,size) - input to the MITB
 Output:
  (cntl_n,pmem_n,vmem_n) - next state of the MITB
  (ready:bool, digest:bits) - output of the MITB
*)

val MITB_PROJ_OUTPUT_def =
 Define
  `(MITB_PROJ_OUTPUT ((Ready,_,vmem):('r, 'c) mitb_state) = (T,(dimindex(:'n)-1 >< 0) vmem) )
  ∧
   (MITB_PROJ_OUTPUT (_,_,vmem) = (F,ZERO:'n word ) )`;

val MITB_STEP_def =
 Define
  `
  MITB_STEP (* MITB_STEP *) f ((cntl,pmem,vmem),
  (skip,move,block,size))
  =
    let s = MITB f ((skip,move,block,size), (cntl, pmem, vmem):('r, 'c) mitb_state) in
      (s, MITB_PROJ_OUTPUT s:('n) mitb_out)
    `;


(* val MITB_STEP_def = *)
(*  Define *)
(*   `MITB_STEP f ((cntl,pmem,vmem), (skip,move,block,size)) = *)
(*     let (cntl_n,pmem_n,vmem_n) = MITB  f ((skip,move,block,size), (cntl, pmem, vmem)) *)
(*     in *)
(*       ((cntl_n,pmem_n,vmem_n), *)
(*       ( *)
(*       (cntl_n = Ready), *)
(*       (if cntl_n = Ready then ((dimindex(:'n)-1 >< 0) vmem_n) else (ZERO:'n word ))) *)
(*       ) *)
(*     `; *)

(*
Datatype of commands to the library/protocol calling the MITB
*)
val _ =
 Datatype
  `mac_query =
            SetKey ('r word)
          | Mac bits
          | Corrupt
          `;

(*
Datatype for
- responses from the library/protocol to the adversary (real
  world)
- responses from the simulator to the environment (ideal world)
or from the S.
WasCorrupted is a notice that the environment decided to corrupt the
library/protocal or functionality
OracleResponse is the response to an Oracle Query
*)
val _ =
 Hol_datatype
  `mac_to_adv_msg =
            WasCorrupted
          | OracleResponse of 'n word
          `;
(*
Datatype for
- queries from the adversary to the library/protocol (real world)
- queries from the simulator to the functionality (ideal world)
*)
val _ =
 Datatype
  `adv_to_mac_msg =
            CorruptACK
          | OracleQuery bits
          `;

(*
State transition function for the functionality defining a perfect MAC
device for a given Hash function
parameters:
 H  -- Hash function
internal state:
 current key K, corruption status
inputs:
 queries of type query
output:
 bitstrings

REMARK: Whoever is on the adversarial interface may request Hashes with
K prepended to the input. This interface will be accessed by SIM, to be
able to  emulate a MITB

FMAC
: (bits -> 'n word) ->  (* Hash function *)
 'r word # bool ->  (* current key, corruption status *)
 ('r mac_query, γ, δ, ε, ζ, adv_to_mac_msg) Message ->
 (* Input from environment or adversary *)
 ('r word # bool) # ('n word, 'n mac_to_adv_msg) ProtoMessage
 (* output to environment or adversary *)
*)

val FMAC_def =
    Define
          `
          ( FMAC (H: bits -> 'n word) (K,F)
              (EnvtoP (SetKey k:'r mac_query)) =
              ((k,F),(Proto_toEnv (0w:'n word)))
          )
          /\
          ( FMAC H (K,F) (EnvtoP (Mac m)) =
            ((K,F),(Proto_toEnv (H (WORD_TO_BITS(K) ++ m)))))
          /\
          ( FMAC H (K,F) (EnvtoP (Corrupt)) = ((K,T),Proto_toA (WasCorrupted)))
          /\
          ( FMAC H (K,T) (AtoP (CorruptACK)) = ((K,T),Proto_toEnv 0w))
          /\
          ( FMAC H (K,T) (AtoP (OracleQuery m)) =
          ((K,T),(Proto_toA (OracleResponse (H((WORD_TO_BITS K) ++ m))))))
          /\
          (* When corrupted, ignore honest queries *)
          ( FMAC H (K,T) (EnvtoP q) = ((K,T),Proto_toEnv 0w))
          `;

(*
Run MITB mitbf s l

Executes a list of commands l on a initial state s, using the step
function mitbf. This function will make the definition of the protocol,
see below, easier in the future.

The output consists of the state after execution of list l and the final
output (preceeding outputs are discarded).
*)
val RunMITB_def =
 Define
  `RunMITB  mitbf s (i::il) =
  if (il=[]) then
     (mitbf (s,i))
  else
     let (s', out) = (mitbf (s,i)) in
       RunMITB  mitbf s' il
       `;

(*
PROCESS_MESSAGE_LIST: bits list -> 'r mitb_inp list
Given a list of bitstrings, PROCESS_MESSAGE_LIST produces a list of
input queries to the MITB that will leave the MITB in ready state, with
vmem set to the hash of the flattening of the input. This is used in the
protocol definition below.
*)
val PROCESS_MESSAGE_LIST_def= Define
`
  (PROCESS_MESSAGE_LIST  [] =
  ([(F,F,0w,0)]:'r mitb_inp list))
  /\
  (PROCESS_MESSAGE_LIST (hd::tl) =
      if (LENGTH hd) <= dimindex(:'r)-4 then
        ([(F,F,(BITS_TO_WORD hd),(LENGTH hd))])
      else
        (if (LENGTH hd) <  dimindex(:'r) then
          [ (F,F,(BITS_TO_WORD hd),(LENGTH hd)); (F,F, 0w, (LENGTH hd)) ]
        else
          ((F,F,(BITS_TO_WORD hd),(LENGTH hd))
           :: (PROCESS_MESSAGE_LIST tl))))
  `;

(* PROCESS_MESSAGE_LIST never outputs NIL *)
val PROCESS_MESSAGE_LIST_neq_NIL = prove (
  ``!a . PROCESS_MESSAGE_LIST a <> []:'r mitb_inp list``,
          Cases  >> rw[PROCESS_MESSAGE_LIST_def]  );


(*
PROTO

stepfunction defining the protocol. When used with a "correct" MITB (described by a step function), it implements FMAC.

(In real life, this protocol corresponds to a client library that
computes hashes by splitting the message and feeding it into the MITB.
This is how honest users are supposed to use the MITB )

Parametric in:
 mitbf - step function of MITB,
Internal state:
 s - current MITB state
 T/F - corruption status
Input:
 mac_query
Output:
 bitstring
*)

val PROTO_def =
    Define
          `
          ( PROTO (mitbf : ('c,'r) mitb_state # 'r mitb_inp -> ('c,'r)
          mitb_state # 'n mitb_out) (s,F) (EnvtoP (SetKey k)) =
              let (s1,(rdy1,dig1))=mitbf (s,(T,F,(ZERO: 'r word),0)) in
                if rdy1=F then
                  (let (s2,(rdy2,dig2)) =mitbf(s1,(F,T,(ZERO:'r word),0)) in
                    let (s3,(rdy3,dig3))=
                    mitbf (s2,(F,F,k,(dimindex (:'r)))) in
                      ((s3,F),(Proto_toEnv 0w)))
                else
                    let (s2,rdy2,dig2)=mitbf(s1,(F,F,k,(dimindex (:'r)))) in
                     ((s2,F),(Proto_toEnv 0w))
              )
          /\
          ( PROTO mitbf (s,F) (EnvtoP (Mac m)) =
          (* Bring MITB into Ready state *)
           let (s0,(rdy0,dig0)) = RunMITB mitbf s [(T,F,(ZERO: 'r
           word),0)] in
           (* make sure that MITB is in Ready state *)
             let (sr,rdyr,digr) =
              ( if (rdy0=F) then
                  RunMITB mitbf (s0) [(F,T,ZERO,0)]
                else
                  (s0,rdy0,dig0)
              ) in
                let (ss,rdys,digest) = ( RunMITB
                  mitbf
                  (sr)
                  ((F,T,ZERO,0)
                   :: (PROCESS_MESSAGE_LIST (Split (dimindex(:'r)) m ))))
                in
                  (* two consecutive moves to re-initialise vmem *)
                  let (sq,rdyq,digq) = RunMITB mitbf ss [(F,T,ZERO,0);
                  (F,T,ZERO,0)] in
                    ((sq,F),(Proto_toEnv digest))
          )
          /\
          ( PROTO mitbf (s,F) (EnvtoP (Corrupt)) =
                ((s,T),(Proto_toEnv 0w)))
          /\
          (* Give adversary blackbox access when corrupted, but
           *  not complete: she is not allowed to set the key.
           * TODO: would be nicer if we would check the ready state via the LED
           *  *)
          (* Ignore Key-overwrite *)
          (* TODO: Allowing key-overwrite now, remove TODO if proof go
          through *)
          (* ( PROTO mitbf ((Ready,cntl,vmem),T) (AtoP (F,F,inp,len)) = *)
          (*   (((Ready,cntl,vmem),T), (Proto_toA (F,ZERO))) *)
          (* ) *)
          (* /\ *)
          ( PROTO mitbf (s,T) (AtoP i) =
            let (s_next,rdy,dig) = mitbf (s,i) in
                ((s_next,T), (Proto_toA (rdy,dig))))
          /\
          (* Ignore honest queries when corrupted *)
          ( PROTO mitbf (s,T) (EnvtoP _) = ((s,T),(Proto_toEnv 0w)))
          /\
          (* Ignore adversarial queries when not corrupted *)
          ( PROTO mitbf (s,F) (AtoP _) = ((s,F),(Proto_toA ( F,0w ))) )
          /\
          (* Ignore the rest TODO : get rid of this and replace with individual
          * cases.. *)
          ( PROTO mitbf (s,cor) _ = ((s,cor),(Proto_toEnv 0w)))
                `;


(*
SIM - step-function defining the simulator.
The simulator can make queries to F, but only on the adversarial
interface. It should not alter or read F's state directly.

REMARK: We first define a step function for SIM, which is then used in a
wrapper function that instantiates the adversarial interface of F as an
oracle.

State: (corrupt,cntl,vm,m,ovr)
corrupt -> corrupted or not
cntl -> simulated state in case corrupted
vm -> hash value is stored here
m -> list of messages received so far
ovr -> true if the key was over written at some point and we can
simulate without oracle
mitb_state -> if key was overwritten, we can simulate using MITB_FUN
*)

val SIM_def =
  Define `
  (* Skip cases *)
(SIM mitbf f (T,Ready,(vm:'n word) ,m, F, c: ('c,'r) mitb_state) (EnvtoA (T,_,_,_)) =
((T,Ready,vm,m,F, c),(Adv_toEnv
(T,vm:'n word))))
    /\
(SIM mitbf f (T,Absorbing,vm,m, F, c) (EnvtoA (T,_,_,_)) =
((T,Absorbing,vm,m, F, c),(Adv_toEnv (F,ZERO))))
    /\
(SIM mitbf f (T,AbsorbEnd0S1,vm,m, F, c) (EnvtoA (T,_,_,_)) =
((T,AbsorbEnd0S1,vm,m,F,c),(Adv_toEnv (F,ZERO))))  /\
(SIM mitbf f (T,AbsorbEnd10S1,vm,m, F, c) (EnvtoA (T,_,_,_)) =
((T,AbsorbEnd10S1,vm,m,F,c),(Adv_toEnv (F,ZERO))))  /\
(SIM mitbf f (T,AbsorbEnd110S1,vm,m, F, c) (EnvtoA (T,_,_,_)) =
((T,AbsorbEnd110S1,vm,m,F,c),(Adv_toEnv (F,ZERO))))  
/\
  (* Move cases: output zero and move to ready sub_state *)
(SIM mitbf f (T,Ready,vm,m, F, c) (EnvtoA (F,T,_,_)) =
((T,Absorbing,vm,[],F,c),(Adv_toEnv (F,ZERO ))))
    /\
(SIM mitbf f (T,Absorbing,vm,m, F, c) (EnvtoA (F,T,_,_)) =
((T,Ready,ZERO, m, F, c),(Adv_toEnv (T,ZERO ))))
    /\
(SIM mitbf f (T,AbsorbEnd0S1,vm,m, F, c) (EnvtoA (F,T,_,_)) =
((T,Ready,ZERO, m,F,c),(Adv_toEnv (T,ZERO )))) 
/\
(SIM mitbf f (T,AbsorbEnd10S1,vm,m, F, c) (EnvtoA (F,T,_,_)) =
((T,Ready,ZERO, m,F,c),(Adv_toEnv (T,ZERO ))))  /\
(SIM mitbf f (T,AbsorbEnd110S1,vm,m, F, c) (EnvtoA (F,T,_,_)) =
((T,Ready,ZERO, m,F,c),(Adv_toEnv (T,ZERO ))))  
/\
(* Input cases *)
(* Input in Absorbing ->  MAC computation.
  *)
(SIM mitbf f (T,Absorbing,(vm: 'n word),m, F, c) (EnvtoA (F,F,(inp: 'r word),inp_size)) =
 let r = dimindex(:'r) in
  (* Cases:
   *  inp_size=r take full block and go to Absorbing
   *  r- 4 < inp_size <= r-1  take partial block, gota
       AbsorbEnd0S1 or AbsorbEnd10S1 or AbsorbEnd110S1
   *  inp_size <= r-4 query oracle
   *  *)
   if (inp_size > r ) then (* behave like skip *)
    ((T,Absorbing,vm,m,F,c),(Adv_toEnv (F,ZERO)))
   else if (inp_size=r) then (* take full block *)
    ((T,Absorbing,ZERO, (m ++ (WORD_TO_BITS inp),F,c)),(Adv_toEnv (F,ZERO)))
   else if (inp_size <= r-4) then (* query oracle, proceed when response is received *)
     (
       if inp_size = 0 then  (* extra treatment for zero-case necessary
       because of (x -- y) operator (x needs to be non-negative) *)
         ((T,Absorbing,vm,[],F,c), Adv_toP ( OracleQuery (m)))
       else 
         ((T,Absorbing,vm,[],F,c),
           (Adv_toP (
             OracleQuery (m ++
             TAKE inp_size (WORD_TO_BITS ((inp_size-1 --0)
             inp))))))
     )
    else (* r-4 < inp_size < r  *)
          let state = if inp_size = r-1 then AbsorbEnd110S1 
                      else if inp_size = r-2 then AbsorbEnd10S1
                      else (* inp_size = r-3 *) 
                      AbsorbEnd0S1
          in
         ((T,state,ZERO,
         (m ++ TAKE inp_size (WORD_TO_BITS ((inp_size-1 -- 0)
         inp))),F,c), Adv_toEnv (F,ZERO))
         )
    /\
( SIM mitbf f (T,AbsorbEnd0S1,vm,m, F, c) (EnvtoA (F,F,inp:'r word,inp_size)) =
  if (inp_size <= dimindex(:'r))
  then
    ( ((T,AbsorbEnd0S1,vm,[],F,c),(Adv_toP (OracleQuery ((m))))))
  else (* behave like Skip *)
      ((T,AbsorbEnd0S1,vm,m,F,c),(Adv_toEnv (F,ZERO))))
    /\
( SIM mitbf f (T,AbsorbEnd10S1,vm,m, F, c) (EnvtoA (F,F,inp:'r word,inp_size)) =
  if (inp_size <= dimindex(:'r))
  then
    ( ((T,AbsorbEnd10S1,vm,[],F,c),(Adv_toP (OracleQuery ((m))))))
  else (* behave like Skip *)
      ((T,AbsorbEnd10S1,vm,m,F,c),(Adv_toEnv (F,ZERO))))
    /\
( SIM mitbf f (T,AbsorbEnd110S1,vm,m, F, c) (EnvtoA (F,F,inp:'r word,inp_size)) =
  if (inp_size <= dimindex(:'r))
  then
    ( ((T,AbsorbEnd110S1,vm,[],F,c),(Adv_toP (OracleQuery ((m))))))
  else (* behave like Skip *)
      ((T,AbsorbEnd110S1,vm,m,F,c),(Adv_toEnv (F,ZERO)))) 
    /\

(SIM mitbf f (T,_,vm,m, F, c) (PtoA (OracleResponse hashvalue)) =
((T,Ready,hashvalue,[],F,c),(Adv_toEnv (T,hashvalue))))
    /\
(* If FMAC was corrupted, change corruption state *)
(SIM mitbf f (F,cntl,vm,m, F, c) (PtoA WasCorrupted) = ((T,cntl,vm,m,F,c),(Adv_toP
(CorruptACK))))
   ∧
(* If FMAC was corrupted, Adversary can overwrite the key, and Sim can
simulate by itself
Sim: using mitb and doing complete mitb definition. That is, not using oracle but mitb itself. *)
(SIM mitbf f (T,Ready,vm,m, F, c) (EnvtoA (F,F,(inp: 'r word),inp_size)) =
  if (inp_size <= dimindex(:'r))
  then
    let s =  (Ready, f((ZERO:'c word) @@ inp ),ZERO)
      in
    ((T,Ready,vm,m,T,s),(Adv_toEnv (T,ZERO)))
  else (* behave like Skip *)
      ((T,Ready,vm,m,F,c),(Adv_toEnv (T,vm:'n word))))
    /\
    (* After key was overwritten, simulate using MITB_STEP *)
(SIM mitbf f (T,cntl,vm,m, T, s) (EnvtoA i) =
            let (s_next,rdy,dig) = (mitbf f) (s,i) in
              ((T,cntl,vm,m,T,s_next),(Adv_toEnv (rdy,dig))))
    /\
(* Ignore other queries while not corrupted *)
(SIM mitbf f (F,cntl,vm,m, F, c) (EnvtoA _) = ((F,cntl,vm,m,F,c),(Adv_toEnv (F,ZERO))))
      `;

(* Type abbreviations for easier debugging *)
val _ =
 type_abbrev
  ("real_game_state",
   ``: (('c,'r) mitb_state # bool) # num list ``);
(*                           ^ corruption status *)


val _ = type_abbrev ("fmac_state",
   ``: ( 'r word # bool) ``);
(* corruption status ^ *)

val _ = type_abbrev ("proto_state",
   ``: (('c,'r) mitb_state # bool)``);


(* ('n,'r) real_message is *)
val _ = type_abbrev ("real_message",
    ``: ('r mac_query, 'r mitb_inp,  'n word,
     'n mitb_out , 'n mitb_out ,'r mitb_inp ) Message ``);

(* ('n,'r) ideal_message is *)
val _ = type_abbrev ("ideal_message",
    ``: ('r mac_query, 'r mitb_inp,  'n word,
     'n mitb_out , 'n mitb_out , adv_to_mac_msg ) Message ``);

(* ('n,'r) adv_message is *)
val _ = type_abbrev ("adv_message",
    ``: (
     'n mitb_out,
    'r mitb_inp
     ) AdvMessage ``);

val _ = type_abbrev ("env_message",
    ``: ('r mac_query, 'r mitb_inp  ) EnvMessage ``);

val _ = type_abbrev ("real_proto_message",
    ``: ('n word, 'n mitb_out  ) ProtoMessage ``);

val _ = type_abbrev ("ideal_proto_message",
    ``: ('n word, 'n mac_to_adv_msg  ) ProtoMessage ``);

(*
We instantiate the real world with the protocol using the MITB, given
parameters and the compression function
*)
val MITB_GAME_def =
    Define `
     ( (MITB_GAME f):
     (('c, 'r) proto_state # num) # 'r env_message ->
     (('c, 'r) proto_state # num) # ('n word,'n mitb_out) GameOutput)
        =
       EXEC_STEP
       ((PROTO ( (MITB_STEP:('c,'n,'r) mitbstepfunction) f))
       : ('c,'r) proto_state -> ('n,'r) real_message
         -> (('c,'r) proto_state) # 'n real_proto_message)
         DUMMY_ADV
        `;

val ALMOST_IDEAL_GAME_def =
    Define `
      (ALMOST_IDEAL_GAME f (h: bits -> 'n word ))
      =
      EXEC_STEP
      (FMAC h)
      (SIM (MITB_STEP:('c,'n,'r) mitbstepfunction) f)
      `;
(*
We define the invariant that is to be preserved after every
invocation of the real world and the ideal world with the same inputs.
*)

(* corruption status in real and ideal world correspond *)
val STATE_INVARIANT_COR_def =
    Define `
    STATE_INVARIANT_COR ((cntl,pmem,vmem),cor_r)
    ((k,cor_f),(cor_s,cntl_s,vm_s,m_s,ovr_s,s_s)) =
    ((cor_r = cor_f) /\ (cor_f = cor_s)  /\ (ovr_s ==> cor_s)

)
    `;

(*
if real game is corrupted, the cntl-state of the MITB simulated by SIM
and the actual MITB in the real game correspond.
*)
val STATE_INVARIANT_CNTL_def =
    Define `
    STATE_INVARIANT_CNTL ((cntl,pmem,vmem),cor_r)
    ((k,cor_f),(cor_s,cntl_s,vm_s,m_s,ovr_s,(s_cntl,s_pmem,s_vmem))) =
   (
    (cor_r ∧ ¬ovr_s ==> (cntl = cntl_s))
     /\
    (cor_r ∧ ovr_s ==> (cntl = s_cntl))
     /\
    (~cor_r ==> (cntl = Ready) /\ (cntl_s = Ready ))
   )
    `;

(*
We need a different version of SplittoWord for the invariant, as in the
case where no input has been made yet (m_s), we expect SplittoWords to
  give an empty list rather than a list consisting of a single 0-word.
*)
val SplittoWords2_def =
  Define
  `(SplittoWords2: bits -> 'r word list) bitlist =
   if bitlist = [] then []
   else SplittoWords bitlist`

(*
TODO document
*)
val STATE_INVARIANT_MEM_def =
    Define `
    (* STATE_INVARIANT_MEM f *) 
    (*   (((cntl:control),(pmem:('r+'c) word),(vmem:('r+'c) word)),(cor_r:bool)) *)
    (*   ((k: 'r word,cor_f),(cor_s,cntl_s,(vm_s:'n word ),m_s, ovr_s,(s_cntl,s_pmem,s_vmem))) *)
    (*   ⇔ *)
    (* cor_r ∧ ~ovr_s, no padding case *)
   (STATE_INVARIANT_MEM f 
      (((Absorbing),(pmem:('r+'c) word),(vmem:('r+'c) word)),(T))
      ((k: 'r word,cor_f),(cor_s,cntl_s,(vm_s:'n word ),m_s, F,(s_cntl,s_pmem,s_vmem)))
      ⇔
        (pmem = f(ZERO: 'c word @@ k))
        /\
        (? n. LENGTH m_s=n * dimindex(:'r))
        /\
        (vmem = Absorb f (f(ZERO: 'c word @@ k)) ( SplittoWords2 m_s) ))
   ∧
    (* cor_r ∧ ~ovr_s, previous word was r-1 *)
   (STATE_INVARIANT_MEM f 
      (((AbsorbEnd110S1),(pmem:('r+'c) word),(vmem:('r+'c) word)),(T))
      ((k: 'r word,cor_f),(cor_s,cntl_s,(vm_s:'n word ),m_s, F,(s_cntl,s_pmem,s_vmem)))
      ⇔
        (pmem = f(ZERO: 'c word @@ k))
        /\
        (? n. (LENGTH m_s=n * dimindex(:'r) - 1) /\ ( n>0))
        /\
        (vmem = Absorb f (f(ZERO:'c word @@ k )) (SplittoWords (m_s ++ [F] )) ) )
  ∧
    (* cor_r ∧ ~ovr_s, previous word was r-2 *)
   (STATE_INVARIANT_MEM f 
      (((AbsorbEnd10S1),(pmem:('r+'c) word),(vmem:('r+'c) word)),(T))
      ((k: 'r word,cor_f),(cor_s,cntl_s,(vm_s:'n word ),m_s, F,(s_cntl,s_pmem,s_vmem)))
      ⇔
        (pmem = f(ZERO: 'c word @@ k))
        /\
        (? n. (LENGTH m_s=n * dimindex(:'r) - 2) /\ ( n>0))
        /\
        (vmem = Absorb f (f(ZERO:'c word @@ k )) (SplittoWords (m_s ++ [F;T] )) ) )
  ∧
    (* cor_r ∧ ~ovr_s, previous word was r-3 *)
   (STATE_INVARIANT_MEM f 
      (((AbsorbEnd0S1),(pmem:('r+'c) word),(vmem:('r+'c) word)),(T))
      ((k: 'r word,cor_f),(cor_s,cntl_s,(vm_s:'n word ),m_s, F,(s_cntl,s_pmem,s_vmem)))
      ⇔
        (pmem = f(ZERO: 'c word @@ k))
        /\
        (? n. (LENGTH m_s=n * dimindex(:'r) - 3) /\ ( n>0))
        /\
        (vmem = Absorb f (f(ZERO:'c word @@ k )) (SplittoWords (m_s ++ [F;T;T] )) ) )
  ∧
    (* cor_r ∧ ~ovr_s, Ready *)
   (STATE_INVARIANT_MEM f 
      (((Ready),(pmem:('r+'c) word),(vmem:('r+'c) word)),(T))
      ((k: 'r word,cor_f),(cor_s,cntl_s,(vm_s:'n word ),m_s, F,(s_cntl,s_pmem,s_vmem)))
      ⇔
        (pmem = f(ZERO: 'c word @@ k))
        /\
        ((Output vmem)=vm_s) )
  ∧
     (* (cor_r ∧ ovr_s ==> (pmem = s_pmem) /\ (vmem = s_vmem)) *)
   (STATE_INVARIANT_MEM f 
      (((cntl),(pmem:('r+'c) word),(vmem:('r+'c) word)),(T))
      ((k: 'r word,cor_f),(cor_s,cntl_s,(vm_s:'n word ),m_s,
      T,(s_cntl,s_pmem,s_vmem)))
      ⇔
        (pmem = s_pmem) /\ (vmem = s_vmem))
  ∧
     (* ~cor_r ==> (pmem = f(ZERO: 'c word @@ k)) /\ (vmem = ZERO) /\ (vm_s = ZERO) *)
   (STATE_INVARIANT_MEM f 
      (((cntl),(pmem:('r+'c) word),(vmem:('r+'c) word)),(F))
      ((k: 'r word,cor_f),(cor_s,cntl_s,(vm_s:'n word ),m_s,
      ovr_s,(s_cntl,s_pmem,s_vmem)))
      ⇔
        (pmem = f(ZERO: 'c word @@ k)) /\ (vmem = ZERO) /\ (vm_s =
        ZERO))
    `;


(* The complete invariant (will grow in the future) *)
val STATE_INVARIANT_def =
  Define `
  STATE_INVARIANT f (state_r) (state_f) ⇔
    ( (STATE_INVARIANT_COR (state_r) (state_f))
     /\
     (STATE_INVARIANT_CNTL (state_r) (state_f))
     /\
     (STATE_INVARIANT_MEM f (state_r) (state_f)))`

val rws_invariants =
 [ STATE_INVARIANT_def, STATE_INVARIANT_COR_def,
STATE_INVARIANT_CNTL_def,STATE_INVARIANT_MEM_def ];

val rws =
[EXEC_STEP_def,
EXEC_def,
LET_THM,ENV_WRAPPER_def,ROUTE_THREE_def,ROUTE_def,
  SIM_def,ADV_WRAPPER_def,DUMMY_ADV_def,PROTO_def,
  MITB_STEP_def,
  (* Here is the lambda-free MITB_STEP rule: *)
  (* CONV_RULE (DEPTH_CONV PairedLambda.let_CONV) MITB_STEP_def, *)
  MITB_def,MITB_FUN_def,PROTO_WRAPPER_def,STATE_INVARIANT_def,FMAC_def,
  STATE_INVARIANT_COR_def, STATE_INVARIANT_CNTL_def,
  ALMOST_IDEAL_GAME_def, MITB_GAME_def,
  RunMITB_def,
  GAME_OUT_WRAPPER_def, ZERO_def
                    ];


val mitb_skip_lemma =
  prove (
  ``
    (((cntl',pmem',vmem'),(rdy,dig)) = RunMITB (MITB_STEP:('c,'n,'r) mitbstepfunction f) (cntl,pmem,vmem) [(T,b,inp,len)] )
    ==>
    ( cntl=cntl')
    /\
    ( pmem=pmem')
    /\
    ( vmem=vmem')
    /\
    (( rdy=T) ==> (cntl=Ready) )
    /\
    (( rdy=F) ==> (cntl=Absorbing) \/ (cntl=AbsorbEnd0S1) \/
    (cntl=AbsorbEnd10S1)  \/ (cntl=AbsorbEnd110S1))
    ``,
split_all_pairs_tac >>
split_all_control_tac >>
fs [RunMITB_def, MITB_STEP_def, MITB_FUN_def, MITB_def,
MITB_PROJ_OUTPUT_def] >>
fsrw_tac [ARITH_ss] [LET_THM]
);


(* This lemma is useful for simplifying terms occuring in the padding *)
val a_mult_b_mod_a_lemma = prove (
``( 0 < a) ==> ((a + b) MOD a = b MOD a)``,
rw [] >>
first_assum (ASSUME_TAC o SYM o (Q.SPECL [`a`,`b`]) o (MATCH_MP
MOD_PLUS)) >>
first_assum (ASSUME_TAC o CONJUNCT2 o (MATCH_MP DIVMOD_ID)) >>
rw []);

val n_a_mult_b_mod_a_lemma = prove (
``( 0 < a) ==> ((n * a  + b) MOD a = b MOD a)``,
Induct_on `n` >>
rw [MULT] >>
fs [] >>
`(n*a + a + b)=(a + (n*a +b))` by simp [] >>
rw [a_mult_b_mod_a_lemma]
);

(*
Rewrite system for what concerns the MACing procedure inside the
protocol
*)
val rws_macking =
  [
  LET_THM,
  MITB_STEP_def, MITB_def,MITB_FUN_def,RunMITB_def,MITB_PROJ_OUTPUT_def,
  PROCESS_MESSAGE_LIST_def,
  SHA3_APPEND_def
  ]

(*
Rewrite system for what concerns the definition of Hash. (Ideal world
behaviour)
*)
val rws_hash =
  [
  LET_THM,
  Hash_def, Output_def, Absorb_def, 
  Pad_def, Zeros_def, PadZeros_def, ZERO_def,
  a_mult_b_mod_a_lemma,
  SplittoWords_def,
  SplittoWords2_def,
  SHA3_APPEND_def
   ];

val rws_hash_sans_split =
  [
  LET_THM,
  Hash_def, Output_def, Absorb_def, 
  Pad_def, Zeros_def, PadZeros_def, ZERO_def,
  a_mult_b_mod_a_lemma
   ];

val non_zero_mult = prove(
``!(n:num) a . ( n <> 0)  ==> (n * a >= a)``,
  Cases >> rw [MULT_SUC]);

val Split_APPEND = prove(
``
! r a b n.
LENGTH a > 0 /\
LENGTH b > 0 /\
(LENGTH a = n * r)
==> (Split r (a++b) = Split r a ++ Split r b)``,
recInduct(Split_ind) >>
rw [] >>
`r<>0` by spose_not_then (fn t=> fs[t]) >>
pop_assum (fn t=> fs[t] >> assume_tac t) >>
`n<>0` by spose_not_then (fn t=> fs[t]) >>
`n*r >= r` by simp [non_zero_mult] >>
`n*r + LENGTH b > r` by simp [] >>
rw [(Once Split_def)]
>> lfs [] (*Contradictory case *)
>>
`r <= LENGTH (msg)` by simp [] >>
rw [TAKE_APPEND1] >>
Cases_on `n<=1`
>- (
  `n=1` by simp [] >>
  `r=LENGTH msg` by simp [] >>
  rw [DROP_LENGTH_APPEND,TAKE_LENGTH_APPEND] >>
  rw [(Once Split_def)]
)
>>
qpat_x_assum `P ==> !b n. Q` (* Invariant *)
 (fn t => first_assum
 (assume_tac o Q.SPECL [`b`, `(n-1)`] o MATCH_MP t)) >>
`n -1 <> 0` by simp[] >>
 pop_assum (assume_tac o Q.SPEC `r` o MATCH_MP non_zero_mult) >>
 `n * r > r` by simp [] >>
 `n* r -r = (n-1)*r` by simp [] >>
 res_tac >>
 rw [DROP_APPEND1] >>
 qmatch_abbrev_tac `lhs=rhs` >> qunabbrev_tac `rhs` >>
 rw [(Once Split_def)]
);


val msg_not_nil = prove (
``! msg. LENGTH msg > 0 ==> msg <> []``,
Induct
>- rw []
>> strip_tac >> simp[] 
);


(*
This lemma shows that the MACing step in the protocol is executed
correctly, i.e., that the virtual memory after execution equals a
properly computed hash,  given that the MITB was in Absorbing state
before.

REMARK: In mac_message_in_ready_lemma, we will be able to establish that
vmem equals pmem after moving into Absorbing. Thus
(Absorb f vmem (SplittoWords (Pad ( dimindex(:'r) ) m)))
will equal Hash f .. for the truncated output, if composed right.
*)



val mac_message_in_absorbing = prove (
``! r m pmem vmem .
  (
  (r = dimindex(:'r))
  /\
  (GoodParameters (dimindex(:'r),dimindex(:'c),dimindex(:'n)))
  )
  ==>
  (
   RunMITB
       (MITB_STEP: ('c,'n,'r) mitbstepfunction  f)
       (Absorbing,pmem,vmem)
       (PROCESS_MESSAGE_LIST
       (Split (dimindex(:'r)) m))
   =
   ((Ready, pmem,
      (Absorb f vmem (SplittoWords (Pad ( dimindex(:'r) ) (SHA3_APPEND m))))
    ),
    (T,Hash f vmem m)
    )
    ) ``,

   recInduct(Split_ind) >>
   strip_tac >> strip_tac >>
   Cases_on `LENGTH msg <= dimindex(:'r)`
   >-
   (
    simp [GoodParameters_def,(Once Split_def)] >>
    (ntac 3 strip_tac) >>
    `Split (dimindex(:'r)) msg = [msg]`
      by (rw [(Once Split_def)]) >> 
    `(dimindex(:'r) = LENGTH msg  )
     \/
     (LENGTH msg = dimindex(:'r)-1 )
     \/
     ((0 < LENGTH msg) /\ (LENGTH msg < dimindex(:'r)-1 ))
     \/
     (0 = LENGTH msg )` by RW_TAC arith_ss []

    >- (* LENGTH msg = dimindex(:'r) *)
    (
      fsrw_tac [ARITH_ss] rws_macking >>
      PairedLambda.GEN_BETA_TAC >>
      (CASE_TAC >> fs[]) >>
      fs rws_macking >>
      (* now cntl_t, pmem_t and vmem_t are determined *)
      fsrw_tac [ARITH_ss] (a_mult_b_mod_a_lemma::rws_hash) >>
      `! rest more . ((msg++[F]++[T]++[T])++ rest) ++ more
       = msg++ ([F]++[T]++[T]++ rest ++ more)` by rw [] >>
      pop_assum (fn thm => PURE_REWRITE_TAC [thm]) >>
      qpat_abbrev_tac `zeroblock = ([F]++[T]++[T] ++ Zeros (LENGTH msg - 4)) ++ [T]` >>
      `0 < LENGTH (msg)` by simp [] >>
      `0 < LENGTH (zeroblock)` by simp [LengthZeros,Abbr`zeroblock`] >>
      RW_TAC arith_ss  [Split_LENGTH_APPEND] >>
      pop_assum (fn thm => ALL_TAC) >> 
      pop_assum (fn thm => ALL_TAC) >>  
      `LENGTH (zeroblock) = LENGTH msg` by simp [LengthZeros,Abbr`zeroblock`] >>
      `LENGTH (msg ++ zeroblock) > LENGTH (msg)` by simp [] >>
      RW_TAC arith_ss  [ (Once Split_def) ] >>
      rw [DROP_LENGTH_APPEND, TAKE_LENGTH_APPEND] >>
      rw rws_hash >>
      RW_TAC arith_ss  [ (Once Split_def) ] >>
      rw rws_hash >>
      qpat_x_assum `dimindex(:'r) = LENGTH (msg)`
        (fn thm => assume_tac (SYM thm)) >>
      simp [ Abbr`zeroblock`,full_padding_append_lemma, ZERO_def ]
    )

    >- (* LENGTH msg = dimindex(:'r)-1 *)
    (
      fsrw_tac [ARITH_ss] rws_macking >>
      `~(dimindex(:'r)-1 <= dimindex(:'r) -2)` by simp [] >>
      pop_assum (fn thm => fsrw_tac[ARITH_ss] [thm]) >>
      fs rws_macking >>
      simp [GSYM one_padding_lemma] >>
      `dimindex(:'r) -2 = LENGTH msg -1` by simp[] >> 
      pop_assum (fn thm => ONCE_REWRITE_TAC [thm]) >>
      qpat_x_assum `LENGTH msg = dimindex(:'r) -1` (fn thm => assume_tac (SYM thm)) >>
      `2 < dimindex(:'r)` by simp[] >>
      rw [] >>
      qpat_abbrev_tac `m' = (LENGTH msg -1 -- 0) (BITS_TO_WORD msg)` >>
      RW_TAC std_ss [WORD_AND_COMM] >>
      RW_TAC std_ss [Abbr`m'`, GSYM one_short_lemma] >>
      pop_assum (fn thm => ALL_TAC) >>
      rw [Hash_def, SHA3_APPEND_def]   >>
      (* now cntl_t, pmem_t and vmem_t are determined *)
      qpat_abbrev_tac `m' = msg ++ [F] ++ [T]` >>
      `LENGTH m' = dimindex(:'r) + 1` by simp[Abbr`m'`] >>
      fsrw_tac [ARITH_ss] (a_mult_b_mod_a_lemma::rws_hash) >>
      rw [Abbr`m'`] >>
      `[F;T] = [F] ++ [T]` by simp [] >> pop_assum (fn thm => ONCE_REWRITE_TAC [thm]) >>
      RW_TAC arith_ss  [GSYM APPEND_ASSOC] >> 
      qpat_abbrev_tac `block2 = ([T] ++ ([T] ++  (Zeros (dimindex(:'r) - 3) ++ [T]))) ` >>
      RW_TAC arith_ss  [APPEND_ASSOC] >>
      qpat_abbrev_tac `block1 = (m' ++ [F]) ` >>
      `LENGTH (block1) = dimindex(:'r)` by simp [Abbr`block1`] >>
      `LENGTH (block2) = dimindex(:'r)` by simp [Abbr`block2`] >>
      `0 < LENGTH (block1)  /\ 0 < LENGTH (block2) ` by simp [] >>
      `LENGTH (block2) = dimindex(:'r)` by simp [Abbr`block2`] >>
      qpat_x_assum ` LENGTH (block1) =  dimindex(:'r)`
        (fn thm => assume_tac (SYM thm)) >>
      `~(LENGTH block1 + LENGTH(block2) <= LENGTH (block1)) ` by simp [Abbr`block1`] 
      >>
      RW_TAC arith_ss  [Split_LENGTH_APPEND] >>
      fs [] >>
      qpat_x_assum ` LENGTH (block2) = X` (fn thm=>assume_tac (SYM thm)) >>
      rw (Once (Split_def)::rws_hash)      
    )

    >- (* LENGTH msg < dimindex(:'r) -1 *)
    (
   
        (* Additional cases *)
      `((0 < LENGTH msg) /\ (LENGTH msg <= dimindex(:'r) -4))
      \/ 
      (LENGTH msg = dimindex(:'r) -3)
      \/ 
      (LENGTH msg = dimindex(:'r) -2)` by RW_TAC arith_ss []
      >- (* LENGTH msg <= dimindex(:'r) -4 *)
      (
      ( 
        fsrw_tac [ARITH_ss] rws_macking >>
        `2 < dimindex(:'r)` by simp [] >>
        `LENGTH msg < dimindex(:'r) -3` by simp [] >>
        `LENGTH msg <> 0` by RW_TAC arith_ss [] >>
        `msg <> []` by simp [msg_not_nil] >> 
        pop_assum (fn thm => ONCE_REWRITE_TAC [thm]) >> simp [] >>
        (* this is rather  ugly, but I couldn't figure out how to do this without abbreviations *)  
        qpat_abbrev_tac `m' = (LENGTH msg -1 -- 0) (BITS_TO_WORD msg) ` >> 
        qpat_abbrev_tac `one_word = SHA3_APPEND_ONE_WORD (LENGTH msg)` >>
        qpat_abbrev_tac `padding = PAD_WORD (LENGTH msg +2)` >>
        qpat_abbrev_tac `zero_word = SHA3_APPEND_ZERO_WORD (LENGTH msg)` >>
        `padding || one_word || zero_word && m' = m' && zero_word || one_word || padding` by rw[] >> 
        pop_assum (fn thm => RW_TAC std_ss [thm]) >>
        RW_TAC std_ss [Abbr`m'`, Abbr`zero_word`, Abbr`one_word`, Abbr`padding`, GSYM padding_lemma] >>
        ntac 3 (pop_assum (fn thm => ALL_TAC)) >>
       
        (* now cntl_t, pmem_t and vmem_t are determined *)
        rw [Hash_def, SHA3_APPEND_def] >>
        qpat_abbrev_tac `m' = msg ++ [F] ++ [T]` >>
        `LENGTH m' MOD dimindex(:'r) <> dimindex(:'r)-1` by simp [Abbr`m'`] >>
        `LENGTH m' <= dimindex(:'r) -2` by simp[Abbr`m'`] >>
        lrw [Hash_def,Pad_def,PadZerosLemma ] >>
        qpat_abbrev_tac `block = m' ++ [T] ++ (Zeros (dimindex(:'r) - (LENGTH m' +
        2))) ++ [T]` >>
        `LENGTH block = dimindex(:'r)` by simp [Abbr`block`,Abbr`m'`, LengthZeros] >>
        rw  (rws_hash@[(Once Split_def)]) >>
        simp [Abbr`m'`, Abbr`block`] >>
        `F::T::T::Zeros (dimindex(:'r) - (LENGTH msg + 4)) = [F] ++ [T] ++ [T] ++
        Zeros (dimindex (:ς) − (LENGTH msg + 4))` by simp [] >>
        pop_assum (fn thm => ONCE_REWRITE_TAC [thm]) >>
        rw [MITB_PROJ_OUTPUT_def] 
      )

      )

      >- (* LENGTH msg = dimindex(:'r) - 3 *)
      ( 
        fsrw_tac [ARITH_ss] rws_macking >>
        pop_assum (fn thm => assume_tac (GSYM thm)) >> rw[] >>
        `2 < dimindex(:'r)` by simp[] >>
        `dimindex(:'r) -4 = (LENGTH msg -1)` by simp[] >>
        pop_assum (fn thm => ONCE_REWRITE_TAC[thm]) >>
        `dimindex(:'r) -1 = LENGTH msg +2` by simp[] >>
        pop_assum (fn thm => ONCE_REWRITE_TAC[thm]) >>
        qpat_abbrev_tac `m' = (LENGTH msg -1  -- 0) (BITS_TO_WORD m)` >>
        qpat_abbrev_tac `one_word = SHA3_APPEND_ONE_WORD (LENGTH m)` >>
        qpat_abbrev_tac `padding = PAD_WORD (LENGTH m +2)` >>
        qpat_abbrev_tac `zero_word = SHA3_APPEND_ZERO_WORD (LENGTH msg)` >> 
        `padding || one_word || zero_word && m' = m' && zero_word || one_word || padding` by simp [] >>
        pop_assum (fn thm => ONCE_REWRITE_TAC [thm]) >>
        RW_TAC std_ss [Abbr`m'`, Abbr`padding`, Abbr`one_word`, Abbr`zero_word`, 
          GSYM three_short_lemma] >>
        pop_assum (fn thm => ALL_TAC) >>
        pop_assum (fn thm => assume_tac (GSYM thm)) >>
        rw [Hash_def, SHA3_APPEND_def] >>
        qpat_abbrev_tac `m' = msg ++ [F] ++ [T]` >>
        `LENGTH m' = dimindex(:'r) -1` by simp [Abbr`m'`] >> 
        lrw [Hash_def, Pad_def, PadZerosLemma]  >>
        qpat_abbrev_tac `block = m' ++ [T]` >>
        `LENGTH block = dimindex(:'r)` by simp[Abbr`block`, LengthZeros] >> 
        rw (rws_hash@[(Once Split_def)]) >>
        qpat_abbrev_tac `zeros =  Zeros (dimindex (:'r) -1)` >>
        ONCE_REWRITE_TAC [GSYM APPEND_ASSOC] >>
        qpat_abbrev_tac `padding = zeros ++ [T]` >>
        `LENGTH padding = dimindex(:'r)` by  
          simp [Abbr`padding`,Abbr`zeros`, LengthZeros, LENGTH_APPEND] >>
        rw [DROP_APPEND1, TAKE_APPEND, TAKE_LENGTH_ID_rwt, DROP_LENGTH_NIL_rwt, (Once Split_def)] >>
        simp[Abbr`padding`, Abbr`zeros`, int_min_lemma] >>
        simp [Absorb_def, Abbr`block`, Abbr`m'`] >>
        ntac 2 (ONCE_REWRITE_TAC [GSYM APPEND_ASSOC]) >>
        `[F] ++ ([T] ++ [T]) = [F;T;T]` by simp [] >>
        pop_assum (fn thm => ONCE_REWRITE_TAC [thm]) >>
        rw []
      )
      >> (* LENGTH msg = dimindex(:'r) - 2) *)
      ( 
        fsrw_tac [ARITH_ss] rws_macking >>
        pop_assum (fn thm => assume_tac (GSYM thm)) >> rw[] >>
        `2 < dimindex(:'r)` by simp[] >>
        `dimindex(:'r) - 3 = (LENGTH msg -1)` by simp[] >>
        pop_assum (fn thm => ONCE_REWRITE_TAC[thm]) >>
        `dimindex(:'r)  = LENGTH msg +2` by simp[] >>
        pop_assum (fn thm => ONCE_REWRITE_TAC[thm]) >>
        qpat_abbrev_tac `m' = (LENGTH msg -1  -- 0) (BITS_TO_WORD m)` >>
        qpat_abbrev_tac `one_word = SHA3_APPEND_ONE_WORD (LENGTH m)` >>
        qpat_abbrev_tac `padding = PAD_WORD (LENGTH m +2)` >>
        qpat_abbrev_tac `zero_word = SHA3_APPEND_ZERO_WORD (LENGTH msg)` >> 
        `padding || one_word || zero_word && m' = m' && zero_word || one_word || padding` by simp [] >>
        pop_assum (fn thm => ONCE_REWRITE_TAC [thm]) >>
        RW_TAC std_ss [Abbr`m'`, Abbr`padding`, Abbr`one_word`, Abbr`zero_word`, 
          GSYM two_short_lemma] >>
        pop_assum (fn thm => ALL_TAC) >>
        pop_assum (fn thm => assume_tac (GSYM thm)) >>
        rw [Hash_def, SHA3_APPEND_def] >>
        qpat_abbrev_tac `block = msg ++ [F] ++ [T]` >>
        `LENGTH block = dimindex(:'r)` by simp [Abbr`block`] >> 
        lrw [Hash_def, Pad_def, PadZerosLemma, GSYM full_padding_lemma]  >>
        rw (rws_hash@[(Once Split_def)]) >>
        `T::(Zeros (dimindex(:'r) -2) ++ [T])  = [T] ++ Zeros(dimindex(:'r) -2) ++ [T] ` by simp[]  >> 
        pop_assum (fn thm => ONCE_REWRITE_TAC[thm]) >>
        ntac 2 ( ONCE_REWRITE_TAC [GSYM APPEND_ASSOC]) >>
        qpat_abbrev_tac `padding = [T] ++ (Zeros (dimindex(:'r) -2) ++ [T])` >>
        `LENGTH padding = dimindex(:'r)` by  
          simp [Abbr`padding`, LengthZeros, LENGTH_APPEND] >>
        rw [DROP_APPEND1, TAKE_APPEND, TAKE_LENGTH_ID_rwt, DROP_LENGTH_NIL_rwt, (Once Split_def)] >>
        simp [Absorb_def] >>
        `msg ++ [F;T] =  block` by simp[Abbr`block`] >>
        pop_assum (fn thm => rw [thm])
      )
     
    )
    >> (* LENGTH msg = 0 *)
    (`LENGTH msg <> dimindex(:'r) -1` by simp [] >>
      fsrw_tac [ARITH_ss] rws_macking >>
      pop_assum (fn t => ALL_TAC) >>
      (* now cntl_t, pmem_t and vmem_t are determined *)
      pop_assum (assume_tac o SYM) >>
      fs [LENGTH_NIL] >>
      SUBGOAL_THEN ``LENGTH (Pad (dimindex(:'r)) []) = dimindex(:'r)``  (fn thm => assume_tac thm) 
      >- (fs[Pad_def,PadZerosLemma,LengthZeros] >> `msg = []` by fs[]>> lfs[])
      
       >> rw  (rws_hash@[(Once Split_def),ZERO_def]) >>
      qpat_abbrev_tac `block =F::T :: T :: ((Zeros (dimindex(:'r) - 4)) ++
      [T])` >>
      `LENGTH block = dimindex(:'r)` by simp [Abbr`block`,LengthZeros] >>
      rw ([Abbr `block`, (Once Split_def),LengthZeros]@rws_hash) >>
      `2 < dimindex(:'r)` by simp [] >>
      assume_tac full_padding_append_lemma >> rw [] 
    )
  ) (* LENGTH msg > dimindex*:'r) *)
  >>
   ntac 4 strip_tac >>
   SIMP_TAC std_ss [(Once Split_def)] >>
   fs [GoodParameters_def] >>
   last_assum (fn t => lfs [t] >> assume_tac t) >>
   simp  (rws_macking) >>
   qpat_abbrev_tac `head=TAKE (dimindex(:'r)) msg` >>
   PURE_REWRITE_TAC [GSYM DROP_APPEND1, GSYM APPEND_ASSOC] >>
   qpat_abbrev_tac `rest=DROP (dimindex(:'r)) msg ++ ([F] ++ [T]) ` >>
   `LENGTH (rest) > 0` by simp [Abbr`rest`,LENGTH_DROP] >>
   `!a . PROCESS_MESSAGE_LIST a <> []:'r mitb_inp list` by
          (Cases  >> rw[PROCESS_MESSAGE_LIST_def] ) >>
   pop_assum (qspec_then `Split (dimindex(:'r)) rest` (fn t => simp[t]))
   >>
   (* qpat_assum `!pmem vmem. P` (fn t => qspecl_then [`pmem`,) >> *)
   rw [Hash_def, SHA3_APPEND_def] >> 
   rw [Pad_def] >>
   qmatch_abbrev_tac `LHS = RHS` >> simp[Abbr`RHS`] >>
   simp [SplittoWords_def, (Once Split_def)] >>
   simp [Absorb_def] >> 
   `!x. TAKE (dimindex(:'r)) (msg ++ x) = TAKE (dimindex(:'r)) msg` by simp[TAKE_APPEND1] >>
   pop_assum (fn thm => RW_TAC arith_ss [GSYM APPEND_ASSOC, thm]) >>
   simp [Abbr`LHS`, ZERO_def,   GSYM Pad_def,  Abbr`rest`,  SplittoWords_def] >>
   simp [Pad_def,  GSYM DROP_APPEND1] >>
   simp [PadZerosLemma, SUB_MOD, GSYM DROP_APPEND1]
);

val mac_message_in_ready_lemma = prove (
``! pmem vmem  m inp len .
  (GoodParameters (dimindex(:'r),dimindex(:'c),dimindex(:'n)))
  ==>
(
  ( RunMITB
        (MITB_STEP: ('c,'n,'r)mitbstepfunction  f)
        (Ready,pmem,vmem)
      ((F,T,inp,len)
        :: (PROCESS_MESSAGE_LIST
            (Split (dimindex(:'r)) m))
      ))
  =
  ((Ready, pmem,
      (Absorb f pmem (SplittoWords (Pad ( dimindex(:'r) ) (SHA3_APPEND m))))
    ),
    (T,Hash f pmem m))
)
    ``,

rw [] >>
qpat_abbrev_tac `COMS = (PROCESS_MESSAGE_LIST (Split (dimindex(:'r)) m)):'r
mitb_inp list` >>
`COMS <> []` by rw [Abbr`COMS`, PROCESS_MESSAGE_LIST_neq_NIL ] >>
simp rws >>
rw [Abbr`COMS`]  >>
(* Now in Absorbing state *)
rw [mac_message_in_absorbing]
);

local 
fun tac1 arg =
   (RW_TAC std_ss [PROTO_def]
     \\ ntac 2 (Q.PAT_UNDISCH_TAC `a (MITB_STEP f) (^arg,_,_) l = r` 
     \\ simp [RunMITB_def, MITB_STEP_def, MITB_def,
     MITB_FUN_def,MITB_PROJ_OUTPUT_def]
     \\ strip_tac
     \\ SYM_ASSUMPTION_TAC ``(a,b,c) = s``
     \\ lfs[])
     \\ first_assum (assume_tac o (MATCH_MP mac_message_in_ready_lemma))
     \\ pop_assum (fn t => fs [t])
     \\	rw []
     \\ lfs [RunMITB_def, MITB_STEP_def, MITB_def, MITB_FUN_def]
    )
in
val mac_message_lemma = prove (
``(GoodParameters (dimindex(:'r),dimindex(:'c),dimindex(:'n)))
==>
(
(*! m . *)
( PROTO ( (MITB_STEP:('c,'n,'r) mitbstepfunction) f)
   ((cntl,pmem,vmem),F) (EnvtoP (Mac m) :('n,'r)real_message) )
 =
 (((Ready, pmem, ZERO ),F), (Proto_toEnv (Hash f pmem m)))
)
    ``,

     rw[]
  \\ Cases_on `cntl = Ready`
  >-( RW_TAC std_ss [PROTO_def]
     \\ split_all_pairs_tac
     \\ first_assum (assume_tac o (MATCH_MP mitb_skip_lemma) o SYM)
     \\ first_assum (assume_tac o (MATCH_MP mac_message_in_ready_lemma))
     \\ `sr0=Ready` by fs[]
     \\ rw[]
     \\ pop_assum (fn t => fs [t])
     \\	rw []
     \\ lfs [RunMITB_def, MITB_STEP_def, MITB_def, MITB_FUN_def]
    )
  \\ MAP_EVERY (fn a => Cases_on `cntl = ^a` >- tac1 a) [``Absorbing``, ``AbsorbEnd0S1``, ``AbsorbEnd10S1``, ``AbsorbEnd110S1``]
  \\ (Cases_on `cntl` >> fs[])
)
end;

(*
Given that the complete invariant holds, the corruption part of
the invariant holds in the next step.
*)

fun COUNT_TAC tac g =
  let 
    val res as (sg,_) = tac g
    val _ = print ("subgoals: "^Int.toString (List.length sg)^"\n")
  in res
  end 


val Invariant_cor = store_thm("Invariant_cor",
 ``! f
     (* The MITB's state in the real game *)
     (cntl:control) (pmem:('r+'c) word) (vmem:('r+'c) word)  (cor_r:bool)
     (* The functionality's state (cor_s is shared with Sim)*)
      k cor_f
     (* The dummy adversary's state, does not matter really *)
      nd
      (* The simulator's state *)
      cor_s cntl_s vm_s m_s ovr_s s_cntl s_pmem s_vmem
      (* The environment's query *)
      (input: 'r env_message) .
        (GoodParameters (dimindex(:'r),dimindex(:'c),dimindex(:'n)))
        /\
        (STATE_INVARIANT f ((cntl,pmem,vmem),cor_r)
        ((k,cor_f),(cor_s,cntl_s,vm_s,m_s,ovr_s,(s_cntl,s_pmem,s_vmem))))
      ==>
      let ((((cntl_n,pmem_n,vmem_n),cor_r_n),_), out_r: ('n word, 'n
      mitb_out) GameOutput ) =
         (MITB_GAME f) ((((cntl,pmem,vmem),cor_r),nd),input)
      in
        (
       let
        (((k_n,cor_f_n),(cor_s_n,cntl_s_n,vm_s_n,m_s_n,ovr_s_n,(s_cntl_n,s_pmem_n,s_vmem_n))),out_i: ('n word, 'n
      mitb_out) GameOutput
        ) =
           (ALMOST_IDEAL_GAME f (Hash f ZERO) )
                      (((k,cor_f),(cor_s,cntl_s,vm_s,m_s,ovr_s,(s_cntl,s_pmem,s_vmem))),input)
        in
        (STATE_INVARIANT_COR ((cntl_n,pmem_n,vmem_n), cor_r_n)
        ((k_n,cor_f_n),(cor_s_n,cntl_s_n,vm_s_n,m_s_n,ovr_s_n,(s_cntl_n,s_pmem_n,s_vmem_n))))
        )
            ``, 
    (* To show: cor_f_n = cor_s_n /\ cor_r_n = cor_f_n *)
    RW_TAC std_ss [STATE_INVARIANT_COR_def]
    \\ `(cor_s = cor_r) /\ (cor_f = cor_r)` by fs [STATE_INVARIANT_def, STATE_INVARIANT_COR_def]
    \\ `~ovr_s ==> (cntl_s = cntl)` by  
              (fs [STATE_INVARIANT_def, STATE_INVARIANT_CNTL_def] >>  Cases_on `cor_f` >> fs[]) 
    \\ `(cor_r ∧ ovr_s) ==> (s_cntl = cntl)` by 
              (fs [STATE_INVARIANT_def, STATE_INVARIANT_CNTL_def] >> Cases_on `cor_f`  >> fs[]) 
    \\ rw[]
    \\ EVERY  (* Proof cor_r_n = cor_f_n *)
    [
      Cases_on `input` 
      >- (* Env_toP a *)
      (
        Cases_on `?m. a = (Mac m)`
        >- (
          rw[]
 	  \\ first_assum(assume_tac o MATCH_MP mac_message_lemma)
	  \\ FIRST [Cases_on `a`  (* a = SetKey c \/ Corrupt *) , all_tac]
          \\ Cases_on `cor_f`
          \\ fs rws
          )
        \\ Cases_on `a` 
        \\ EVERY [map_every (fn a => Cases_on `^a`) [``cntl``, ``cntl_s``, ``cntl_s_n``, ``cor_f``]
                \\ fs rws
		\\ rw []
		\\ PAT_ASSUM ``(λ((a,a'),b).  p) p' = q`` (fn thm => assume_tac(thm |> PairedLambda.GEN_BETA_RULE))
		\\ rpt(BasicProvers.EVERY_CASE_TAC >>  fsrw_tac [ARITH_ss] rws)
	       ]
      )    
     \\ split_all_pairs_tac (* Env_toA b *)
     \\ MAP_EVERY (fn a => Cases_on `^a`) [``b0``, ``b1``, ``b2``, ``b3``, ``cor_f``]
     \\ fs rws
     \\ rw []
     \\ FIRST[map_every(fn a => Cases_on `^a`) [``cntl_s``, ``s_cntl``, ``ovr_s``]
            \\ fs rws
	    \\ schneiderUtils.UNDISCH_ALL_TAC
	    \\ PairedLambda.GEN_BETA_TAC
	    \\ rpt(BasicProvers.EVERY_CASE_TAC >>  fsrw_tac [ARITH_ss] rws),
	    fs rws] 
    ]
);

(*
Given that the complete invariant holds, the state part
of the invariant holds in the next step.
*)
val Invariant_cntl = store_thm("Invariant_cntl",
``! f
  (* The MITB's state in the real game *)
  (cntl:control) (pmem:('r+'c) word) (vmem:('r+'c) word)  (cor_r:bool)
  (* The functionality's state (cor_s is shared with Sim)*)
  k cor_f
  (* The dummy adversary's state, does not matter really *)
     nd
  (* The simulator's state *)
  cor_s cntl_s vm_s m_s ovr_s s_cntl s_pmem s_vmem
  (* The environment's query *)
  (input: 'r env_message) .
    (GoodParameters (dimindex(:'r),dimindex(:'c),dimindex(:'n)))
    /\
    (STATE_INVARIANT f ((cntl,pmem,vmem),cor_r)
    ((k,cor_f),(cor_s,cntl_s,vm_s,m_s,ovr_s,(s_cntl,s_pmem,s_vmem))))
  ==>
  let ((((cntl_n,pmem_n,vmem_n),cor_r_n),_), out_r: ('n word, 'n
  mitb_out) GameOutput ) =
      (MITB_GAME f) ((((cntl,pmem,vmem),cor_r),nd),input)
  in
    (
    let
     (((k_n,cor_f_n),(cor_s_n,cntl_s_n,vm_s_n,m_s_n,ovr_s_n,(s_cntl_n,s_pmem_n,s_vmem_n))),out_i: ('n word, 'n
   mitb_out) GameOutput
     ) =
        (ALMOST_IDEAL_GAME f (Hash f ZERO) )
                      (((k,cor_f),(cor_s,cntl_s,vm_s,m_s,ovr_s,(s_cntl,s_pmem,s_vmem))),input)

    in 
    (STATE_INVARIANT_CNTL ((cntl_n,pmem_n,vmem_n), cor_r_n)
    ((k_n,cor_f_n),(cor_s_n,cntl_s_n,vm_s_n,m_s_n,ovr_s_n,(s_cntl_n,s_pmem_n,s_vmem_n))))
    )
``,
    rw[] >>
    `(cor_s = cor_r) ∧ (cor_f = cor_r)` by
      fs[STATE_INVARIANT_def, STATE_INVARIANT_COR_def] >>
    `∃a b. (input = Env_toA a) ∨ (input = Env_toP b)` by (
      Cases_on`input` >> rw[]) >> rw[]
    >- (
      split_all_pairs_tac >>
      split_all_control_tac >>
      Cases_on `cor_f` >>
      fs [STATE_INVARIANT_def, STATE_INVARIANT_CNTL_def] >>
      split_all_bools_tac >>
      fsrw_tac [ARITH_ss] rws >> rw[] >>
      BasicProvers.EVERY_CASE_TAC >>

       (PairedLambda.GEN_BETA_TAC
       \\ fsrw_tac [ARITH_ss] rws 
       \\ rw[]
       \\ fsrw_tac[ARITH_ss][]
       \\ fs [GoodParameters_def]
       \\ `~(dimindex (:'r) <= 1 + (dimindex (:'r)-2))` by (simp [])
       \\ fsrw_tac [ARITH_ss] rws)
      )
    
    >> (*Input to protocol *)
    ( fs rws
      \\ PairedLambda.GEN_BETA_TAC
      \\ map_every (fn a => Cases_on `^a`) [``cntl``, ``cntl_s``, ``cor_f``, ``ovr_s``]
      \\ EVERY[
      ( (* cor_f T  (proto ignores messages) *)
        split_all_pairs_tac >>
        split_all_control_tac >>
        Cases_on `b` >>
        fs (rws@[MITB_PROJ_OUTPUT_def]) >>
        RULE_ASSUM_TAC EVAL_RULE
      )]

      \\ PairedLambda.GEN_BETA_TAC
      \\ fs rws
      \\ BasicProvers.EVERY_CASE_TAC
      \\ assume_tac
           (mac_message_in_absorbing |> Q.ISPECL[`dimindex (:ς):num`, `(l :bool list)`, `(pmem :(ς + γ) word)`, `(pmem :(ς + γ) word)`])
      \\ rfs ([PROCESS_MESSAGE_LIST_neq_NIL, GoodParameters_def]@rws)
    )

);

(* The following lemmas are all used in the proof to
Invariant_mem *)

val TAKE_Zeros = prove(
``! b a . TAKE a (Zeros (b)) = Zeros (MIN a b)``,
Induct 
>- (EVAL_TAC >> rw[TAKE_def]) 
>> rw [Zeros_def, MIN_DEF]
>> RW_TAC std_ss [TAKE_def, Zeros_def]
>> rw [MIN_DEF]
>> rw [GSYM Zeros_def, ADD1]);


val l2n_MAP_Zeros = prove (
``!b . l2n 2 (MAP (\e. if e then 1 else 0) (Zeros b)) = 0``,
Induct >>
rw [Zeros_def,numposrepTheory.l2n_def]);

val LENGTH_n2n_w2n = prove (
``
!a w .
(dimindex(:'r)>1 )
/\
(a <= dimindex(:'r))
/\
(a > 0)
==>
LENGTH (n2l 2 (w2n ((a − 1 -- 0) w:'r word))) ≤ a ``,
rw [] >>
Q.ISPECL_THEN [`a-1`,`0`,`w`] assume_tac WORD_BITS_LT >>
Cases_on `(w2n ((a-1 -- 0) w)) = 0`
>- (
`((a-1 -- 0) w) = 0w` by fs [w2n_eq_0] >>
simp [] )
>>
`SUC (a-1) - 0 = a` by simp [ADD1] >>
qspecl_then [`2`,`w2n ((a-1 -- 0) w)`,`(2 **
a)-1`] assume_tac logrootTheory.LOG_LE_MONO >>
`0 < w2n ((a-1 -- 0 ) w)` by simp [] >>
fs [] >>
`w2n ((a-1 -- 0) w) <= (2 ** a)-1` by simp [] >>
res_tac >>
`LOG 2 (2**a -1) = a-1` by simp [LOG_2_POW_2_SHORT_1] >>
fs [] >>
pop_assum (fn t => all_tac) >>
`LENGTH (n2l 2 (w2n ((a-1 -- 0) w))) <= (a)`
  by simp [numposrepTheory.LENGTH_n2l,ADD1]
);

val MIN_DEF_ALT = prove (
``∀m n. MIN m n = if m <= n then m else n``,
simp [MIN_DEF]);

val BITS_TO_WORD_TAKE_WORD_TO_BITS = prove (
``
!w a.
(dimindex(:'r)>1 )
/\
(a <= dimindex(:'r))
/\
(a > 0)
==>
((BITS_TO_WORD (TAKE a (WORD_TO_BITS (((a - 1) -- 0) w: 'r word))))
= ((a - 1) -- 0) w)``,

    rw [BITS_TO_WORD_def,WORD_TO_BITS_def]
   \\ simp [word_to_bin_list_def, w2l_def] 
   \\ qspecl_then [`a`,`w`] assume_tac  LENGTH_n2n_w2n
   \\ rfs []
   \\ rw [TAKE_APPEND2]
   \\ qspecl_then [`2`,`w2n ((a-1 -- 0) w)`] assume_tac n2l_st
   \\ fs []
   \\ rw [MAP_MAP_o, MAP_num_to_bool_conversion]
   \\ rw [TAKE_Zeros]
   \\ `(a - LENGTH (n2l 2 (w2n ((a − 1 -- 0) w)))) <= (dimindex (:ς) − LENGTH (n2l 2 (w2n ((a − 1 -- 0) w))))`
       by simp []
   \\ rw [MIN_DEF_ALT, word_from_bin_list_def, l2w_def,l2n_APPEND ]
   \\ rw [l2n_Zeros_helper]
   \\ rw [GSYM w2l_def, GSYM l2w_def, l2w_w2l]
);

val SplittoWords_WORD_TO_BITS = prove(
``
dimindex(:'r)>1 ==>
(SplittoWords (WORD_TO_BITS (w:'r word)) = [w] )``,
rw [] >>
`LENGTH (WORD_TO_BITS w) = dimindex(:'r)` by simp [LENGTH_WORD_TO_BITS] >>
`dimindex(:'r) <>0` by simp [] >>
rw [SplittoWords_def, (Once Split_def), BITS_TO_WORD_WORD_TO_BITS]
);

val SplittoWords2_WORD_TO_BITS = prove(
``
dimindex(:'r)>1 ==>
(SplittoWords2 (WORD_TO_BITS (w:'r word)) = [w] )``,
rw [] >>
`(WORD_TO_BITS w) <> []`
              by (fs [GoodParameters_def] >> simp
                  [WORD_TO_BITS_NEQ_NIL]) >>
rw [SplittoWords2_def, SplittoWords_WORD_TO_BITS]
);


val Split_LENGTH_APPEND = prove(
``LENGTH a > 0 /\
LENGTH b > 0
==> (Split (LENGTH a) (a++b) = a :: Split (LENGTH a) b)``,
simp [(Once Split_def)] >>
rw [DROP_LENGTH_APPEND,TAKE_LENGTH_APPEND]
);

val SplittoWords_APPEND = prove(
``! a b n.
(dimindex(:'r)>0)
/\
(LENGTH a >0 )
/\
(LENGTH a = n * dimindex(:'r))
/\
(LENGTH b > 0 )
==>
(SplittoWords ( a ++ b):'r word list
  = (SplittoWords a) ++ (SplittoWords b) )``,
rw [SplittoWords_def, SplittoWords_def] >>
`n<>0` by spose_not_then (fn t => assume_tac t >> fs [LENGTH_NIL]) >>
`n*dimindex(:'r) >= dimindex(:'r)` by simp [non_zero_mult] >>
`LENGTH a > 0 ` by simp [] >>
Q.ISPECL_THEN [`dimindex(:'r)`,`a`,`b`,`n`] assume_tac Split_APPEND >>
fs []
);

val SplittoWords2_APPEND = prove(
``! a b n.
(dimindex(:'r)>0)
/\
(LENGTH a = n * dimindex(:'r))
/\
(LENGTH b > 0 )
==>
(SplittoWords2 ( a ++ b):'r word list
  = (SplittoWords2 a) ++ (SplittoWords2 b) )``,
rw [SplittoWords2_def, SplittoWords_def] >>
fs [] >>
`n<>0` by spose_not_then (fn t => assume_tac t >> fs [LENGTH_NIL]) >>
`n*dimindex(:'r) >= dimindex(:'r)` by simp [non_zero_mult] >>
`LENGTH a > 0 ` by simp [] >>
Q.ISPECL_THEN [`dimindex(:'r)`,`a`,`b`,`n`] assume_tac Split_APPEND >>
fs []
);

val Absorb_APPEND = prove(
``! s a b . Absorb f s (a++b) = Absorb f (Absorb f s a) b``,
Induct_on `a` >> rw [Absorb_def]);

val Absorb_SplittoWords =prove(
``
! s k m more.
dimindex(:'r) > 1
/\
(? n. LENGTH m = n * dimindex(:'r))
/\
(LENGTH more > 0)
==>
((Absorb (f: ('r+'c) word -> ('r+'c) word )
   s ((SplittoWords: bits -> 'r word list)
     ((WORD_TO_BITS (k:'r word)) ++ m ++ more)))
= (Absorb f (Absorb f (f (s ?? 0w:'c word @@ k)) (SplittoWords2 m))
   (SplittoWords more )
  ))``,
  rw [] >>
  qmatch_abbrev_tac `lhs =rhs` >> qunabbrev_tac`lhs` >>
  `dimindex(:'r) > 0` by simp [] >>
  `LENGTH (WORD_TO_BITS k) > 0` by simp [LENGTH_WORD_TO_BITS] >>
  `LENGTH (m++more)>0` by simp [] >>
  `LENGTH (WORD_TO_BITS k) = 1* dimindex(:'r)` 
    by simp [LENGTH_WORD_TO_BITS] >>
  qspecl_then [`WORD_TO_BITS k`, `m ++ more`,`1`] 
          imp_res_tac SplittoWords_APPEND >>
  rw_tac pure_ss [GSYM APPEND_ASSOC, SplittoWords_WORD_TO_BITS] >>
  rw [Absorb_APPEND]  >>
  Cases_on `m=[]` 
  >- rw [Abbr`rhs`,SplittoWords2_def, Absorb_def]
  >>
     `LENGTH m <>0`
         by spose_not_then (fn t => assume_tac t >> fs [LENGTH_NIL]) >>
     `LENGTH m > 0` by simp [] >>
    qspecl_then [`m`, `more`,`n`] 
            assume_tac SplittoWords_APPEND >>
    rw [Absorb_APPEND] >>
    rw [Absorb_def,Abbr`rhs`, SplittoWords2_def]
);

  
local
fun AbsEnd_tac a b lbl mssg lem =
      rfs rws 
      \\ PairedLambda.GEN_BETA_TAC
      \\ rw rws
      \\ fs ([ZERO_def, STATE_INVARIANT_MEM_def, Output_def, SHA3_APPEND_def, GoodParameters_def]@rws_hash_sans_split@rws)
      >-   ( `dimindex(:'r) > 1` by ( fs [GoodParameters_def] >> simp [] )
           \\ rw [LENGTH_WORD_TO_BITS]
           \\ `0 < n *dimindex(:'r)` by simp [arithmeticTheory.LESS_MULT2]
           \\ fsrw_tac [ARITH_ss] rws
           \\ `dimindex(:'r) + (n * dimindex(:'r) +1) = ((n+1)*dimindex(:'r))+1` by fsrw_tac [ARITH_ss] rws

           \\ rw [ADD_ASSOC]
           \\ PURE_ONCE_REWRITE_TAC [MULT_COMM, ADD_COMM]
           \\ `0 < dimindex(:'r) ` by simp []
           (* Term in Zeros not completely reduced, but keeping this for
           later *)
           (* Prepare to use Absorb_SplittoWords *)
           \\ qpat_abbrev_tac `ZEROS = Zeros (X)` 
           \\ PURE_REWRITE_TAC [GSYM APPEND_ASSOC]
           \\ SUBGOAL_THEN  ``(n * dimindex (:ς) − ^a + 4)  = (n * dimindex (:ς) + ^b)`` (fn thm => assume_tac thm)
	   >-(
              SUBGOAL_THEN``!m a. (m > 0) /\ (a > 4) ==> (m*a > 4)`` (fn thm => assume_tac thm)
              >- (Induct_on `m` 
                  >- fs[]
                  \\ rw[MULT_SUC])
              \\ fs[GoodParameters_def]
	      \\ qpat_assum `!a b. P`   (qspecl_then [`n`, `dimindex (:ς)`] ASSUME_TAC)
	      \\ fs[]
	   )
          \\ fs[]
	  \\ `(dimindex (:ς) − ^b MOD dimindex (:ς)) = (dimindex (:ς) − ^b)` by fs[GoodParameters_def]
	  \\ ntac 2 (abr_tac_goal listSyntax.is_append "ls" NONE)
	  \\ `ls' = (WORD_TO_BITS k ⧺ (^mssg) ⧺ (^lbl))` by fs[]
          \\ qabbrev_tac `LASTBLOCK = ^lbl`
	  \\ qabbrev_tac`msg =  ^mssg` 
	  \\ fs[]
	  \\ SUBGOAL_THEN  ``LENGTH (msg:bool list) = n * dimindex (:ς)`` (fn thm => assume_tac thm)
            >-(SUBGOAL_THEN``!m a. (m > 0) /\ (a > 4) ==> (m*a > 4)`` (fn thm => assume_tac thm)
               >- (Induct_on `m` 
                   >- fs[]
                  \\ rw[MULT_SUC])
              \\ fs[Abbr`msg`, GoodParameters_def]
	      \\ qpat_assum `!a b. P`   (qspecl_then [`n`, `dimindex (:ς)`] ASSUME_TAC)
	      \\ fs[]
	      )
         \\ `LENGTH LASTBLOCK > 0` by simp [Abbr`LASTBLOCK`]
	 \\ ASSUME_TAC (Absorb_SplittoWords |> Q.ISPECL[`(0w :(ς + γ) word)`, `(k :ς word)`, `msg:bool list`, `LASTBLOCK:bool list`])
	 \\ assume_tac lem
	 \\ rfs[]
	 \\`ls <> []` by fs[Abbr`ls`]
         \\ rw [SplittoWords2_def]
	 \\ qpat_abbrev_tac `PREV=Absorb f X (SplittoWords ls)`
	 \\ SUBGOAL_THEN ``LENGTH (LASTBLOCK:bool list) =  (dimindex (:ς))`` (fn thm => assume_tac thm)
	 >-(fs[Abbr`LASTBLOCK`, Abbr`ZEROS`])
	 \\ fs[DROP_LENGTH_NIL_rwt, TAKE_LENGTH_ID_rwt, Abbr`LASTBLOCK`, Abbr`ZEROS`, SplittoWords_def]
	 \\ rw ([(Once Split_def)]@rws_hash)
	 \\ simp [int_min_lemma, Absorb_def]
	 )
    \\ fs rws >> qexists_tac `n` >> decide_tac

fun  AbsEndSub_tac a b l  t =
    simp rws
    \\ PairedLambda.GEN_BETA_TAC
    \\ fs[STATE_INVARIANT_MEM_def, ZERO_def,Output_def]
    \\ rw[]
    >-( qexists_tac `n+1`  >>  simp [LENGTH_WORD_TO_BITS, LENGTH_TAKE] )
    \\ rw_tac arith_ss  [GSYM APPEND_ASSOC]
    \\ qpat_abbrev_tac `BSA = (TAKE (dimindex (:ς) − ^a) (WORD_TO_BITS X) ++ ^l)` 
    \\ `LENGTH (BSA) = dimindex(:'r)` by simp[Abbr`BSA`,LENGTH_TAKE,LENGTH_WORD_TO_BITS] 
    \\ `dimindex(:'r) > 0` by simp []
    \\ Cases_on `m_s= []`
    >- (fs [SplittoWords2_def, SplittoWords_def, Abbr`BSA`] 
        \\ simp [(Once Split_def), Absorb_def]
	\\ qabbrev_tac `m = TAKE (dimindex (:ς) − ^a)(WORD_TO_BITS ((dimindex (:ς) − ^b -- 0) a2))`
	\\ `LENGTH m = dimindex (:ς) − ^a` by fs[]
	\\ fs [t, Abbr `m`]
	\\ assume_tac(BITS_TO_WORD_TAKE_WORD_TO_BITS |> Q.ISPECL[`a2:ς word`, `(dimindex (:ς) − ^a)`])
	\\ rfs[WORD_BITS_COMP_THM]
       )
   \\`LENGTH m_s <> 0` by simp [LENGTH_NIL]
   \\ `LENGTH m_s > 0` by simp []
   \\ qspecl_then [`m_s`,`BSA`, `n`] assume_tac  SplittoWords_APPEND
   \\ simp [SplittoWords2_def, Absorb_APPEND]
   \\ qpat_abbrev_tac `PR=(SplittoWords m_s):'r word list`
   \\ simp [SplittoWords_def,(Once Split_def), Absorb_def]
   \\ qunabbrev_tac `BSA`
   \\ qpat_abbrev_tac `BLA = (TAKE (dimindex(:'r)- ^a) (WORD_TO_BITS ((dimindex(:'r) - ^b -- 0 ) a2)))`
   \\ `LENGTH BLA = dimindex(:'r) - ^a` by simp[Abbr`BLA`, LENGTH_TAKE,LENGTH_WORD_TO_BITS]
   \\ rw [t]
   \\ assume_tac(BITS_TO_WORD_TAKE_WORD_TO_BITS |> Q.ISPECL[`a2:ς word`, `(dimindex (:ς) − ^a)`])
   \\ rfs[WORD_BITS_COMP_THM]

in

(*
Given that the complete invariant holds, the state part
of the invariant holds in the next step.
*)
val Invariant_mem = store_thm("Invariant_mem",
``! f
  (* The MITB's state in the real game *)
  (cntl:control) (pmem:('r+'c) word) (vmem:('r+'c) word)  (cor_r:bool)
  (* The functionality's state (cor_s is shared with Sim)*)
  k cor_f
   (* The dummy adversary's state, does not matter really *)
   nd
  (* The simulator's state *)
  cor_s cntl_s vm_s m_s ovr_s s_cntl s_pmem s_vmem
  (* The environment's query *)
  (input: 'r env_message) .
    (GoodParameters (dimindex(:'r),dimindex(:'c),dimindex(:'n)))
    /\
    (STATE_INVARIANT f ((cntl,pmem,vmem),cor_r)
    ((k,cor_f),(cor_s,cntl_s,vm_s,m_s, ovr_s,(s_cntl,s_pmem,s_vmem))))
  ==>
  let ((((cntl_n,pmem_n,vmem_n),cor_r_n),_), out_r: ('n word, 'n
  mitb_out) GameOutput ) =
      (MITB_GAME f) ((((cntl,pmem,vmem),cor_r),nd),input)
  in 
    (
    let
     (((k_n,cor_f_n),(cor_s_n,cntl_s_n,vm_s_n,m_s_n,ovr_s_n,(s_cntl_n,s_pmem_n,s_vmem_n))),out_i: ('n word, 'n
   mitb_out) GameOutput
     ) =
        (ALMOST_IDEAL_GAME f (Hash f ZERO) )
                      (((k,cor_f),(cor_s,cntl_s,vm_s,m_s,ovr_s,(s_cntl,s_pmem,s_vmem))),input)

    in 
    (STATE_INVARIANT_MEM f ((cntl_n,pmem_n,vmem_n), cor_r_n)
    ((k_n,cor_f_n),(cor_s_n,cntl_s_n,vm_s_n,m_s_n,ovr_s_n,(s_cntl_n,s_pmem_n,s_vmem_n))))
    )
`` ,  

    rw[] 
    \\ (PairedLambda.GEN_BETA_TAC 
    \\ fs[MITB_GAME_def, ALMOST_IDEAL_GAME_def])
    \\ `(cor_s = cor_r) ∧ (cor_f = cor_r)` by fs[STATE_INVARIANT_def, STATE_INVARIANT_COR_def]
    \\ `∃a b. (input = Env_toA a) ∨ (input = Env_toP b)` by (Cases_on`input` >> rw[]) 

    >- ( (* Input to adversary *)
      fs ([STATE_INVARIANT_def, STATE_INVARIANT_CNTL_def, STATE_INVARIANT_COR_def]@rws)
      \\ PairedLambda.GEN_BETA_TAC >> fs[STATE_INVARIANT_MEM_def]
      \\ split_all_pairs_tac
      \\ rfs [STATE_INVARIANT_MEM_def]
        (* must be corrupted *)
      \\ Cases_on `~cor_f`
      >- (
       (split_all_control_tac >> fs[])
       \\ split_all_bools_tac 
       \\ rfs (rws@[STATE_INVARIANT_MEM_def, ZERO_def])
       ) 
        (* skip bit *)
      \\ Cases_on `a0` 
      >-
       (
       (split_all_control_tac >> fs [])
       \\ split_all_bools_tac
       \\ simp rws
       \\ PairedLambda.GEN_BETA_TAC
       \\ fs (rws@[STATE_INVARIANT_MEM_def, ZERO_def])
       \\ qexists_tac `n`
       \\ decide_tac
       )
         (* mov bit *)
      \\ Cases_on `a1`
      >-(
       Cases_on`ovr_s`
       \\ split_all_control_tac
       \\ fs rws
       \\ PairedLambda.GEN_BETA_TAC
       \\ rule_assum_tac (SIMP_RULE arith_ss rws)
       \\ fs (rws@[STATE_INVARIANT_MEM_def])
       \\ rw ([Once Split_def] @ rws_hash)
       \\ exists_tac ``0`` 
       \\ simp []
       )

       (* What remains to be shown: Input works nicely *)
      \\ Cases_on `ovr_s`
      >-(map_every Cases_on [`s_cntl`, `cntl_s`]
	\\ ( (* Ready *)
          fs rws
          \\ PairedLambda.GEN_BETA_TAC
	  \\ rw (rws)
	  \\ (BasicProvers.EVERY_CASE_TAC >>  fsrw_tac [ARITH_ss] rws)
	  \\ (fs (rws@[STATE_INVARIANT_MEM_def, Output_def, GoodParameters_def])
	  )
	)
      )

     \\ (Cases_on `cntl_s`
     \\ fs (rws@[STATE_INVARIANT_MEM_def, ZERO_def])
     \\ PairedLambda.GEN_BETA_TAC)
     >- ( (* Ready *)
          fs rws
          \\ PairedLambda.GEN_BETA_TAC
	  \\ rw (rws)
	  \\ (BasicProvers.EVERY_CASE_TAC >>  fsrw_tac [ARITH_ss] rws)
	  \\ (fs (rws@[STATE_INVARIANT_MEM_def, Output_def, GoodParameters_def])
	  )
     )

     >- ( (* Absorbing *)
          `(a3 > dimindex(:'r))  \/  (a3 = dimindex(:'r)) \/ (a3 = dimindex(:'r) -1 ) \/ (a3< dimindex(:'r) -1 )` 
            by simp []
          (* (a3 > dimindex(:'r)) *)
          >- (rfs (rws@ [STATE_INVARIANT_MEM_def,ZERO_def])  >> fs rws >> qexists_tac `n` >> decide_tac)
          >- (* (a3 = dimindex(:'r)) *)
           (
            rfs (rws@ [STATE_INVARIANT_MEM_def,ZERO_def, GoodParameters_def]) 
            \\ qspecl_then [`dimindex(:'r)`,`2`] assume_tac SUB_LESS 
            \\ `2 <= dimindex(:'r)` 
               by fs [LESS_IMP_LESS_OR_EQ] 
            \\ rw []
            \\ `dimindex(:'r)>1`
                by (fs [GoodParameters_def] >> decide_tac)
            >- ( qexists_tac `n+1`  >> simp [LENGTH_WORD_TO_BITS, LENGTH_TAKE] )
            \\  qspecl_then [`m_s`,`WORD_TO_BITS a2`, `n`] assume_tac  SplittoWords2_APPEND
            \\ `dimindex(:'r)>0` by simp [] 
            \\ `LENGTH (WORD_TO_BITS a2) >0` 
                  by (fs [] >>  simp[LENGTH_WORD_TO_BITS]) 
            \\ `dimindex(:'r)>1` by simp []
	    \\ simp [Absorb_APPEND,SplittoWords2_WORD_TO_BITS,Absorb_def] 
           )
           >- (*  a3 = dimindex(:'r)-1  *)
           (rfs ([GoodParameters_def, STATE_INVARIANT_MEM_def]@rws) 
            \\ PairedLambda.GEN_BETA_TAC
            \\ rw []
            >- (qexists_tac `n+1` >> simp [LENGTH_WORD_TO_BITS, LENGTH_TAKE])
            \\ rw_tac arith_ss  [GSYM APPEND_ASSOC]
            \\ Cases_on `m_s= []`
            >- (rw  [SplittoWords2_def, SplittoWords_def]
               \\ simp [(Once Split_def)]
               \\ qpat_abbrev_tac `BLA = (TAKE (dimindex(:'r)-1) (WORD_TO_BITS ((dimindex(:'r) -2 -- 0 ) a2)))`
               \\ `LENGTH BLA = dimindex(:'r)-1` by simp[Abbr`BLA`, LENGTH_TAKE,LENGTH_WORD_TO_BITS]
               \\ rw [one_short_lemma]
               \\ qunabbrev_tac `BLA`
               \\ qspecl_then [`a2`,`dimindex(:'r)-1`] assume_tac BITS_TO_WORD_TAKE_WORD_TO_BITS
               \\ fs [WORD_BITS_COMP_THM]
	       >- rw  [Absorb_def , SHA3_APPEND_ZERO_WORD_def]
	       \\ rfs[l2w_def, l2n_APPEND, GSYM word_add_n2w]
               )
           \\ Q.PAT_ABBREV_TAC `BSA = (g (dimindex (:ς) − 1) (a))`
           \\ `LENGTH m_s <> 0` by simp [LENGTH_NIL]
	   \\ qspecl_then [`m_s`,`BSA ++ [F]`, `n`] assume_tac  SplittoWords_APPEND
           \\ simp [SplittoWords2_def, Absorb_APPEND]
           \\ qpat_abbrev_tac `PR=(SplittoWords m_s):'r word list`
           \\ simp [SplittoWords_def,(Once Split_def), Absorb_def]
	   \\ qunabbrev_tac `BSA`
           \\ qpat_abbrev_tac `BLA = (TAKE (dimindex(:'r)-1) (WORD_TO_BITS ((dimindex(:'r) -2 -- 0 ) a2)))`
	   \\ `LENGTH BLA = dimindex(:'r)-1` by simp[Abbr`BLA`, LENGTH_TAKE,LENGTH_WORD_TO_BITS]
           \\ rw [one_short_lemma]
           \\ qunabbrev_tac `BLA`
	   \\ qspecl_then [`a2`,`dimindex(:'r)-1`] assume_tac  BITS_TO_WORD_TAKE_WORD_TO_BITS
           \\ fs [WORD_BITS_COMP_THM, Absorb_def]
           )
	   (*  a3 < dimindex(:'r)-1  *)
	   \\ Cases_on `a3 = 0`
	   \\ rw (rws@rws_hash_sans_split)
	   \\ fs ([GoodParameters_def]@rws)
           >-(simp [LENGTH_WORD_TO_BITS] 
 	      \\ qspecl_then [`n`,`dimindex(:'r)`] (fn t=>rw[t]) MULT_COMM
	      \\ rw_tac pure_ss [GSYM APPEND_ASSOC, SHA3_APPEND_def, SplittoWords_WORD_TO_BITS,
				  ADD_ASSOC, GSYM MULT_SUC, MULT_COMM, n_a_mult_b_mod_a_lemma]
	      \\ `LENGTH (WORD_TO_BITS k) = 1* dimindex(:'r)`  by simp [LENGTH_WORD_TO_BITS]
	      \\ fs[STATE_INVARIANT_MEM_def, Output_def, ZERO_def]
	      \\ (fn (asl ,g) => let val trm = find_term listSyntax.is_append g
    		    in (`^trm = (WORD_TO_BITS k ⧺ m_s ⧺ ([F] ⧺ [T] ⧺ [T] ⧺  Zeros (dimindex (:ς) − 4) ⧺ [T]))` by fs[])(asl ,g)
		   end
		  )
	      \\ qabbrev_tac `more = [F] ⧺ [T] ⧺ [T] ⧺ Zeros (dimindex (:ς) − 4) ⧺ [T]`
	      \\ rw[]
	      \\ ASSUME_TAC (Absorb_SplittoWords |> Q.ISPECL[`(0w :(ς + γ) word)`, `(k :ς word)`, `m_s: bool list`, `more: bool list`])
	      \\ rfs[]
	      \\ SUBGOAL_THEN ``LENGTH (more: bool list) > 0``  (fn thm => assume_tac thm) 
	      >- (SYM_ASSUMPTION_TAC ``b = more`` >> fs[])
	      \\ assume_tac(full_padding_append_lemma)
	      \\ rw[Absorb_def, SplittoWords_def, Once Split_def]
             )
   	       (* a3 <> 0 *)
           >-(qpat_abbrev_tac `a=(a3 -1 -- 0) a2`
              \\ `LENGTH (WORD_TO_BITS a)=dimindex(:'r)` by rw[LENGTH_WORD_TO_BITS]
	      \\ qspecl_then [`n`,`dimindex(:'r)`] (fn t=>rw[t]) MULT_COMM
	      \\ rw [GSYM MULT_SUC, GSYM ADD_ASSOC, MULT_COMM, n_a_mult_b_mod_a_lemma, LENGTH_WORD_TO_BITS]
              \\ qpat_abbrev_tac `foo = a3+2`
              \\ Cases_on `a3=dimindex(:'r)-2`
              \\ simp (rws@[STATE_INVARIANT_MEM_def, Absorb_def,Output_def,ZERO_def,SHA3_APPEND_def])
	      \\ PairedLambda.GEN_BETA_TAC
	      \\ fs[STATE_INVARIANT_MEM_def, ZERO_def,Output_def]
   	      \\ `LENGTH (WORD_TO_BITS k) = 1* dimindex(:'r)`  by simp [LENGTH_WORD_TO_BITS]
	      \\ fs[Abbr `foo`]
	      \\ qabbrev_tac `zer = Zeros ((dimindex (:ς) − (a3 + (4 :num)) MOD dimindex (:ς)) MOD dimindex (:ς))`
	      \\ qabbrev_tac `tk = TAKE (a3:num) (WORD_TO_BITS a)`
	      \\ (fn (asl ,g) => let val trm = find_term listSyntax.is_append g
    	   	   in (`^trm = (WORD_TO_BITS k ⧺ m_s ⧺ (tk ⧺ [F] ⧺ [T] ⧺ [T] ⧺ zer ⧺ [T]))` by fs[])(asl ,g)
		  end
		 )
	      \\ qabbrev_tac `more =  tk ⧺ [F] ⧺ [T] ⧺ [T] ⧺ zer ⧺ [T]`
	      \\ rw[]
	      \\ ASSUME_TAC (Absorb_SplittoWords |> Q.ISPECL[`(0w :(ς + γ) word)`, `(k :ς word)`, `m_s: bool list`, `more: bool list`])
	      \\ rfs[]
	      \\ SUBGOAL_THEN ``LENGTH (more: bool list) > 0``  (fn thm => assume_tac thm) >- (SYM_ASSUMPTION_TAC ``b = more`` >> fs[])
	      \\ rfs[]
	      \\ qabbrev_tac `absrb = (Absorb f (f (((0w :γ word) @@ k) :(ς + γ) word)) (SplittoWords2 m_s :ς word list))`
	      \\ SUBGOAL_THEN ``LENGTH (tk: bool list) = (a3:num)``  (fn thm => assume_tac thm)  >- (fs[Abbr`tk`, Abbr `a`])
	      \\ SUBGOAL_THEN ``(tk:bool list) ≠ []`` (fn thm => assume_tac thm) 
	      >- (fs[Abbr`tk`, Abbr `a`]
	          \\ strip_tac
		  \\ fs[TAKE_0] 
		 )
   	     \\ assume_tac(padding_lemma |> Q.ISPECL[`tk:bool list`])
	     \\ simp[SplittoWords_def, Absorb_def, Once Split_def]
	     \\ rfs[]
	     \\ CASE_TAC
	     >-(Cases_on `(a3 + 4) MOD dimindex (:ς) = 0`
	        >- (fs[Zeros_def, Abbr`zer`]
                 \\ SUBGOAL_THEN ``dimindex (:ς) = (LENGTH (tk:bool list) + 4)`` (fn thm => assume_tac thm) 
                    >- (SYM_ASSUMPTION_TAC`` LENGTH tk = a3``
                       \\ CCONTR_TAC
		       \\ `a3 < dimindex (:ς) − 4` by rfs[]
		       \\ fs[]
		       )
		 \\ assume_tac(BITS_TO_WORD_TAKE_WORD_TO_BITS |> Q.ISPECL[`a2:ς word`, `LENGTH (tk:bool list)`])
		 \\ rfs[]
		 \\ `(tk ≠ []) ==> (LENGTH (tk:bool list) > 0)` by fs[NOT_NIL_EQ_LENGTH_NOT_0]
		 \\ fs[Zeros_def, Abbr`a`, WORD_BITS_COMP_THM, Absorb_def]
		 \\ rw[]
		 \\ (fn (asl ,g) => let val trm = find_term listSyntax.is_append g
      		      in (`^trm = (tk ⧺ [F; T; T] ⧺ [T])` by fs[])(asl ,g) end)
		 \\ rw[] )
            \\ fs[Zeros_def, Abbr`zer`]
	    \\ SUBGOAL_THEN ``dimindex (:ς) <> (LENGTH (tk:bool list) + 4)``  (fn thm => assume_tac thm) 
	    >-( CCONTR_TAC >> (rfs[] >> fs[]) )
	    \\ SUBGOAL_THEN ``((a3 :num) + (4 :num)) MOD dimindex (:ς) = ((a3 :num) + (4 :num))`` (fn thm => assume_tac thm) 
	    >- ( rw[] )
	    \\ assume_tac(BITS_TO_WORD_TAKE_WORD_TO_BITS |> Q.ISPECL[`a2:ς word`, `LENGTH (tk:bool list)`])
	    \\ `(tk ≠ []) ==> (LENGTH (tk:bool list) > 0)` by fs[NOT_NIL_EQ_LENGTH_NOT_0]
	    \\ rfs[]
	    \\ fs[Zeros_def, Abbr`a`, WORD_BITS_COMP_THM]
	    \\ rw[Absorb_def,APPEND]
	    \\ (fn (asl ,g) => let val trm = find_term listSyntax.is_append g
    		in (`^trm = (tk ⧺ F::T::T::Zeros (dimindex (:ς) − (LENGTH tk + 4)) ⧺ [T])  ` by fs[])(asl ,g)
		end
	       )
	    \\ rw[])
	  \\ Cases_on `(a3 + 4) MOD dimindex (:ς) = 0`
	    >- (fs[Zeros_def, Abbr`zer`]
	        \\ SUBGOAL_THEN ``dimindex (:ς) = (LENGTH (tk:bool list) + 4)`` (fn thm => assume_tac thm) 
		    >- (SYM_ASSUMPTION_TAC`` LENGTH tk = a3``
		     \\ CCONTR_TAC
		     \\ `a3 < dimindex (:ς) − 4` by rfs[]
		     \\ fs[]
		       )
		\\ assume_tac(BITS_TO_WORD_TAKE_WORD_TO_BITS
				  |> Q.ISPECL[`a2:ς word`, `LENGTH (tk:bool list)`])
		\\ `(tk ≠ []) ==> (LENGTH (tk:bool list) > 0)` by fs[NOT_NIL_EQ_LENGTH_NOT_0]	
		\\ rw[Absorb_def]
		\\ fs[Abbr`a`, WORD_BITS_COMP_THM]
	       )
               \\ fs[ Abbr`zer`]
	       \\ SUBGOAL_THEN ``dimindex (:ς) <> (LENGTH (tk:bool list) + 4)``  (fn thm => assume_tac thm) 
                  >-( CCONTR_TAC \\ (rfs[] >> fs[]) )
               \\ SUBGOAL_THEN ``((a3 :num) + (4 :num)) MOD dimindex (:ς) = ((a3 :num) + (4 :num))`` (fn thm => assume_tac thm) 
	       >- ( rw[] )
               \\ rw[]
	       \\ assume_tac(BITS_TO_WORD_TAKE_WORD_TO_BITS |> Q.ISPECL[`a2:ς word`, `LENGTH (tk:bool list)`])
	       \\ fs[Abbr`a`, WORD_BITS_COMP_THM, Absorb_def]
	   )

       >- (AbsEndSub_tac ``3:num``  ``4:num`` ``[F; T; T]`` three_short_lemma) 
      \\  (AbsEndSub_tac ``2:num``  ``3:num``  ``[F; T]``   two_short_lemma)
     )
     >- AbsEnd_tac ``3:num`` ``1:num`` ``((ZEROS:bool list) ++ [T])`` ``((m_s:bool list) ⧺ [F] ⧺ [T] ⧺ [T])``   full_padding_lemma
     >- AbsEnd_tac ``2:num`` ``2:num`` ``([T] ++ (ZEROS:bool list) ++ [T])`` ``((m_s:bool list) ⧺ [F] ⧺ [T])``  full_padding_lemma
     \\ AbsEnd_tac ``1:num`` ``3:num`` ``([T] ++ [T] ++ (ZEROS:bool list) ++ [T])`` ``((m_s:bool list) ⧺ [F])`` one_padding_lemma
    )
    >> (* Case: input to protocol *)
      fs [STATE_INVARIANT_def, STATE_INVARIANT_CNTL_def, STATE_INVARIANT_COR_def] >>
      split_all_pairs_tac >>
      fs [STATE_INVARIANT_MEM_def] >>
      Cases_on `cor_f` (* must be uncorrupted *)
      >- (rfs[]>>
       split_all_control_tac >> fs [] >>
       split_all_bools_tac >> fs [] >>
       Cases_on `b` >>
       fs ([ZERO_def, STATE_INVARIANT_MEM_def, Output_def, GoodParameters_def]@rws) >>
       qexists_tac `n` >>
       decide_tac
       )
      >>
       Cases_on `b` 
       >- ( (* SetKey *)
         split_all_control_tac >>  fs [] >>
         split_all_bools_tac >> fs [] >>
         fs ([MITB_PROJ_OUTPUT_def, ZERO_def, STATE_INVARIANT_MEM_def, Output_def, GoodParameters_def]@rws)
         )
       >- (fs[]
         \\ first_assum(assume_tac o MATCH_MP ( Q.GEN `m` mac_message_lemma))
	 \\ qpat_assum `!a. P` (qspecl_then [`l`] ASSUME_TAC)
	 \\ PairedLambda.GEN_BETA_TAC
         \\ rfs (rws@ [STATE_INVARIANT_MEM_def])
          )
       >> ( (* Corrupt *)
         split_all_control_tac >>  fs [] >>
         split_all_bools_tac >> fs [] >>
         fs ([ZERO_def, STATE_INVARIANT_MEM_def, Output_def, GoodParameters_def]@rws) >>
         rw [Output_def] 
         )
)

end;

val  Initial_State_MITB_def =
  Define `
    (Initial_State_MITB f ((cntl,pmem,vmem),cor_r) ) ⇔
    (cntl = Ready) /\
    (pmem = (f(((ZERO:'c word) @@ (ZERO:'r word)): ('r+'c)
    word)):('r+'c) word ) /\
    (vmem = ZERO) /\
    (cor_r = F)
    `;

val  Initial_State_ALMOST_IDEAL_def =
  Define `
    (Initial_State_ALMOST_IDEAL  ((k,cor_f),(cor_s,cntl_s,vm_s,m_s, ovr_s)) ⇔
    (k = ZERO) /\
    (cor_f = F) /\
    (cor_s = F) /\
    (cntl_s = Ready) /\
    (vm_s = ZERO) /\
    (m_s = []) /\
    (ovr_s = F)
    )
    `;

val initial_state_fulfills_invariant = prove(``
! f (cntl:control) (pmem:('r+'c) word) (vmem:('r+'c) word)  (cor_r:bool)
  k cor_f cor_s cntl_s (vm_s: 'n word) m_s ovr_s s_cntl s_pmem s_vmem
  .
    (Initial_State_MITB f  ((cntl,pmem,vmem),cor_r) )
    /\
    (Initial_State_ALMOST_IDEAL  ((k,cor_f),(cor_s,cntl_s,vm_s,m_s,ovr_s)))
    ==>
    (STATE_INVARIANT f ((cntl,pmem,vmem),cor_r)
    ((k,cor_f),(cor_s,cntl_s,vm_s,m_s,ovr_s,(s_cntl,s_pmem,s_vmem))))
    ``,
simp [Initial_State_MITB_def, Initial_State_ALMOST_IDEAL_def, STATE_INVARIANT_def, STATE_INVARIANT_COR_def,
STATE_INVARIANT_CNTL_def,STATE_INVARIANT_MEM_def]);

(* Hash_WORD_TO_BITS_KEY fascilitates the proof of same_output.
 I couldn't figure out how to introduce an existential in an assumption,
 so I used this lemma instead.
 *)
val simple_lemma = prove( ``? n . (n=0) \/ (dimindex(:'r) =0)``,
 qexists_tac `0` >> simp [] ) ;

val Hash_WORD_TO_BITS_KEY = prove( ``
GoodParameters(dimindex(:'r),dimindex(:'c), dimindex(:'n))
==>
(
  ( (Hash f (s:('r+'c) word) (WORD_TO_BITS (k: 'r word) ++ l)):'n word)
  =
  (Hash f (f ( s ?? 0w:'c word @@ k)) (l))
 )
  ``,
  rw [Hash_def, GoodParameters_def, Output_def, Pad_def, PadZeros_def]
  \\ qpat_abbrev_tac `Z1= Zeros X`
  \\ qpat_abbrev_tac `Z2= Zeros X`
  \\ qspecl_then [`s`,`k`,`[]`,`l++ [T] ++ Z1 ++ [T]`] assume_tac Absorb_SplittoWords
  \\`dimindex(:'r) >1` by ( fs [GoodParameters_def] >> simp [] )
  \\ `LENGTH (l++ [T] ++ Z1 ++ [T])  > 0` by simp [] 
  \\ fs [simple_lemma]
  \\ rw [SplittoWords2_def, Absorb_def] 
  \\ fs [SHA3_APPEND_def, LENGTH_WORD_TO_BITS]
  \\ ntac 2 (abr_tac_goal listSyntax.is_append "ls" NONE)
  \\ `ls = ((WORD_TO_BITS (k :ς word)) ++ (ls':bool list))` by (fs[Abbr`ls`, Abbr`ls'`])
  \\ assume_tac(SplittoWords_APPEND|> Q.ISPECL[`(WORD_TO_BITS (k :ς word))`, `ls':bool list`, `1:num`])
  \\ `LENGTH ls' > 0` by fs[Abbr`ls'`]
  \\ `(LENGTH (WORD_TO_BITS k) = dimindex (:ς))` by fs[LENGTH_WORD_TO_BITS]
  \\ rfs[SplittoWords_WORD_TO_BITS]
  \\ rw[Absorb_def]
);

local 
open pairLib intSyntax
val snoc_to_list = prove(``! (x:'a) (l:'a list). ((SNOC x l) = (l++[x]))``, fs[])

val exec_list_full_not_nil = prove(
``! p a s l. (l <> []) ==> (EXEC p a s l <> [])``,
    rw[]
    \\ assume_tac((GSYM CONS) |> Q.ISPECL[`(l :(β, γ) EnvMessage list)`])
    \\ `(l ≠ []) ==> (~NULL l)` by fs[NULL, NULL_EQ]
    \\ `(l = HD l::TL l)` by rfs[]
    \\ fs[EXEC_def]
    \\ qabbrev_tac`i = HD l`
    \\ qabbrev_tac`l' = TL l`
    \\ fs[EXEC_def]
    \\ PairedLambda.GEN_BETA_TAC
    \\ fs[]
)

val exec_list_full_split_lemma = prove(
``!p a s e l. (l <> []) ==> 
   (EXEC p a s (SNOC e l) = (SNOC (EXEC_STEP p a ((FST(LAST (EXEC p a s l))), e)) (EXEC p a s l)))``,

    Induct_on `l`
    \\ fs[EXEC_def]
    \\ PairedLambda.GEN_BETA_TAC
    \\ qpat_assum `!a b c d. P`   (qspecl_then [`p`, `a`, `(FST (EXEC_STEP p a (s,h)))`, `e`] ASSUME_TAC)
    \\ Cases_on`l = []`
    >- (simp[EXEC_def, LAST, APPEND]
        \\ PairedLambda.GEN_BETA_TAC
	\\ rfs[]
       )
    \\ rw[EXEC_def, APPEND, LAST_DEF]
    \\ first_x_assum(mp_tac o MATCH_MP(exec_list_full_not_nil |> REWRITE_RULE[GSYM AND_IMP_INTRO]))
    \\ disch_then(fn th => first_x_assum (mp_tac o MATCH_MP th))
    \\ fs[]
)

val exec_list_full_eq_len_lemma = prove(
``!l p a s p' a' s'. 
  let ls = EXEC p a s l in
  let ls'=  EXEC p' a' s' l in
  LENGTH ls = LENGTH ls'``,
  
   Induct_on`l`
   \\ simp[EXEC_def]
   \\ PairedLambda.GEN_BETA_TAC
   \\ fs[])

val tac =
 fn arg =>
    Cases_on `^arg`
    \\ split_all_pairs_tac
    \\ split_all_control_tac
    \\ split_all_bools_tac
    \\ fs (rws@[Initial_State_MITB_def, Initial_State_ALMOST_IDEAL_def])
    \\ PairedLambda.GEN_BETA_TAC
    \\ rw (rws@rws_hash) 
    \\ BasicProvers.EVERY_CASE_TAC
    \\ fs(rws@[STATE_INVARIANT_MEM_def, Output_def, SplittoWords2_def, Absorb_def, MITB_PROJ_OUTPUT_def])

val same_out_one_step = prove(
``! f
  (* The MITB's state in the real game *)
  (cntl:control) (pmem:('r+'c) word) (vmem:('r+'c) word)  (cor_r:bool)
  (* The functionality's state (cor_s is shared with Sim)*)
  k cor_f
   (* The dummy adversary's state, does not matter really *)
   nd
  (* The simulator's state *)
  cor_s cntl_s vm_s m_s ovr_s s_cntl s_pmem s_vmem
  (* The environment's query *)
  (input: 'r env_message) .
    (GoodParameters (dimindex(:'r),dimindex(:'c),dimindex(:'n)))
    /\
    (STATE_INVARIANT f ((cntl,pmem,vmem),cor_r)
      ((k,cor_f),(cor_s,cntl_s,vm_s,m_s, ovr_s,(s_cntl,s_pmem,s_vmem))))
    ==>
    let ((((cntl_n,pmem_n,vmem_n),cor_r_n),_), out_r: ('n word, 'n mitb_out) GameOutput ) =
      (MITB_GAME f) ((((cntl,pmem,vmem),cor_r),nd),input)
    in
    (
    let (((k_n,cor_f_n),(cor_s_n,cntl_s_n,vm_s_n,m_s_n,ovr_s_n,(s_cntl_n,s_pmem_n,s_vmem_n))),out_i: ('n word, 'n mitb_out) GameOutput) =
      (ALMOST_IDEAL_GAME f (Hash f ZERO)) (((k,cor_f),(cor_s,cntl_s,vm_s,m_s,ovr_s,(s_cntl,s_pmem,s_vmem))),input)
    in
    (STATE_INVARIANT f ((cntl_n,pmem_n,vmem_n), cor_r_n)
    ((k_n,cor_f_n),(cor_s_n,cntl_s_n,vm_s_n,m_s_n,ovr_s_n,(s_cntl_n,s_pmem_n,s_vmem_n)))) ==>
    (out_r = out_i)
    )
``, 

    fs rws
    \\ PairedLambda.GEN_BETA_TAC
    \\ lrw[]
    \\ Cases_on `input`
    \\ fs[ENV_WRAPPER_def]
    \\ schneiderUtils.UNDISCH_ALL_TAC
    >- (Cases_on `ovr_s`
       \\ tac``a``
       \\ abbr_fn_tac "PROCESS_MESSAGE_LIST" "m" 
       \\ assume_tac (mac_message_in_absorbing 
                       |> Q.ISPECL[`dimindex (:ς)`,`l:bool list`, `(pmem :(ς + γ) word)`, `(pmem :(ς + γ) word)`] 
		       |> SIMP_RULE (srw_ss())[])
       \\ rfs[GoodParameters_def, LENGTH_WORD_TO_BITS]
       \\ fs ([ZERO_def, Output_def, Hash_def, SHA3_APPEND_def, Pad_def, PadZeros_def, LENGTH_WORD_TO_BITS]@rws_hash_sans_split@rws)
       \\ abbr_fn_tac "Zeros" "zer"
       \\ ntac 2 (abr_tac_goal listSyntax.is_append "ls" NONE)
       \\ `ls' = (WORD_TO_BITS k) ++ ls` by fs[Abbr`ls'`, Abbr `ls`]
       \\ full_simp_tac (srw_ss()) []
       \\ assume_tac(Split_APPEND |> Q.ISPECL[`(dimindex (:ς))`, `WORD_TO_BITS (k :ς word)`, `ls:bool list`, `1:num`])
       \\ `LENGTH ls > 0` by fs[Abbr`ls`]
       \\ rfs[LENGTH_WORD_TO_BITS]
       \\ res_tac
       \\ simp[Once Split_def]
       \\ CASE_TAC
       \\ rfs[LENGTH_WORD_TO_BITS, BITS_TO_WORD_WORD_TO_BITS, Absorb_def, SplittoWords_def, MITB_PROJ_OUTPUT_def]
       )
    \\ (Cases_on `ovr_s` >> tac ``b``)
)

val inv_tac =
    fn th =>
      split_all_pairs_tac
      \\ first_x_assum(mp_tac o MATCH_MP(th |> SIMP_RULE (srw_ss()) [LET_DEF, MITB_GAME_def, ALMOST_IDEAL_GAME_def] 
					      |> PairedLambda.GEN_BETA_RULE 
					      |> REWRITE_RULE[GSYM AND_IMP_INTRO]))
      \\ fs[]
in
val same_output_ind = store_thm("same_output_ind",
``! f
  (* The MITB's state in the real game *)
  (cntl:control) (pmem:('r+'c) word) (vmem:('r+'c) word)  (cor_r:bool)
  (* The functionality's state (cor_s is shared with Sim)*)
  k cor_f
  (* The dummy adversary's state, does not matter really *)
  nd
  (* The simulator's state *)
  cor_s cntl_s vm_s m_s ovr_s s_cntl s_pmem s_vmem
  (* The environment's query *)
  (input: ('r env_message) list) .
    (* Trace in the mitbgame *)
    let (mitb_trace = EXEC
      ((PROTO ( (MITB_STEP:('c,'n,'r) mitbstepfunction) f))
       : ('c,'r) proto_state -> ('n,'r) real_message
         -> (('c,'r) proto_state) # 'n real_proto_message)
      DUMMY_ADV
      (((cntl,pmem,vmem),cor_r),nd)
      input) in
    
    (* (* Trace in the almost ideal game *) *)
    let (alm_ideal_trace = EXEC (FMAC (Hash f ZERO)) 
                  (SIM (MITB_STEP:('c,'n,'r) mitbstepfunction) f)
                  ((k,cor_f),(cor_s,cntl_s,vm_s,m_s, ovr_s,(s_cntl,s_pmem,s_vmem)))
                  input) in
    (GoodParameters (dimindex(:'r),dimindex(:'c),dimindex(:'n)))
    /\
    (STATE_INVARIANT f  ((cntl,pmem,vmem),cor_r) ((k,cor_f),(cor_s,cntl_s,vm_s,m_s, ovr_s,(s_cntl,s_pmem,s_vmem))) )

    ==>
    (
    EVERY (\(((s1,_),o1),(s2,o2)). (STATE_INVARIANT f s1 s2) /\ (o1=o2) )
      (ZIP (mitb_trace,alm_ideal_trace))
    )
``,
    ntac 16 strip_tac 
    \\ listLib.SNOC_INDUCT_TAC 
    \\ rw[]
    (* Induct_on `input` *)
    >- rw [EXEC_def]
    \\ Cases_on `input = []`
    >-(rfs[EXEC_def]
      \\ PairedLambda.GEN_BETA_TAC
      \\ fs[listTheory.ZIP_def, ZIP_SNOC, listTheory.EVERY_DEF]
      \\ (fn (asl, g) => let val (a::b::l) = (tl o snd o strip_comb) g
           in (qabbrev_tac`exs = ^a` THEN qabbrev_tac`exs' = ^b`) (asl, g) end)
      \\ (fn (asl,g) => let val exs::exs'::[] = (tl o snd o strip_comb) g 
           in (SUBGOAL_THEN ``STATE_INVARIANT f (FST(FST ^exs)) (FST ^exs')`` (fn thm => assume_tac thm))(asl, g) end)
      \\ fs[Abbr `exs`, Abbr `exs'`]
      \\ rw[STATE_INVARIANT_def]
      \\ FIRST_PROVE [inv_tac Invariant_cor, inv_tac Invariant_cntl, inv_tac Invariant_mem,
          (PairedLambda.GEN_BETA_TAC
	   \\ first_x_assum(mp_tac o MATCH_MP((same_out_one_step 
						 |> SIMP_RULE (srw_ss()) [MITB_GAME_def, ALMOST_IDEAL_GAME_def, LET_DEF]
						 |>  PairedLambda.GEN_BETA_RULE)
				               |> REWRITE_RULE[GSYM AND_IMP_INTRO]))
           \\ rfs[STATE_INVARIANT_def])]
       )
    \\ (fn (asl,g) => let val (e,e') = (listSyntax.dest_zip o snd o dest_comb) g
			  val (l, _) = (front_last  o snd o strip_comb) e
			  val (l',_) = (front_last  o snd o strip_comb) e'
			  val arg    = append l l'
         in  
           (assume_tac ((exec_list_full_eq_len_lemma 
		       |> Q.ISPECL[`(input : (ς mac_query, bool # bool # ς word # num) EnvMessage list)`])
		       |> Drule.ISPECL arg
		       |> SIMP_RULE (srw_ss()) [LET_DEF])) (asl ,g) 
         end)
    \\ rw[exec_list_full_split_lemma, ZIP_SNOC,EVERY_SNOC ]
    \\ rfs[]
    \\ ntac 2 (abr_tac_goal is_fst "s" NONE)
    \\ (fn (asl,g) => let val s::s'::[] = map (hd o snd o strip_comb o last o snd o strip_comb)((tl o snd o strip_comb) g)
         in (SUBGOAL_THEN``STATE_INVARIANT f (FST ^s) ^s'`` (fn thm => assume_tac thm))(asl, g) end)
    >-(unabbrev_all_tac
       \\ `input = (SNOC (LAST input) (FRONT input))` by fs[APPEND_FRONT_LAST]
       \\ qabbrev_tac`l' = FRONT input`
       \\ qabbrev_tac`el = LAST input`
       \\ rw[]
       \\ Cases_on`l' = []`
       
       >-(fs[EXEC_def]
          \\ UNDISCH_MATCH_TAC ``EVERY f  x``
	  \\ rpt(PairedLambda.GEN_BETA_TAC >> simp[])
	 )
       \\ fs[exec_list_full_split_lemma, EXEC_def,  ZIP_SNOC,EVERY_SNOC ]
       \\ UNDISCH_MATCH_TAC ``(λ((s1,_),o1) (s2,o2). q ∧ p) a b``
       \\ rpt(PairedLambda.GEN_BETA_TAC >> simp[])
      )
    \\ (fn (asl, g) => let val (a::b::l) = (tl o snd o strip_comb) g
        in(qabbrev_tac`exs = ^a` THEN qabbrev_tac`exs' = ^b`) (asl, g) end)
    \\ (fn (asl,g) => let val exs::exs'::[] = (tl o snd o strip_comb) g 
           in (SUBGOAL_THEN ``STATE_INVARIANT f (FST(FST ^exs)) (FST ^exs')`` (fn thm => assume_tac thm))(asl, g) end)
    \\ fs[Abbr `exs`, Abbr `exs'`]
    \\ rw[STATE_INVARIANT_def]
    \\ FIRST_PROVE[inv_tac Invariant_cor, inv_tac Invariant_cntl, inv_tac Invariant_mem,
        (PairedLambda.GEN_BETA_TAC
         \\ split_all_pairs_tac
         \\ first_x_assum(mp_tac o MATCH_MP((same_out_one_step
					      |> SIMP_RULE (srw_ss()) [MITB_GAME_def, ALMOST_IDEAL_GAME_def, LET_DEF]
					      |>  PairedLambda.GEN_BETA_RULE)
	                   |> REWRITE_RULE[GSYM AND_IMP_INTRO]))
          \\ rfs[STATE_INVARIANT_def])]
    
)
end ;


val same_output = store_thm("same_output", 
``! f
  (* The MITB's state in the real game *)
  (cntl:control) (pmem:('r+'c) word) (vmem:('r+'c) word)  (cor_r:bool)
  (* The functionality's state (cor_s is shared with Sim)*)
  k cor_f
  (* The dummy adversary's state, does not matter really *)
  nd
  (* The simulator's state *)
  cor_s cntl_s vm_s m_s ovr_s s_cntl s_pmem s_vmem
  (* The environment's query *)
  (input: ('r env_message) list) 
  (* Trace in the mitbgame *)
  (mitb_trace: ((('c, 'r) proto_state # num) # ('n word,'n mitb_out)
  GameOutput) list )
  (* Trace in the almost ideal game *)
  (alm_ideal_trace)
  .
    (GoodParameters (dimindex(:'r),dimindex(:'c),dimindex(:'n)))
    /\
    (Initial_State_MITB f  ((cntl,pmem,vmem),cor_r) )
    /\
    (Initial_State_ALMOST_IDEAL ((k,cor_f),(cor_s,cntl_s,vm_s,m_s, ovr_s)))
    /\
    (mitb_trace = EXEC 
      ((PROTO ( (MITB_STEP:('c,'n,'r) mitbstepfunction) f))
       : ('c,'r) proto_state -> ('n,'r) real_message
         -> (('c,'r) proto_state) # 'n real_proto_message)
      DUMMY_ADV
      (((cntl,pmem,vmem),cor_r),nd)
      input)
    /\
      (alm_ideal_trace = EXEC (FMAC (Hash f ZERO)) 
                (SIM (MITB_STEP:('c,'n,'r) mitbstepfunction) f)
                ((k,cor_f),(cor_s,cntl_s,vm_s,m_s, ovr_s,(s_cntl,s_pmem,s_vmem)))
                 input)
    ==>
    (
    EVERY (\(((s1,_),o1),(s2,o2)). (STATE_INVARIANT f s1 s2) /\ (o1=o2) ) 
      (ZIP (mitb_trace,alm_ideal_trace))
    )
``,
       rw [] 
    \\ first_assum(mp_tac o MATCH_MP (
         initial_state_fulfills_invariant |> REWRITE_RULE[GSYM AND_IMP_INTRO]))
    \\ disch_then(fn th => last_assum (assume_tac o MATCH_MP th))
    \\ imp_res_tac (same_output_ind |> SIMP_RULE (srw_ss()) [LET_DEF])
    \\ fs[]
);


val _ = export_theory();


(* Printing
load "mitbTheory"; load "EmitTeX"; open mitbTheory EmitTeX
load "uccomTheory"; open uccomTheory

*)
