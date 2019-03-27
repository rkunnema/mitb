structure tacLib :> tacLib =
struct

open HolKernel boolLib bossLib Parse wordsLib lcsymtacs;
open wordsLib wordsTheory bitstringTheory schneiderUtils;     
open numSyntax pairLib pairTools Abbrev;


val UNDISCH_MATCH_TAC = fn MATCH => (PAT_ASSUM MATCH (fn th => (MP_TAC th)));
val UNDISCH_ALL_TAC = (REPEAT (UNDISCH_MATCH_TAC ``X``));
val SPEC_ASSUM_TAC = fn (MATCH, SLIST) => (REPEAT (PAT_ASSUM MATCH (fn th => ASSUME_TAC (SPECL SLIST th))));
val SPEC_AND_KEEP_ASSUM_TAC = fn (MATCH, SLIST) => (PAT_ASSUM MATCH (fn th => ASSUME_TAC th THEN ASSUME_TAC (SPECL SLIST th)));
val THROW_AWAY_TAC = fn MATCH => (REPEAT (PAT_ASSUM MATCH (fn th => IMP_RES_TAC th)));
val THROW_ONE_AWAY_TAC = fn MATCH => (PAT_ASSUM MATCH (fn th => IMP_RES_TAC th));
val THROW_AWAY_IMPLICATIONS_TAC = (REPEAT (WEAKEN_TAC is_imp));
val TAKE_DOWN_TAC = fn pat => PAT_ASSUM  pat (fn thm => let val c = concl thm  in  ASSUME_TAC thm  end);

(* Tactics for different case splits *)
fun split_all_pairs_tac (g as (asl,w)) =
  let
    val vs = free_varsl (w::asl)
    val ps = filter (can pairSyntax.dest_prod o snd o dest_var) vs
    val qs = map (C cons nil o QUOTE o fst o dest_var) ps
  in
    map_every PairCases_on qs
  end g


fun split_all_bools_tac (g as (asl,w)) =
  let
    val vs = free_varsl (w::asl)
    val ps = filter (equal bool o snd o dest_var) vs
    val qs = map (C cons nil o QUOTE o fst o dest_var) ps
  in
    map_every Cases_on qs
  end g

fun split_all_control_tac (g as (asl,w)) =
  let
    val vs = free_varsl (w::asl)
    val ps = filter (equal ``:control`` o snd o dest_var) vs
    val qs = map (C cons nil o QUOTE o fst o dest_var) ps
  in
    map_every Cases_on qs
  end g

fun split_applied_pair_tac tm =
  let
    val (f,p) = dest_comb tm
    val (x,b) = pairSyntax.dest_pabs f
    val xs = pairSyntax.strip_pair x
    val g = list_mk_exists(xs,mk_eq(p,x))
    val th = prove(g, SIMP_TAC bool_ss [GSYM pairTheory.EXISTS_PROD])
  in
    strip_assume_tac th
  end

fun PairCases_on_tm tm (g as (asl,w)) =
let
  val vs = free_varsl(w::asl)
  val p = variant vs (mk_var("p",type_of tm))
  val eq = mk_eq(p,tm)
in
  markerLib.ABBREV_TAC eq >>
  PairCases_on([QUOTE(fst(dest_var p))]) >>
  PAT_ASSUM``Abbrev(^eq)``(ASSUME_TAC o SYM o
  PURE_REWRITE_RULE[markerTheory.Abbrev_def])
end g

fun SYM_ASSUMPTION_TAC pattern = 
  PAT_ASSUM pattern (fn thm => ASSUME_TAC (GSYM thm));     


fun abr_tac_goal f var s =
 case s of NONE =>
    (fn (asl ,g) => let val trm = find_term f g
    		     val vr  = mk_var (var, (type_of trm))
      in 
        (Q.ABBREV_TAC `^vr = ^trm` )(asl ,g)
      end
    )
   | SOME s =>
    (fn (asl ,g) => let val trm = find_term f g
    			val vr  = mk_var (var, (type_of (``^trm ^s``)))
      in 
        (Q.ABBREV_TAC `^vr = (^trm ^s)` )(asl ,g)
      end
    );


fun abbr_fn_tac fn_str abbr_tm = 
  let val ERR = Feedback.mk_HOL_ERR "native_ieeeLib"
      val thy         = (fst o fst o hd)(DB.find (String.concat[fn_str, "_def"]))
      val fn_tm       = prim_mk_const {Name=fn_str,   Thy=thy}
      val dest_fn     = dest_monop fn_tm (ERR (String.concat["dest_", fn_str]) "")
      val is_fn       = can dest_fn
      
 in 
  (fn (asl,g) => 
   let val func = find_term is_fn g
       val vr  = mk_var (abbr_tm, (type_of func))
   in 
     (qabbrev_tac `^vr = ^func`) (asl ,g) 
   end)
 end


end
