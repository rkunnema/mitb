signature tacLib =
sig
    include Abbrev
val UNDISCH_MATCH_TAC: term -> Tactical.tactic
val UNDISCH_ALL_TAC: Tactical.tactic
val SPEC_ASSUM_TAC: term * term list -> Tactical.tactic
val SPEC_AND_KEEP_ASSUM_TAC: term * term list -> Tactical.tactic
val THROW_AWAY_TAC: term -> Tactical.tactic
val THROW_ONE_AWAY_TAC: term -> Tactical.tactic
val THROW_AWAY_IMPLICATIONS_TAC: Tactical.tactic
val TAKE_DOWN_TAC: term -> Tactical.tactic
val PairCases_on_tm:
   term -> term list * term -> goal list * (thm list -> thm)
val SYM_ASSUMPTION_TAC: term -> Tactical.tactic
val split_all_bools_tac:
   term list * term -> goal list * validation
val split_all_control_tac:
   term list * term -> goal list * validation
val split_all_pairs_tac:
   term list * term -> goal list * validation
val split_applied_pair_tac: term -> tactic
val abr_tac_goal:
   (term -> bool) ->
     string -> term option -> term list * term -> Q.goal list * validation
val abbr_fn_tac:
   string -> string -> term list * term -> goal list * validation

end
