The MAC-In-The-Box-Project
==========================

These are the the case-studies and proof scripts for the paper 
> MAC-in-the-Box: Verifying the Security of a Minimalistic Hardware Design for MAC Computation.

It contains the proof scripts in the directory `hol4` and the case studies in
the directory `casestudies`. 

Proof script
------------

Run `Holmake` to compile.

Case studies
------------

To verify the case studies yourself, please run:

```
tamarin-prover --prove MITB_U2F.sapic 
```
and
```
tamarin-prover --prove MACedDH_PFS.sapic
```

Note that Tamarin automatically parses .sapic-file and transforms them into
.spthy, but we left the .spthy for future reference. You can likewise run
tamarin-prover --prove *.spthy .

For the deepsec example, run

```
deepsec password_store.dps
```

The case studies were tested with Deepsec, Version: 1.0alpha with Git hash:
33bc4790006ef051721a18cfcd0df52d00c25957 and tamarin-prover 1.4.1 with the
following patch. This patch solves a bug that is otherwise only fixed in the
current development branch. As 1.4.1 is the latest stable version at the time of writing, we prefer
making the change transparent: the proof strategy has a negation that is
simply wrong: as its name suggests, the function `isLastInsertAction` should match a Goal with a literal that is
prefixed with "L_".

```
diff --git a/lib/theory/src/Theory/Constraint/Solver/ProofMethod.hs b/lib/theory/src/Theory/Constraint/Solver/ProofMethod.hs
index 3f2bba05..4cb3ece6 100644
--- a/lib/theory/src/Theory/Constraint/Solver/ProofMethod.hs
+++ b/lib/theory/src/Theory/Constraint/Solver/ProofMethod.hs
@@ -626,7 +626,7 @@ isFirstInsertAction _ = False
 isLastInsertAction :: Goal -> Bool
 isLastInsertAction (ActionG _ (Fact (ProtoFact _ "Insert" _) _ (t:_)) ) =
         case t of
-            (viewTerm2 -> FPair (viewTerm2 -> Lit2( Con (Name PubName a)))  _) -> not( isPrefixOf "L_" (show a))
+            (viewTerm2 -> FPair (viewTerm2 -> Lit2( Con (Name PubName a)))  _) -> isPrefixOf "L_" (show a)
             _ -> False
 isLastInsertAction _ = False
```
