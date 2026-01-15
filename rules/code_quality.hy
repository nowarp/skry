(require rules.hy.macros [defrule])
(import rules.hy.macros [fun capability event])
(import rules.hy.bridge [orphan-txcontext? duplicated-branch-condition?
                         duplicated-branch-body? unused-arg? sensitive-event-leak?])
(import rules.hy.builtins [is-orphan-privileged? is-self-recursive?])

;; ---------------------------------------------------------------------------
;; orphan-capability - Capability struct never used as parameter
;; ---------------------------------------------------------------------------
(defrule orphan-capability
  :severity :low
  :categories [:code-quality :visibility]
  :description "Capability struct defined but never used as parameter - likely dead code"
  :match (capability)
  :filter (orphan-capability f))

;; ---------------------------------------------------------------------------
;; orphan_event - Event struct never emitted
;; ---------------------------------------------------------------------------
(defrule orphan-event
  :severity :low
  :categories [:code-quality :visibility]
  :description "Event struct defined but never emitted - likely dead code"
  :match (event)
  :filter (orphan-event f))

;; ---------------------------------------------------------------------------
;; orphan-privileged-capability - Privileged capability defined but never used
;; ---------------------------------------------------------------------------
;; Privileged capability struct is defined (LLM: IsCapability + IsPrivileged) but never
;; used as a function parameter (OrphanCapability). This indicates dead code that
;; was intended for access control but was never wired up - likely a security
;; oversight where privileged-only functions lack their intended protection.
(defrule orphan-privileged-capability
  :severity :medium
  :categories [:code-quality :access-control]
  :description "Privileged capability defined but never used as parameter - protection may be missing"
  :match (capability)
  :filter (is-orphan-privileged? f facts ctx))

;; ---------------------------------------------------------------------------
;; orphan_txcontext - public(friend) with TxContext never called
;; ---------------------------------------------------------------------------
(defrule orphan-txcontext
  :severity :low
  :categories [:code-quality :visibility]
  :description "public(friend) function with TxContext is not called by any module - likely dead code"
  :match (fun :public)
  :filter (orphan-txcontext? f facts ctx))

;; ---------------------------------------------------------------------------
;; duplicated_branch_condition - Same condition multiple times
;; ---------------------------------------------------------------------------
(defrule duplicated-branch-condition
  :severity :critical
  :categories [:logic-error :control-flow]
  :description "Same condition appears multiple times in if-else chain - second branch is unreachable"
  :match (fun)
  :filter (duplicated-branch-condition? f facts ctx))

;; ---------------------------------------------------------------------------
;; duplicated_branch_body - Identical code in branches
;; ---------------------------------------------------------------------------
(defrule duplicated-branch-body
  :severity :low
  :categories [:code-quality :maintainability]
  :description "Identical code in multiple if/else branches - consider refactoring"
  :match (fun)
  :filter (duplicated-branch-body? f facts ctx))

;; ---------------------------------------------------------------------------
;; sensitive_event_leak - Private data in events
;; ---------------------------------------------------------------------------
(defrule sensitive-event-leak
  :severity :high
  :categories [:privacy :security]
  :description "Sensitive data exposed in event - private fields visible on-chain"
  :match (fun :public :entry)
  :filter (sensitive-event-leak? f facts ctx))

;; ---------------------------------------------------------------------------
;; self-recursive-entry - Entry function calls itself
;; ---------------------------------------------------------------------------
;; Entry function that calls itself directly leads to infinite recursion.
;; Attacker can trigger DoS via gas exhaustion or stack overflow.
(defrule self-recursive-entry
  :severity :high
  :categories [:code-quality :dos]
  :description "Entry function calls itself - infinite recursion causes DoS"
  :match (fun :entry)
  :filter (is-self-recursive? f facts ctx))

;; ---------------------------------------------------------------------------
;; unused-arg - Function argument never used
;; ---------------------------------------------------------------------------
;; Function argument is declared but never referenced in the function body.
;; This may indicate: dead code, incomplete implementation, or copy-paste error.
;; Skips: arguments starting with _ (intentionally unused), role/capability types.
(defrule unused-arg
  :severity :low
  :categories [:code-quality :dead-code]
  :description "Function argument is never used in function body"
  :match (fun :public)
  :filter (unused-arg? f facts ctx))
