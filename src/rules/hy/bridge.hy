;; Bridge functions for calling Python semantic checks from Hy rules
;;
;; These wrap the Python check functions via hy_bridge.py, allowing
;; Hy rules to use complex analysis (CFG, taint, LLM) while keeping
;; predicate composition in Hy.
;;
;; Usage:
;;   (import rules.hy.bridge [double-init? tainted-recipient?])
;;   (defrule my-rule
;;     :where (and (double-init? f facts ctx)
;;                 (not (is-init? f facts ctx))))

(import rules.hy_bridge [call-check call-check-capability call-check-event call-check-const
                        call-llm-classify-access-control
                        call-llm-classify-missing-unlock call-llm-classify-arbitrary-drain
                        call-llm-classify-missing-transfer call-llm-classify-sensitive-setter
                        call-llm-classify-internal-helper-exposure
                        has-internal-callers])
(import rules.hy.builtins [has-fact-transitive?])

;; ============================================================================
;; Taint Checks - detect user-controlled data flowing to dangerous sinks
;; ============================================================================

(defn tainted-param? [f facts ctx]
  "Check if function has tainted parameters."
  (call-check "tainted_param" f facts ctx))

(defn tainted-recipient? [f facts ctx]
  "Check if transfer recipient is user-controlled."
  (call-check "tainted_recipient" f facts ctx))

(defn tainted-state-write? [f facts ctx]
  "Check if state write uses user-controlled data."
  (call-check "tainted_state_write" f facts ctx))

(defn tainted-amount? [f facts ctx]
  "Check if amount in coin operations is user-controlled."
  (call-check "tainted_amount" f facts ctx))

(defn tainted-transfer-value? [f facts ctx]
  "Check if transfer value is user-controlled."
  (call-check "tainted_transfer_value" f facts ctx))

(defn tainted-object-destroy? [f facts ctx]
  "Check if object destruction uses user-controlled data."
  (call-check "tainted_object_destroy" f facts ctx))

(defn tainted-loop-bound? [f facts ctx]
  "Check if loop bound is user-controlled (DoS risk)."
  (call-check "tainted_loop_bound" f facts ctx))

;; ============================================================================
;; Sanitized Checks - detect proper validation of user input
;; ============================================================================

(defn sanitized-recipient? [f facts ctx]
  "Check if recipient is properly validated."
  (call-check "sanitized_recipient" f facts ctx))

(defn sanitized-state-write? [f facts ctx]
  "Check if state write has proper validation."
  (call-check "sanitized_state_write" f facts ctx))

(defn sanitized-amount? [f facts ctx]
  "Check if amount is properly validated."
  (call-check "sanitized_amount" f facts ctx))

(defn sanitized-transfer-value? [f facts ctx]
  "Check if transfer value is properly validated."
  (call-check "sanitized_transfer_value" f facts ctx))

(defn sanitized-object-destroy? [f facts ctx]
  "Check if object destruction is properly validated."
  (call-check "sanitized_object_destroy" f facts ctx))

;; ============================================================================
;; Access Control Checks
;; ============================================================================

(defn py-checks-capability? [f facts ctx]
  "Check if function requires capability (Python version)."
  (call-check "checks_capability" f facts ctx))

(defn py-checks-sender? [f facts ctx]
  "Check if function verifies tx_context::sender (Python version)."
  (call-check "checks_sender" f facts ctx))

(defn creates-privileged-cap? [f facts ctx]
  "Check if function creates a privileged capability (uses CreatesCapability + IsPrivileged facts)."
  (call-check "creates_privileged_cap" f facts ctx))

(defn requires-parent-cap? [f facts ctx]
  "Check if function requires a parent capability via CapabilityHierarchy."
  (call-check "requires_parent_cap" f facts ctx))

(defn verifies-ownership? [f facts ctx]
  "Check if function verifies ownership (FieldAccess to owner + HasSenderEqualityCheck)."
  (call-check "verifies_ownership" f facts ctx))

(defn transfers-privileged-to-tainted? [f facts ctx]
  "Check if function transfers privileged cap to tainted recipient."
  (call-check "transfers_privileged_to_tainted" f facts ctx))

(defn single-step-ownership? [f facts ctx]
  "Check if function performs single-step ownership transfer."
  (call-check "single_step_ownership" f facts ctx))

(defn llm-classify-vulnerable? [f facts ctx]
  "LLM access control classification. Generates LLMHasAccessControl or LLMVulnerableAccessControl fact."
  (call-llm-classify-access-control f facts ctx))

(defn llm-classify-internal-helper-exposure? [f facts ctx]
  "LLM classification for internal helper exposure vulnerability.
   Provides rich context: function + callers + callees."
  (call-llm-classify-internal-helper-exposure f facts ctx))

(defn has-internal-callers? [f facts ctx]
  "Check if function has callers within the same package.
   Strong structural signal that function is designed as internal helper."
  (has-internal-callers f facts ctx))

;; ============================================================================
;; Structural Checks
;; ============================================================================

(defn py-is-init? [f facts ctx]
  "Check if function is module init (Python version)."
  (call-check "is_init" f facts ctx))

(defn py-is-public? [f facts ctx]
  "Check if function is public (Python version)."
  (call-check "public" f facts ctx))

(defn py-is-entry? [f facts ctx]
  "Check if function is entry (Python version)."
  (call-check "entry" f facts ctx))

(defn orphan-txcontext? [f facts ctx]
  "Check if function has orphan TxContext parameter."
  (call-check "orphan_txcontext" f facts ctx))

(defn py-orphan-capability? [c facts ctx]
  "Check if capability is orphan (Python version via bridge)."
  (call-check-capability "orphan_capability" c facts ctx))

(defn py-orphan-event? [e facts ctx]
  "Check if event is orphan (Python version via bridge)."
  (call-check-event "orphan_event" e facts ctx))

(defn missing-transfer? [f facts ctx]
  "Check if withdraw function is missing transfer call."
  (call-check "missing_transfer" f facts ctx))

(defn double-init? [f facts ctx]
  "Check if init function is called twice on any path."
  (call-check "double_init" f facts ctx))

(defn self-recursive? [f facts ctx]
  "Check if function calls itself (recursion)."
  (call-check "self_recursive" f facts ctx))

;; ============================================================================
;; Complexity Checks
;; ============================================================================

(defn version-check-inconsistent? [f facts ctx]
  "Check if function is missing version check when others have it."
  (call-check "version_check_inconsistent" f facts ctx))

(defn unused-arg? [f facts ctx]
  "Check if function has unused argument."
  (call-check "unused" f facts ctx))

(defn duplicated-branch-condition? [f facts ctx]
  "Check if same condition appears multiple times in if-else."
  (call-check "duplicated_branch_condition" f facts ctx))

(defn duplicated-branch-body? [f facts ctx]
  "Check if identical code in multiple branches."
  (call-check "duplicated_branch_body" f facts ctx))

;; ============================================================================
;; DeFi Checks
;; ============================================================================

(defn has-transfer-call? [f facts ctx]
  "Check if function OR any callee performs a transfer (transitive)."
  (has-fact-transitive? ctx f "Transfers"))

(defn transfers-to-zero-address? [f facts ctx]
  "Check if function transfers to zero/null address."
  (call-check "transfers_to_zero_address" f facts ctx))

(defn returns-mutable-ref? [f facts ctx]
  "Check if function returns mutable reference."
  (call-check "returns_mutable_ref" f facts ctx))

(defn py-weak-randomness? [f facts ctx]
  "Check if function uses weak randomness source."
  (call-check "weak_randomness" f facts ctx))

(defn sensitive-event-leak? [f facts ctx]
  "Check if sensitive data is leaked in events."
  (call-check "sensitive_event_leak" f facts ctx))

(defn llm-classify-missing-unlock? [f facts ctx]
  "LLM unlock classification. Generates LLMHasUnlockOnAllPaths or LLMMissingUnlock fact."
  (call-llm-classify-missing-unlock f facts ctx))

(defn llm-classify-arbitrary-drain? [f facts ctx]
  "LLM drain classification. Generates LLMCallerOwnsValue or LLMArbitraryDrain fact."
  (call-llm-classify-arbitrary-drain f facts ctx))

(defn llm-classify-missing-transfer? [f facts ctx]
  "LLM transfer classification. Generates LLMValueReachesRecipient or LLMMissingTransfer fact."
  (call-llm-classify-missing-transfer f facts ctx))

(defn llm-classify-sensitive-setter? [f facts ctx]
  "LLM sensitive setter classification. Generates LLMHasSetterAuth or LLMSensitiveSetter fact."
  (call-llm-classify-sensitive-setter f facts ctx))
