;; Built-in property checkers for Hy rules
;;
;; All properties follow the signature: (prop? f facts ctx) -> bool

;; ============================================================================
;; Fact Query Helpers
;; ============================================================================

(defn has-fact? [facts fact-name args]
  "Check if a fact with given name and args prefix exists."
  (setv args-tuple (tuple args))
  (setv args-len (len args))
  (any (gfor fact facts
             :if (and (= (. fact name) fact-name)
                      (= (cut (. fact args) 0 args-len) args-tuple))
             True)))

(defn get-facts [facts fact-name]
  "Get all facts with given name."
  (lfor fact facts :if (= (. fact name) fact-name) fact))

(defn get-global-facts [ctx func-name]
  "Get facts for a function from global index."
  (setv index (. ctx ctx global-facts-index))
  (if (in func-name index)
    (do
      (setv file-facts (get index func-name))
      (setv all-facts [])
      (for [#(file-path facts-list) (.items file-facts)]
        (.extend all-facts facts-list))
      all-facts)
    []))

(defn get-project-facts [ctx]
  "Get project-level facts (IsPrivileged, ProjectCategory, etc.)."
  (getattr (. ctx ctx) "project_facts" []))

(defn get-all-file-facts [ctx]
  "Get all facts from all source files (for cross-file struct facts like IsPrivileged)."
  (setv all-facts [])
  (for [#(file-path file-ctx) (.items (. ctx ctx source_files))]
    (.extend all-facts (. file-ctx facts)))
  all-facts)

(defn get-semantic-facts [ctx]
  "Get semantic facts (IsUserAsset, etc.) from context."
  (getattr (. ctx ctx) "semantic_facts" []))

(defn _last [lst]
  "Get last element of list."
  (get lst (- (len lst) 1)))

(defn _split-last [s sep]
  "Split string and get last part."
  (_last (.split s sep)))

(defn has-fact-for-name? [facts fact-name target-name]
  "Check if fact exists for target-name using Python's names_match (handles qualified names)."
  (import core.facts [has_fact_for_name])
  (has_fact_for_name facts fact-name target-name))

;; ============================================================================
;; Modifier Properties
;; ============================================================================

(defn is-public? [f facts ctx]
  "Check if function is public."
  (has-fact? facts "IsPublic" [f]))

(defn is-entry? [f facts ctx]
  "Check if function is an entry point."
  (has-fact? facts "IsEntry" [f]))

(defn is-init? [f facts ctx]
  "Check if function is a module initializer."
  (has-fact? facts "IsInit" [f]))

(defn is-test-only? [f facts ctx]
  "Check if function is test-only."
  (has-fact? facts "IsTestOnly" [f]))

(defn is-friend? [f facts ctx]
  "Check if function is public(package) or public(friend) - internal to package."
  (has-fact? facts "IsFriend" [f]))

(defn is-externally-callable? [f facts ctx]
  "True if function is callable by external users via transaction or PTB.
   Matches: public entry OR public non-friend."
  (or (is-entry? f facts ctx)
      (not (is-friend? f facts ctx))))

;; ============================================================================
;; Access Control Properties
;; ============================================================================

(defn checks-capability? [f facts ctx #* args]
  "Check if function requires a capability parameter."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (if args
    ;; Check specific capability
    (let [cap (get args 0)]
      (any (gfor fact all-facts
                 :if (and (= (. fact name) "ChecksCapability")
                          (= (get (. fact args) 1) f)
                          (or (= (get (. fact args) 0) cap)
                              (= (_split-last (get (. fact args) 0) "::")
                                 (_split-last cap "::"))))
                 True)))
    ;; Check any capability
    (any (gfor fact all-facts
               :if (and (= (. fact name) "ChecksCapability")
                        (= (get (. fact args) 1) f))
               True))))

(defn checks-sender? [f facts ctx]
  "Check if function has sender equality check for authorization (e.g., owner == sender)."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (has-fact? all-facts "HasSenderEqualityCheck" [f]))

(defn checks-auth? [f facts ctx]
  "Check if function has any form of authorization."
  (or (checks-capability? f facts ctx)
      (checks-sender? f facts ctx)))

(defn checks-privileged? [f facts ctx]
  "Check if function requires a privileged capability parameter."
  (setv func-facts (+ facts (get-global-facts ctx f)))
  ;; Get privileged capability types from ALL files (IsPrivileged is stored where struct is defined)
  (setv all-file-facts (get-all-file-facts ctx))
  (setv privileged-caps (set (gfor fact all-file-facts
                               :if (= (. fact name) "IsPrivileged")
                               (get (. fact args) 0))))
  ;; Check if function has ChecksCapability for any privileged capability
  (any (gfor fact func-facts
             :if (and (= (. fact name) "ChecksCapability")
                      (= (get (. fact args) 1) f)
                      (or (in (get (. fact args) 0) privileged-caps)
                          ;; Also match by simple name
                          (any (gfor pc privileged-caps
                                     (= (_split-last (get (. fact args) 0) "::")
                                        (_split-last pc "::"))))))
             True)))

;; ============================================================================
;; Sink Properties
;; ============================================================================

(defn has-transfer-sink? [f facts ctx]
  "Check if function has a transfer sink."
  (has-fact? facts "TransferSink" [f]))

(defn has-state-write-sink? [f facts ctx]
  "Check if function has a state write sink."
  (has-fact? facts "StateWriteSink" [f]))

(defn has-amount-sink? [f facts ctx]
  "Check if function has an amount extraction sink."
  (has-fact? facts "AmountExtractionSink" [f]))

(defn has-any-sink? [f facts ctx]
  "Check if function has any dangerous sink."
  (or (has-transfer-sink? f facts ctx)
      (has-state-write-sink? f facts ctx)
      (has-amount-sink? f facts ctx)))

(defn has-tainted-sink-in-callchain? [f facts ctx]
  "Check if function has any tainted sink (direct or via cross-module callee)."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (any (gfor fact all-facts
             :if (and (= (. fact name) "TaintedAtSink")
                      (= (get (. fact args) 0) f))
             True)))

;; ============================================================================
;; Taint Properties
;; ============================================================================

(defn tainted-amount? [f facts ctx]
  "Check if function has tainted amount extraction."
  (any (gfor fact facts
             :if (and (= (. fact name) "TaintedAtSink")
                      (= (get (. fact args) 0) f)
                      (= (get (. fact args) 3) "amount_extraction"))
             True)))

(defn tainted-recipient? [f facts ctx]
  "Check if function has tainted transfer recipient (direct or via cross-module callee)."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (any (gfor fact all-facts
             :if (and (= (. fact name) "TaintedAtSink")
                      (= (get (. fact args) 0) f)
                      (= (get (. fact args) 3) "transfer_recipient"))
             True)))

(defn weak-randomness? [f facts ctx]
  "Check if function uses weak randomness (TrackedDerived with source_type=weak_random)."
  (any (gfor fact facts
             :if (and (= (. fact name) "TrackedDerived")
                      (= (get (. fact args) 0) f)
                      (= (get (. fact args) 2) "weak_random"))
             True)))

;; ============================================================================
;; Transfer Properties
;; ============================================================================

(defn has-transfer? [f facts ctx]
  "Check if function performs a transfer (direct only)."
  (has-fact? facts "Transfers" [f]))

;; ============================================================================
;; Transitive Helpers - check func OR any callee
;; ============================================================================

(defn _get-transitive-callees [ctx f]
  "Get transitive callees from CallGraph IR."
  (setv cg (. ctx ctx call_graph))
  (if (is cg None)
    (set)
    (.get (. cg transitive_callees) f (set))))

(defn _has-fact-in-func? [ctx func-name fact-name]
  "Check if a function has a boolean fact (direct).
   Checks both global_facts_index and source_files.facts for injected facts."
  ;; Check indexed facts first (fast path)
  (setv index (. ctx ctx global-facts-index))
  (when (in func-name index)
    (setv file-facts (get index func-name))
    (for [#(_ facts-list) (.items file-facts)]
      (for [fact facts-list]
        (when (and (= (. fact name) fact-name)
                   (>= (len (. fact args)) 1)
                   (= (get (. fact args) 0) func-name))
          (return True)))))
  ;; Also check source_files.facts for injected facts not in index
  (for [#(_ file-ctx) (.items (. ctx ctx source-files))]
    (for [fact (. file-ctx facts)]
      (when (and (= (. fact name) fact-name)
                 (>= (len (. fact args)) 1)
                 (= (get (. fact args) 0) func-name))
        (return True))))
  False)

(defn has-fact-transitive? [ctx f fact-name]
  "Check if func OR any transitive callee has a boolean fact."
  (when (_has-fact-in-func? ctx f fact-name)
    (return True))
  (for [callee (_get-transitive-callees ctx f)]
    (when (_has-fact-in-func? ctx callee fact-name)
      (return True)))
  False)

;; Transitive predicates: has-*? checks direct, has-**? checks transitive
(defn has-transfer*? [f facts ctx]
  "Check if function OR any callee performs a transfer."
  (has-fact-transitive? ctx f "Transfers"))

(defn has-value-extraction*? [f facts ctx]
  "Check if function OR any callee has value extraction."
  (has-fact-transitive? ctx f "HasValueExtraction"))

(defn checks-sender*? [f facts ctx]
  "Check if function OR any callee has sender equality check."
  (has-fact-transitive? ctx f "HasSenderEqualityCheck"))

(defn checks-capability*? [f facts ctx]
  "Check if function OR any callee checks capability."
  ;; ChecksCapability has args (cap_type, func_name), not (func_name, ...)
  ;; Need custom check
  (setv index (. ctx ctx global-facts-index))
  (defn check-func [func-name]
    (when (not (in func-name index))
      (return False))
    (setv file-facts (get index func-name))
    (for [#(_ facts-list) (.items file-facts)]
      (for [fact facts-list]
        (when (and (= (. fact name) "ChecksCapability")
                   (= (get (. fact args) 1) func-name))
          (return True))))
    False)
  (when (check-func f)
    (return True))
  (for [callee (_get-transitive-callees ctx f)]
    (when (check-func callee)
      (return True)))
  False)

(defn checks-auth*? [f facts ctx]
  "Check if function OR any callee has auth check (sender or capability)."
  (or (checks-sender*? f facts ctx)
      (checks-capability*? f facts ctx)))

;; ============================================================================
;; Event Properties
;; ============================================================================

(defn emits-event? [f facts ctx]
  "Check if function emits any event (uses EmitsEvent fact)."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (any (gfor fact all-facts
             :if (and (= (. fact name) "EmitsEvent")
                      (= (get (. fact args) 0) f))
             True)))

;; ============================================================================
;; Orphan Properties
;; ============================================================================

(defn orphan-capability? [c facts ctx]
  "Check if capability is orphan."
  (has-fact? facts "OrphanCapability" [c]))

(defn orphan-event? [e facts ctx]
  "Check if event is orphan."
  (has-fact? facts "OrphanEvent" [e]))

;; ============================================================================
;; Derived Facts (computed from base facts)
;; ============================================================================

(defn operates-on-shared-object? [f facts ctx]
  "Check if function has &mut param to shared object type."
  (has-fact? facts "OperatesOnSharedObject" [f]))

(defn operates-on-owned-only? [f facts ctx]
  "Check if function operates only on owned objects (no shared)."
  (has-fact? facts "OperatesOnOwnedOnly" [f]))

(defn value-exchange-function? [f facts ctx]
  "Check if function takes Coin/Balance input and returns Coin/Balance (swap/refund pattern)."
  (has-fact? facts "ValueExchangeFunction" [f]))

(defn transfers-user-provided-value? [f facts ctx]
  "Check if function transfers user-provided Coin/Balance."
  (has-fact? facts "TransfersUserProvidedValue" [f]))

(defn transfers-user-asset? [f facts ctx]
  "Check if function transfers user-owned asset type."
  (any (gfor fact facts
             :if (and (= (. fact name) "TransfersUserAsset")
                      (= (get (. fact args) 0) f))
             True)))

(defn transfers-from-sender? [f facts ctx]
  "Check if function transfers from ctx.sender() - user operates on own assets."
  (has-fact? facts "TransfersFromSender" [f]))

(defn transfers-from-shared-object? [f facts ctx]
  "Check if function OR any callee extracts value from shared object param (transitive)."
  (has-fact-transitive? ctx f "TransfersFromSharedObject"))

(defn transfers-from-shared-object-direct? [f facts ctx]
  "Check if function DIRECTLY extracts value from shared object param (non-transitive)."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (any (gfor fact all-facts
             :if (and (= (. fact name) "TransfersFromSharedObject")
                      (= (get (. fact args) 0) f))
             True)))

(defn is-deposit-pattern? [f facts ctx]
  "Check if function is a deposit pattern - user provides Coin/Balance for storage.
   Deposits are safe because user provides their own value to be stored,
   not extracting from shared storage."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (any (gfor fact all-facts
             :if (and (= (. fact name) "UserDepositsInto")
                      (= (get (. fact args) 0) f))
             True)))

(defn has-sender-equality-check? [f facts ctx]
  "Check if function has sender equality check (e.g., owner == sender)."
  (has-fact? facts "HasSenderEqualityCheck" [f]))

(defn calls-sender? [f facts ctx]
  "Check if function OR any callee calls tx_context::sender() (transitive).
   Used to detect if assets could be transferred to the caller.
   Functions that don't call sender() cannot transfer assets to the attacker,
   making them safe from 'cross-user theft' where attacker receives victim's assets."
  (has-fact-transitive? ctx f "CallsSender"))

(setv SENSITIVE_SINK_FACTS
  ["TransferSink" "StateWriteSink" "AmountExtractionSink" "TaintedAtSink"])

(defn has-sensitive-sink? [f facts ctx]
  "Check if function has any sensitive sink (transfer/state-write/extraction).
   Includes IPA-propagated sinks from callees."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (any (gfor fact all-facts
             :if (and (in (. fact name) SENSITIVE_SINK_FACTS)
                      (= (get (. fact args) 0) f))
             True)))

(setv DIRECT_SINK_FACTS
  ["TransferSink" "StateWriteSink" "AmountExtractionSink"])

(defn has-direct-sensitive-sink? [f facts ctx]
  "Check if function has any DIRECT sensitive sink (transfer/state-write/extraction).
   Excludes propagated sinks from callees (identified by '_via_' in sink ID)."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  ;; Check for direct base sink facts
  (when (any (gfor fact all-facts
                   :if (and (in (. fact name) DIRECT_SINK_FACTS)
                            (= (get (. fact args) 0) f))
                   True))
    (return True))
  ;; Check TaintedAtSink, but only direct sinks (no '_via_' in sink ID)
  (any (gfor fact all-facts
             :if (and (= (. fact name) "TaintedAtSink")
                      (= (get (. fact args) 0) f)
                      (>= (len (. fact args)) 3)
                      (not (in "_via_" (get (. fact args) 2))))
             True)))

(setv THEFT_SINK_FACTS
  ["TransferSink" "AmountExtractionSink"])

(defn has-theft-sink? [f facts ctx]
  "Check if function has theft-specific sinks (transfer/extraction, NOT state writes).
   Used for user asset theft detection - filters out deposit functions that only write to state."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  ;; Check for base transfer/extraction sinks
  (when (any (gfor fact all-facts
                   :if (and (in (. fact name) THEFT_SINK_FACTS)
                            (= (get (. fact args) 0) f))
                   True))
    (return True))
  ;; Check for TaintedAtSink, but exclude state_write (that's deposit pattern)
  (any (gfor fact all-facts
             :if (and (= (. fact name) "TaintedAtSink")
                      (= (get (. fact args) 0) f)
                      (>= (len (. fact args)) 4)
                      (!= (get (. fact args) 3) "state_write"))
             True)))

;; ============================================================================
;; User Asset Properties
;; ============================================================================

(defn writes-user-asset? [f facts ctx]
  "Check if function has &mut param to user asset container."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (any (gfor fact all-facts
             :if (and (= (. fact name) "WritesUserAsset")
                      (= (get (. fact args) 0) f))
             True)))

(defn reads-user-asset? [f facts ctx]
  "Check if function has & param to user asset container."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (any (gfor fact all-facts
             :if (and (= (. fact name) "ReadsUserAsset")
                      (= (get (. fact args) 0) f))
             True)))

(defn accesses-user-asset? [f facts ctx]
  "Check if function reads or writes user asset container."
  (or (writes-user-asset? f facts ctx)
      (reads-user-asset? f facts ctx)))

(defn accesses-user-owned-asset? [f facts ctx]
  "Check if function accesses user asset container WITH ownership field (filters protocol state).

  User-owned assets have ownership fields (owner, authority, etc.) that track per-user ownership.
  Protocol state (shared pools/vaults without owner fields) are excluded by this check."
  (when (not (accesses-user-asset? f facts ctx))
    (return False))

  ;; Get all accessed struct types (from WritesUserAsset/ReadsUserAsset)
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (setv accessed-structs (set))
  (for [fact all-facts]
    (when (and (in (. fact name) ["WritesUserAsset" "ReadsUserAsset"])
               (= (get (. fact args) 0) f))
      (.add accessed-structs (get (. fact args) 1))))

  ;; Check if ANY accessed struct has ownership field
  ;; Need to check global facts for the struct since HasOwnershipField is struct-level
  (for [struct-type accessed-structs]
    ;; Get struct facts from all files
    (for [#(_ file-ctx) (.items (. ctx ctx source-files))]
      (for [fact (. file-ctx facts)]
        (when (and (= (. fact name) "HasOwnershipField")
                   (= (get (. fact args) 0) struct-type))
          (return True)))))
  False)

;; ============================================================================
;; Parameter Properties
;; ============================================================================

(defn has-param-type? [f type-name facts ctx]
  "Check if function has parameter of given type."
  (any (gfor fact facts
             :if (and (= (. fact name) "FormalArg")
                      (= (get (. fact args) 0) f)
                      (in type-name (get (. fact args) 3)))
             True)))

(defn has-mutable-param? [f facts ctx]
  "Check if function has &mut parameter (modifies state)."
  ;; FormalArg: (func_name, param_idx, param_name, param_type)
  ;; Check if param_type starts with "&mut"
  (any (gfor fact facts
             :if (and (= (. fact name) "FormalArg")
                      (= (get (. fact args) 0) f)
                      (.startswith (get (. fact args) 3) "&mut"))
             True)))

;; ============================================================================
;; Value Extraction Properties
;; ============================================================================

(defn has-value-extraction? [f facts ctx]
  "Check if function has value extraction (coin::take, balance::split, etc.) including via callees."
  (has-fact? facts "HasValueExtraction" [f]))

(defn _names-match [a b]
  "Match qualified names using Python's names_match function."
  (import core.facts [names_match])
  (names_match a b))

(defn _fields-match [fc-field field]
  "Match field names. Handles simple field names and nested paths (e.g., 'admin' matches 'admin.inner')."
  ;; Extract top-level field from paths like 'admin.inner'
  (setv field-top (get (.split field ".") 0))
  (setv fc-field-top (get (.split fc-field ".") 0))
  (= fc-field-top field-top))

(defn writes-privileged-field? [f facts ctx]
  "Check if function writes to any privileged/config field.
   Detects create-and-corrupt: creating user-creatable + corrupting admin/config."
  (setv all-facts (+ facts (get-all-file-facts ctx)))
  ;; Find all fields this function writes to
  (setv writes-by-func
        (lfor fact all-facts
              :if (and (in (. fact name) ["WritesField" "TransitiveWritesField"])
                       (= (get (. fact args) 0) f))
              #((get (. fact args) 1) (get (. fact args) 2))))  ; (struct, field)
  ;; Check if any written field is privileged/config
  (any (gfor #(struct field) writes-by-func
             (any (gfor fact all-facts
                        :if (and (= (. fact name) "FieldClassification")
                                 (= (len (. fact args)) 6)
                                 (in (get (. fact args) 2) ["mutable_config" "privileged_address"])
                                 (= (get (. fact args) 3) False))  ; positive classification
                        ;; Match struct using proper FQN resolution and field
                        (let [fc-struct (get (. fact args) 0)
                              fc-field (get (. fact args) 1)]
                          (and (_names-match fc-struct struct)
                               (_fields-match fc-field field))))))))

(defn returns-coin-type? [f facts ctx]
  "Check if function returns Coin/Balance/Token type."
  (has-fact? facts "ReturnsCoinType" [f]))

;; ============================================================================
;; Feature Detection Properties
;; Names match fact names: feature-version? -> FeatureVersion, project-category? -> ProjectCategory
;; ============================================================================

(defn project-category? [category facts ctx]
  "Check if project has given category (probability >= 0.7).
   Raises error if category is not in PROJECT_CATEGORIES."
  (import core.facts [PROJECT_CATEGORIES])
  (when (not (in category PROJECT_CATEGORIES))
    (raise (ValueError f"Unknown project category '{category}'. Valid: {PROJECT_CATEGORIES}")))
  (setv project-facts (getattr (. ctx ctx) "project_facts" []))
  (any (gfor fact project-facts
             :if (and (= (. fact name) "ProjectCategory")
                      (= (get (. fact args) 0) category))
             True)))

(defn feature-version? [facts ctx]
  "Check if project uses versioning (FeatureVersion fact is true)."
  (setv project-facts (getattr (. ctx ctx) "project_facts" []))
  (any (gfor fact project-facts
             :if (and (= (. fact name) "FeatureVersion")
                      (> (len (. fact args)) 0)
                      (is (get (. fact args) 0) True))
             True)))

;; ============================================================================
;; Privilege Properties
;; ============================================================================

(defn returns-mutable-ref? [f facts ctx]
  "Check if function returns mutable reference (&mut T).
   Returning &mut to internal state allows caller to corrupt it."
  (any (gfor fact facts
             :if (and (= (. fact name) "ReturnsMutableRef")
                      (= (get (. fact args) 0) f))
             True)))

(defn is-privileged? [r facts ctx]
  "Check if struct/role is privileged capability.
   Uses IsPrivileged fact from LLM classification."
  (setv all-file-facts (get-all-file-facts ctx))
  (has-fact-for-name? all-file-facts "IsPrivileged" r))

(defn has-mutable-config-param? [f facts ctx]
  "Check if function has &mut param to config struct.
   Cross-references FormalArg with IsConfig structs.
   Uses exact FQN matching to avoid cross-module collisions."
  (setv all-file-facts (get-all-file-facts ctx))
  (setv config-struct-names (set (gfor fact all-file-facts
                                       :if (= (. fact name) "IsConfig")
                                       (get (. fact args) 0))))
  (when (not config-struct-names)
    (return False))
  ;; Check if function has &mut param whose type matches a config struct
  (for [fact facts]
    (when (and (= (. fact name) "FormalArg")
               (= (get (. fact args) 0) f)
               (.startswith (get (. fact args) 3) "&mut "))
      (setv param-type (get (. fact args) 3))
      ;; Extract type from "&mut Type" or "&mut Type<G>"
      (setv type-part (. param-type [(slice 5 None)]))  ;; Remove "&mut " using slice
      ;; Strip generics if present
      (when (in "<" type-part)
        (setv type-part (. type-part [(slice 0 (.index type-part "<"))])))
      ;; Exact FQN match - no names_match to avoid FQN collision bugs
      (when (in type-part config-struct-names)
        (return True))))
  False)

(defn is-state-container? [s facts ctx]
  "Check if struct is a state container (holds mutable runtime state).
   Uses IsStateContainer fact from LLM classification."
  (setv all-file-facts (get-all-file-facts ctx))
  (has-fact-for-name? all-file-facts "IsStateContainer" s))

(defn is-state-field? [struct-name field-name facts ctx]
  "Check if field is a state field (holds mutable runtime state).
   Uses FieldClassification fact with category='state'.
   Uses exact FQN matching to avoid cross-module collisions."
  (setv all-file-facts (get-all-file-facts ctx))
  (for [fact all-file-facts]
    (when (and (= (. fact name) "FieldClassification")
               (= (len (. fact args)) 6)
               (= (get (. fact args) 0) struct-name)
               (= (get (. fact args) 1) field-name)
               (= (get (. fact args) 2) "state")
               (= (get (. fact args) 3) False))  ; negative=False means positive classification
      (return True)))
  False)

(defn operates-on-state-container? [f facts ctx]
  "Check if function has &mut param to state container struct.
   State containers (pools, registries) are expected to be modified by users.
   Cross-references FormalArg with IsStateContainer structs.
   Uses exact FQN matching to avoid cross-module collisions."
  (setv all-file-facts (get-all-file-facts ctx))
  (setv state-container-names (set (gfor fact all-file-facts
                                         :if (= (. fact name) "IsStateContainer")
                                         (get (. fact args) 0))))
  (when (not state-container-names)
    (return False))
  ;; Check if function has &mut param whose type matches a state container
  (for [fact facts]
    (when (and (= (. fact name) "FormalArg")
               (= (get (. fact args) 0) f)
               (.startswith (get (. fact args) 3) "&mut "))
      (setv param-type (get (. fact args) 3))
      (setv type-part (. param-type [(slice 5 None)]))
      (when (in "<" type-part)
        (setv type-part (. type-part [(slice 0 (.index type-part "<"))])))
      ;; Exact FQN match - no names_match to avoid FQN collision bugs
      (when (in type-part state-container-names)
        (return True))))
  False)

(defn has-mutable-state-container-param? [f facts ctx]
  "Alias for operates-on-state-container? for clarity in rules."
  (operates-on-state-container? f facts ctx))

;; ============================================================================
;; Orphan Detection Properties
;; ============================================================================

(defn is-orphan-role? [r facts ctx]
  "Check if role struct is orphan (OrphanCapability fact - defined but never used as param)."
  (setv all-file-facts (get-all-file-facts ctx))
  (has-fact-for-name? all-file-facts "OrphanCapability" r))

(defn is-orphan-privileged? [r facts ctx]
  "Check if orphan role is also privileged capability.
   Combines OrphanCapability + IsPrivileged for dead privileged capability detection."
  (and (is-orphan-role? r facts ctx)
       (is-privileged? r facts ctx)))

;; ============================================================================
;; Recursion Properties
;; ============================================================================

(defn is-self-recursive? [f facts ctx]
  "Check if function calls itself (SelfRecursive fact).
   Self-recursive entry functions can cause DoS via stack overflow."
  (has-fact? facts "SelfRecursive" [f]))

;; ============================================================================
;; Global Pause Properties (from PauseDetector)
;; ============================================================================

(defn feature-pause? [facts ctx]
  "Check if project has global pause mechanism (from PauseDetector).
   Returns True if FeaturePause(True) exists in project facts."
  (setv project-facts (get-project-facts ctx))
  (any (gfor fact project-facts
             :if (and (= (. fact name) "FeaturePause")
                      (> (len (. fact args)) 0)
                      (is (get (. fact args) 0) True))
             True)))

(defn checks-pause? [f facts ctx]
  "Check if function checks global pause state before operating.
   Uses ChecksPause fact from PauseDetector + propagation."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (has-fact? all-facts "ChecksPause" [f]))

(defn checks-pause*? [f facts ctx]
  "Check if function OR any callee checks pause (transitive).
   Handles wrapper patterns like storage::when_not_paused()."
  (has-fact-transitive? ctx f "ChecksPause"))

(defn is-pause-control? [f facts ctx]
  "Check if function controls pause state (pause/unpause).
   Uses IsPauseControl fact from PauseDetector."
  (setv project-facts (get-project-facts ctx))
  (any (gfor fact project-facts
             :if (and (= (. fact name) "IsPauseControl")
                      (> (len (. fact args)) 0)
                      (= (get (. fact args) 0) f))
             True)))

;; ============================================================================
;; Struct Creation Pattern Properties
;; ============================================================================

(defn operates-on-user-creatable? [f facts ctx]
  "Check if function operates on user-creatable struct (not singleton).
   User-creatable structs can be minted by anyone via public function,
   so writes to them are less severe (user owns their instances).
   Uses IsUserCreatable fact from creation site analysis."
  ;; Get all facts (IsUserCreatable is in file facts, not project facts)
  (setv all-facts (get-all-file-facts ctx))
  ;; Get all user-creatable types
  (setv user-creatable-types
        (set (gfor fact all-facts
                   :if (= (. fact name) "IsUserCreatable")
                   (get (. fact args) 0))))
  ;; Check if function has &mut param to any user-creatable type
  (any (gfor fact facts
             :if (= (. fact name) "FormalArg")
             :if (= (get (. fact args) 0) f)
             (do
               (setv param-type (get (. fact args) 3))
               (setv is-mut-ref (.startswith param-type "&mut"))
               (when is-mut-ref
                 (setv base-type (.strip (cut param-type 4 None)))
                 ;; Check both FQN and simple name
                 (or (in base-type user-creatable-types)
                     (any (gfor uc-type user-creatable-types
                                (.endswith uc-type (+ "::" base-type))))))))))

(defn creates-user-creatable? [f facts ctx]
  "Check if function creates (shares/transfers) a user-creatable struct.
   Functions that create user-creatable objects are safe because they only
   write to their NEW object, not existing shared state.
   Uses SharesObject/TransfersToSender facts to detect creation,
   and IsUserCreatable facts to identify user-mintable types."
  (setv all-facts (get-all-file-facts ctx))
  ;; Get all user-creatable types
  (setv user-creatable-types
        (set (gfor fact all-facts
                   :if (= (. fact name) "IsUserCreatable")
                   (get (. fact args) 0))))
  ;; Check if function shares or transfers a user-creatable type
  (any (gfor fact all-facts
             :if (and (in (. fact name) #{"SharesObject" "TransfersToSender"})
                      (= (get (. fact args) 0) f))
             (do
               (setv created-type (get (. fact args) 1))
               ;; Check both FQN and simple name match
               (or (in created-type user-creatable-types)
                   (any (gfor uc-type user-creatable-types
                              (.endswith uc-type (+ "::" created-type)))))))))

;; ============================================================================
;; Per-Sink Guard Properties (Phase 2 IPA)
;; ============================================================================

(defn _get-sink-stmt-ids [f facts sink-type]
  "Get all stmt_ids for sinks of given type in function f.
   For TaintedAtSink facts: sink-type is 'transfer_recipient', 'transfer_value', etc.
   Returns stmt_ids from TaintedAtSink(func, source, stmt_id, sink_type, cap)."
  (lfor fact facts
        :if (and (= (. fact name) "TaintedAtSink")
                 (= (get (. fact args) 0) f)
                 (= (get (. fact args) 3) sink-type))
        (get (. fact args) 2)))  ;; stmt_id is at index 2

(defn _sink-guarded? [f stmt-id guard-type facts]
  "Check if specific sink (by stmt_id) is guarded by guard_type.
   Handles IPA-propagated sinks: if stmt_id contains '_via_callee', check callee's guards."
  ;; Direct check: exact match on (f, stmt_id, guard_type)
  (when (any (gfor fact facts
                   :if (and (= (. fact name) "GuardedSink")
                            (= (get (. fact args) 0) f)
                            (= (get (. fact args) 1) stmt-id)
                            (= (get (. fact args) 2) guard-type))
                   True))
    (return True))
  ;; IPA check: if stmt_id is like "stmt_X_via_callee", check if callee has guard
  (when (in "_via_" stmt-id)
    (setv callee (. stmt-id [(slice (+ (.index stmt-id "_via_") 5) None)]))
    (when (any (gfor fact facts
                     :if (and (= (. fact name) "GuardedSink")
                              (= (get (. fact args) 0) callee)
                              (= (get (. fact args) 2) guard-type))
                     True))
      (return True)))
  False)

(defn _sink-guarded-by-any-capability? [f stmt-id facts]
  "Check if specific sink is guarded by any role.
   Handles IPA-propagated sinks: if stmt_id contains '_via_callee', check callee's guards."
  ;; Direct check
  (when (any (gfor fact facts
                   :if (and (= (. fact name) "GuardedSink")
                            (= (get (. fact args) 0) f)
                            (= (get (. fact args) 1) stmt-id)
                            (.startswith (get (. fact args) 2) "role:"))
                   True))
    (return True))
  ;; IPA check
  (when (in "_via_" stmt-id)
    (setv callee (. stmt-id [(slice (+ (.index stmt-id "_via_") 5) None)]))
    (when (any (gfor fact facts
                     :if (and (= (. fact name) "GuardedSink")
                              (= (get (. fact args) 0) callee)
                              (.startswith (get (. fact args) 2) "role:"))
                     True))
      (return True)))
  False)

(defn has-unguarded-tainted-recipient? [f facts ctx]
  "Check if function has tainted transfer recipient NOT guarded by sender.
   This is the per-sink equivalent of (and (tainted-recipient? f) (not (checks-sender? f)))."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (setv recipient-stmt-ids (_get-sink-stmt-ids f all-facts "transfer_recipient"))
  (any (gfor stmt-id recipient-stmt-ids
             (not (_sink-guarded? f stmt-id "sender" all-facts)))))

(defn has-unguarded-tainted-recipient-no-role? [f facts ctx]
  "Check if function has tainted transfer recipient NOT guarded by sender OR role."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (setv recipient-stmt-ids (_get-sink-stmt-ids f all-facts "transfer_recipient"))
  (any (gfor stmt-id recipient-stmt-ids
             (and (not (_sink-guarded? f stmt-id "sender" all-facts))
                  (not (_sink-guarded-by-any-capability? f stmt-id all-facts))))))

(defn has-unguarded-tainted-value? [f facts ctx]
  "Check if function has tainted transfer value NOT guarded by sender."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (setv value-stmt-ids (_get-sink-stmt-ids f all-facts "transfer_value"))
  (any (gfor stmt-id value-stmt-ids
             (not (_sink-guarded? f stmt-id "sender" all-facts)))))

(defn has-unguarded-state-write? [f facts ctx]
  "Check if function has tainted state write NOT guarded by sender."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (setv write-stmt-ids (_get-sink-stmt-ids f all-facts "state_write"))
  (any (gfor stmt-id write-stmt-ids
             (not (_sink-guarded? f stmt-id "sender" all-facts)))))

(defn all-sinks-guarded-by-pause? [f facts ctx]
  "Check if ALL tainted sinks are guarded by pause check."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (setv sink-types ["transfer_recipient" "transfer_value"
                    "state_write" "amount_extraction" "object_destroy"])
  (setv all-stmt-ids [])
  (for [sink-type sink-types]
    (.extend all-stmt-ids (_get-sink-stmt-ids f all-facts sink-type)))
  (if (not all-stmt-ids)
    False  ;; No sinks, so nothing to check
    (all (gfor stmt-id all-stmt-ids
               (_sink-guarded? f stmt-id "pause" all-facts)))))

(defn _sink-has-any-guard? [f stmt-id facts]
  "Check if sink has ANY guard (sender, role, pause, lock, version)."
  (any (gfor fact facts
             :if (and (= (. fact name) "GuardedSink")
                      (= (get (. fact args) 0) f)
                      (= (get (. fact args) 1) stmt-id))
             True)))

(defn _sink-guarded-by-auth? [f stmt-id facts]
  "Check if sink is guarded by sender OR any role."
  (or (_sink-guarded? f stmt-id "sender" facts)
      (_sink-guarded-by-any-capability? f stmt-id facts)))

;; User deposit sink detection (per-sink level)

(defn _get-coin-balance-params [f facts]
  "Get set of param names that are Coin/Balance/Token by value (not reference)."
  (import move.sui_patterns [is_value_type_fqn])
  (setv params (set))
  (for [fact facts]
    (when (and (= (. fact name) "FormalArg")
               (= (get (. fact args) 0) f))
      (setv param-name (get (. fact args) 2))
      (setv param-type (get (. fact args) 3))
      ;; By value (not reference) and is Coin/Balance/Token (FQN check)
      (when (and (not (.startswith param-type "&"))
                 (is_value_type_fqn param-type))
        (.add params param-name))))
  params)

(defn _get-mut-value-params [f facts]
  "Get set of param names that are &mut Coin/Balance/Token (mutable reference)."
  (import move.sui_patterns [is_value_type_fqn])
  (setv params (set))
  (for [fact facts]
    (when (and (= (. fact name) "FormalArg")
               (= (get (. fact args) 0) f))
      (setv param-name (get (. fact args) 2))
      (setv param-type (get (. fact args) 3))
      ;; Mutable reference to stdlib value type (FQN check)
      (when (and (.startswith param-type "&mut ")
                 (is_value_type_fqn (.replace param-type "&mut " "" 1)))
        (.add params param-name))))
  params)

(defn _get-extraction-results [f mut-params facts]
  "Get set of result variables from extraction calls on &mut Coin/Balance params.
   Handles both function syntax (coin::split(coin, ...)) and method syntax (coin.split(...))."
  (import move.sui_patterns [is_value_extraction_call])
  (setv results (set))

  ;; Find extraction calls and their results via CallResult facts
  (for [fact facts]
    (when (and (= (. fact name) "CallResult")
               (= (get (. fact args) 0) f))
      (setv stmt-id (get (. fact args) 1))
      (setv result-var (get (. fact args) 2))
      (setv callee (get (. fact args) 3))
      (when (is_value_extraction_call callee)
        ;; Check if this extraction call operates on a mut-param
        ;; Method 1: Check CallArg arg 0 (function syntax)
        (setv is-on-mut-param False)
        (for [ca-fact facts]
          (when (and (= (. ca-fact name) "CallArg")
                     (= (get (. ca-fact args) 0) f)
                     (= (get (. ca-fact args) 1) stmt-id)
                     (= (get (. ca-fact args) 3) 0))  ;; arg index 0
            (setv arg-vars (get (. ca-fact args) 4))
            (when (and (isinstance arg-vars tuple)
                       (> (len arg-vars) 0)
                       (in (get arg-vars 0) mut-params))
              (setv is-on-mut-param True))
            (break)))
        ;; Method 2: Fallback for method syntax - if has mut-params, assume it's on one
        (when (and (not is-on-mut-param) mut-params)
          (setv is-on-mut-param True))
        (when is-on-mut-param
          (.add results result-var)))))
  results)

(defn _sink-receives-extracted-value? [f stmt-id extraction-results facts]
  "Check if the specific state_write sink receives value derived from extraction results.
   Uses SinkUsesVar to check which variables are actually used at the sink."
  ;; Check SinkUsesVar - does any extraction result variable get used at this sink?
  (for [fact facts]
    (when (and (= (. fact name) "SinkUsesVar")
               (= (get (. fact args) 0) f)
               (= (get (. fact args) 1) stmt-id))
      (setv var (get (. fact args) 2))
      ;; Direct match: extraction result used at sink
      (when (in var extraction-results)
        (return True))
      ;; Transitive: check if sink var is tainted by extraction result
      (setv visited (set))
      (setv worklist [var])
      (while worklist
        (setv current (.pop worklist 0))
        (when (in current visited)
          (continue))
        (.add visited current)
        (when (in current extraction-results)
          (return True))
        ;; Follow TaintedBy chain: current is tainted BY origin
        (for [tb-fact facts]
          (when (and (= (. tb-fact name) "TaintedBy")
                     (= (get (. tb-fact args) 0) f)
                     (= (get (. tb-fact args) 1) current))
            (setv origin (get (. tb-fact args) 2))
            (when (not (in origin visited))
              (.append worklist origin)))))))
  False)

(defn _is-user-deposit-sink? [f stmt-id facts]
  "Check if a specific state_write sink is a user deposit pattern.
   Returns True if sink is safe deposit, False otherwise.

   Handles two patterns:
   1. By-value Coin/Balance param -> balance::join/coin::put/coin::join sink
   2. &mut Coin/Balance param -> extraction (coin::split) -> any state write sink"
  (import move.sui_patterns [is_user_deposit_call])

  ;; Pattern 1: By-value param + deposit callee (balance::join, coin::put, coin::join)
  (setv is-join-callee False)
  (for [fact facts]
    (when (and (= (. fact name) "StateWriteSink")
               (= (get (. fact args) 0) f)
               (= (get (. fact args) 1) stmt-id))
      (setv callee (get (. fact args) 2))
      (when (is_user_deposit_call callee)
        (setv is-join-callee True))
      (break)))

  (when is-join-callee
    ;; Check by-value params for Pattern 1
    (setv value-params (_get-coin-balance-params f facts))
    (when value-params
      (for [fact facts]
        (when (and (= (. fact name) "TaintedAtSink")
                   (= (get (. fact args) 0) f)
                   (= (get (. fact args) 2) stmt-id)
                   (= (get (. fact args) 3) "state_write"))
          (setv taint-source (get (. fact args) 1))
          ;; Direct match
          (when (in taint-source value-params)
            (return True))
          ;; Transitive TaintedBy traversal (BFS)
          (setv visited (set))
          (setv worklist [taint-source])
          (while worklist
            (setv current (.pop worklist 0))
            (when (in current visited)
              (continue))
            (.add visited current)
            (for [tb-fact facts]
              (when (and (= (. tb-fact name) "TaintedBy")
                         (= (get (. tb-fact args) 0) f)
                         (= (get (. tb-fact args) 1) current))
                (setv origin (get (. tb-fact args) 2))
                (when (in origin value-params)
                  (return True))
                (when (not (in origin visited))
                  (.append worklist origin)))))))))

  ;; Pattern 2: &mut param + extraction (coin::split, etc.) -> THIS sink receives extracted value
  ;; User provides &mut Coin<T>, function extracts value via split and stores it
  ;; Only suppress THIS specific sink if it receives the extracted value
  (setv mut-params (_get-mut-value-params f facts))
  (when mut-params
    ;; Pattern 2a: The sink IS an extraction call on a &mut param
    ;; e.g., coin::split(user_coin, amount, ...) where user_coin is &mut Coin<T>
    ;; Tainted amount controls extraction from user's own coin - safe
    (import move.sui_patterns [is_value_extraction_call])
    (setv found-extraction-sink False)
    (setv has-any-extraction-call False)
    (for [fact facts]
      (when (and (= (. fact name) "StateWriteSink")
                 (= (get (. fact args) 0) f)
                 (= (get (. fact args) 1) stmt-id))
        (setv callee (get (. fact args) 2))
        (when (is_value_extraction_call callee)
          (setv found-extraction-sink True)
          ;; Extraction call on &mut param = safe (user extracting from own coin)
          (return True)))
      ;; Also track if function has ANY extraction call
      (when (and (= (. fact name) "CallResult")
                 (= (get (. fact args) 0) f))
        (setv callee (get (. fact args) 3))
        (when (is_value_extraction_call callee)
          (setv has-any-extraction-call True))))
    ;; Fallback: Function-level suppression for user deposit pattern
    ;; If function has &mut Coin<T> param AND calls extraction, suppress ALL state_write sinks
    ;; This handles: 1) duplicate FQN case, 2) transitive sinks via callees
    ;; Rationale: User provides &mut Coin<T>, splits their own coin, deposits the result
    (when has-any-extraction-call
      (return True))

    ;; Pattern 2b: Extraction result flows to a different state write sink
    (setv extraction-results (_get-extraction-results f mut-params facts))
    (when extraction-results
      ;; Check if THIS sink receives value derived from extraction
      (when (_sink-receives-extracted-value? f stmt-id extraction-results facts)
        (return True))))

  False)

(defn has-unguarded-recipient-no-capability? [f facts ctx]
  "Check if function has tainted recipient NOT guarded by any role.
   Equivalent to: (and (tainted-recipient? f) (not (checks-role? f)))"
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (setv stmt-ids (_get-sink-stmt-ids f all-facts "transfer_recipient"))
  (any (gfor stmt-id stmt-ids
             (not (_sink-guarded-by-any-capability? f stmt-id all-facts)))))

(defn has-unguarded-recipient-no-auth? [f facts ctx]
  "Check if function has tainted recipient NOT guarded by sender OR role.
   Equivalent to: (and (tainted-recipient? f) (not (checks-sender? f)) (not (checks-role? f)))"
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (setv stmt-ids (_get-sink-stmt-ids f all-facts "transfer_recipient"))
  (any (gfor stmt-id stmt-ids
             (not (_sink-guarded-by-auth? f stmt-id all-facts)))))

(defn has-unguarded-state-write-no-auth? [f facts ctx]
  "Check if function has tainted state write NOT guarded by sender OR role.
   Excludes user deposit sinks (Coin/Balance -> balance::join) which are safe.
   Equivalent to: (and (tainted-state-write? f) (not (checks-sender? f)) (not (checks-role? f)))"
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (setv stmt-ids (_get-sink-stmt-ids f all-facts "state_write"))
  (any (gfor stmt-id stmt-ids
             (and (not (_sink-guarded-by-auth? f stmt-id all-facts))
                  (not (_is-user-deposit-sink? f stmt-id all-facts))))))

(defn has-unguarded-amount-no-auth? [f facts ctx]
  "Check if function has tainted amount extraction NOT guarded by sender OR role."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (setv stmt-ids (_get-sink-stmt-ids f all-facts "amount_extraction"))
  (any (gfor stmt-id stmt-ids
             (not (_sink-guarded-by-auth? f stmt-id all-facts)))))

(defn has-unguarded-sink-no-auth? [f facts ctx]
  "Check if function has ANY tainted sink NOT guarded by sender OR role.
   Equivalent to: (and (has-tainted-sink-in-callchain? f) (not (checks-sender? f)) (not (checks-role? f)))"
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (setv sink-types ["transfer_recipient" "transfer_value"
                    "state_write" "amount_extraction" "object_destroy"])
  (any (gfor sink-type sink-types
             (any (gfor stmt-id (_get-sink-stmt-ids f all-facts sink-type)
                        (not (_sink-guarded-by-auth? f stmt-id all-facts)))))))

(defn has-unguarded-sink-no-pause? [f facts ctx]
  "Check if function has ANY tainted sink NOT guarded by pause.
   For pause-check-missing rule.
   Uses transitive check: if func or any callee checks pause, all sinks are protected."
  ;; Transitive check: if any callee checks pause, function is protected
  (when (checks-pause*? f facts ctx)
    (return False))
  ;; Fall back to per-sink GuardedSink check
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (setv sink-types ["transfer_recipient" "transfer_value"
                    "state_write" "amount_extraction" "object_destroy"])
  (any (gfor sink-type sink-types
             (any (gfor stmt-id (_get-sink-stmt-ids f all-facts sink-type)
                        (not (_sink-guarded? f stmt-id "pause" all-facts)))))))

(defn has-unguarded-value-sink-no-pause? [f facts ctx]
  "Check if function has value transfer sink NOT guarded by pause.
   For admin-bypasses-pause rule.
   Excludes state_write (config updates are allowed during pause).
   Only flags actual value extraction/transfer operations."
  ;; Transitive check: if any callee checks pause, function is protected
  (when (checks-pause*? f facts ctx)
    (return False))
  ;; Only check value-related sinks (not state_write)
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (setv value-sink-types ["transfer_recipient" "transfer_value" "amount_extraction"])
  (any (gfor sink-type value-sink-types
             (any (gfor stmt-id (_get-sink-stmt-ids f all-facts sink-type)
                        (not (_sink-guarded? f stmt-id "pause" all-facts)))))))

;; ============================================================================
;; Capability Destruction
;; ============================================================================

(defn destroys-capability? [f facts ctx]
  "Check if function destroys a capability/role struct.
   Uses DestroysCapability fact generated from ObjectDestroySink + IsCapability."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (has-fact? all-facts "DestroysCapability" [f]))

(defn _has-ref-capability-param? [f all-facts]
  "Check if function has a capability parameter passed by REFERENCE (for auth).
   Reference params (&Cap or &mut Cap) are for authorization.
   By-value params (Cap) are being consumed/destroyed, not for auth."
  ;; Get all role types
  (setv role-types
    (set (lfor fact all-facts
               :if (= (. fact name) "IsCapability")
               (get (. fact args) 0))))
  ;; Check if any FormalArg is a reference to a role
  (any (gfor fact all-facts
             :if (and (= (. fact name) "FormalArg")
                      (= (get (. fact args) 0) f))
             (do
               (setv param-type (get (. fact args) 3))
               ;; Must be a reference type
               (when (.startswith param-type "&")
                 ;; Strip reference and generics
                 (setv stripped (.lstrip param-type "&"))
                 (setv stripped (if (.startswith stripped "mut ") (.lstrip stripped "mut ") stripped))
                 (setv clean-type (get (.split stripped "<") 0))
                 ;; Check if it's a role (by FQN or simple name)
                 (or (in clean-type role-types)
                     (any (gfor role role-types
                                (.endswith role (+ "::" clean-type))))))))))

(defn has-unguarded-capability-destroy? [f facts ctx]
  "Check if function destroys capability WITHOUT proper auth guard.

   A capability destroy is GUARDED if:
   - Function has a capability param passed by REFERENCE (& or &mut)
   - OR function has sender equality check

   A capability passed BY VALUE is being destroyed, NOT used for auth."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  ;; Check if function has DestroysCapability fact
  (setv has-destroy (has-fact? all-facts "DestroysCapability" [f]))
  (when (not has-destroy)
    (return False))
  ;; Check for authorization: ref capability param OR sender check
  (setv has-ref-cap (_has-ref-capability-param? f all-facts))
  (setv has-sender (has-fact? all-facts "HasSenderEqualityCheck" [f]))
  ;; Unguarded if no ref cap AND no sender check
  (not (or has-ref-cap has-sender)))

(defn has-capability-takeover? [f facts ctx]
  "Check if function enables capability takeover.

   A takeover occurs when:
   - Capability is owned by Deployer (created in init)
   - Function can transfer it to TxSender without authorization

   Uses CapabilityTakeover fact from cap_ir detection."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (has-fact? all-facts "CapabilityTakeover" [f]))

(defn get-takeover-cap-type [f facts ctx]
  "Get the capability type being taken over by function f.
   Returns None if no takeover detected."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (for [fact all-facts]
    (when (and (= (. fact name) "CapabilityTakeover")
               (= (get (. fact args) 0) f))
      (return (get (. fact args) 1))))
  None)

(defn has-phantom-type-mismatch? [f facts ctx]
  "Check if function has phantom type mismatch between cap guard and target.

   A mismatch occurs when:
   - Function has cap guard param with phantom type T: cap: &Cap<T>
   - Function operates on object with different phantom type U: obj: &mut Obj<U>
   - T != U means the cap doesn't actually guard the object

   Uses PhantomTypeMismatch fact from cap_ir detection."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (has-fact? all-facts "PhantomTypeMismatch" [f]))

(defn get-phantom-mismatch-details [f facts ctx]
  "Get phantom type mismatch details for function f.
   Returns dict with guard and target info, or None if no mismatch."
  (setv all-facts (+ facts (get-global-facts ctx f)))
  (for [fact all-facts]
    (when (and (= (. fact name) "PhantomTypeMismatch")
               (= (get (. fact args) 0) f))
      (return {"guard_param" (get (. fact args) 1)
               "guard_type" (get (. fact args) 2)
               "guard_phantom" (get (. fact args) 3)
               "target_param" (get (. fact args) 4)
               "target_type" (get (. fact args) 5)
               "target_phantom" (get (. fact args) 6)})))
  None)

(defn is-leaked-via-shared-object? [r facts ctx]
  "Check if role/capability r is stored in a shared object field.

   A capability leak occurs when:
   - A shared object has a field of this capability type
   - Anyone can access the shared object and thus the capability

   Uses CapabilityLeakViaStore fact from cap_ir detection.
   Note: r is the capability type, fact's 3rd arg (cap_type)."
  (setv all-facts (get-all-file-facts ctx))
  ;; Check if any CapabilityLeakViaStore has this cap type
  (for [fact all-facts]
    (when (= (. fact name) "CapabilityLeakViaStore")
      (setv cap-type (get (. fact args) 2))
      ;; Match by FQN or simple name
      (setv r-simple (if (in "::" r) (get (.split r "::") -1) r))
      (setv cap-simple (if (in "::" cap-type) (get (.split cap-type "::") -1) cap-type))
      (when (or (= r cap-type) (= r-simple cap-simple))
        (return True))))
  False)

(defn get-capability-leak-details [r facts ctx]
  "Get capability leak details for role r.
   Returns dict with shared_struct and field_name, or None if no leak."
  (setv all-facts (get-all-file-facts ctx))
  (setv r-simple (if (in "::" r) (get (.split r "::") -1) r))
  (for [fact all-facts]
    (when (= (. fact name) "CapabilityLeakViaStore")
      (setv cap-type (get (. fact args) 2))
      (setv cap-simple (if (in "::" cap-type) (get (.split cap-type "::") -1) cap-type))
      (when (or (= r cap-type) (= r-simple cap-simple))
        (return {"shared_struct" (get (. fact args) 0)
                 "field_name" (get (. fact args) 1)}))))
  None)

;; ============================================================================
;; Generic Type Properties
;; ============================================================================

(defn has-generic-param? [f facts ctx]
  "Check if function has generic type parameters."
  (has-fact? facts "HasGenericParam" [f]))

(defn validates-generic-type? [f facts ctx]
  "Check if ALL type params reaching sinks are validated or phantom-bound.

  A function is safe if:
  1. No UnvalidatedTypeAtSink AND no TypeReachesExtractionInCallers facts exist, OR
  2. All type params with UnvalidatedTypeAtSink or TypeReachesExtractionInCallers
     also have TypeValidated (direct or IPA validation)

  IPA validation (via callee) may add TypeValidated after UnvalidatedTypeAtSink was generated.
  TypeReachesExtractionInCallers indicates validation responsibility from caller context."
  (setv all-facts (get-global-facts ctx f))
  ;; Collect unvalidated type params for this function
  ;; This includes BOTH direct sinks AND validation responsibility from callers
  (setv unvalidated-types (set))
  (for [fact all-facts]
    (when (and (= (. fact name) "UnvalidatedTypeAtSink")
               (= (get (. fact args) 0) f))
      (.add unvalidated-types (get (. fact args) 1))))
  ;; Also add types from TypeReachesExtractionInCallers (validation responsibility)
  (for [fact all-facts]
    (when (and (= (. fact name) "TypeReachesExtractionInCallers")
               (= (get (. fact args) 0) f))
      (.add unvalidated-types (get (. fact args) 1))))
  ;; Collect validated type params for this function
  (setv validated-types (set))
  (for [fact all-facts]
    (when (and (= (. fact name) "TypeValidated")
               (= (get (. fact args) 0) f))
      (.add validated-types (get (. fact args) 1))))
  ;; Check if any phantom-bound types should also be considered validated
  (for [fact all-facts]
    (when (and (= (. fact name) "TypeBoundByPhantom")
               (= (get (. fact args) 0) f))
      (.add validated-types (get (. fact args) 1))))
  ;; Function is safe if all unvalidated types are also validated (via IPA or phantom)
  (.issubset unvalidated-types validated-types))

(defn extracted-value-returned? [f facts ctx]
  "Check if ALL type params' extracted values are returned (not transferred).

  A function is safe if ALL its type params have ExtractedValueReturned facts,
  meaning extracted values flow to return statements, not transfer sinks.

  This suppresses FPs for utility functions like:
    public fun extract<T>(balance: &mut Balance<T>): Coin<T> {
        coin::take(balance, amount, ctx)  // returned to caller
    }"
  (setv all-facts (get-global-facts ctx f))
  ;; Get type params for this function
  (setv type-params (set (gfor fact all-facts
                               :if (and (= (. fact name) "HasGenericParam")
                                        (= (get (. fact args) 0) f))
                               (get (. fact args) 2))))
  (when (not type-params)
    (return False))
  ;; Get type params with ExtractedValueReturned
  (setv returned-type-params (set (gfor fact all-facts
                                        :if (and (= (. fact name) "ExtractedValueReturned")
                                                 (= (get (. fact args) 0) f))
                                        (get (. fact args) 1))))
  ;; Safe if all type params have their extraction returned
  (.issubset type-params returned-type-params))

(defn type-reaches-extraction-in-callers? [f facts ctx]
  "Check if function's type params reach extraction sinks in callers.

  This enables detection of validation helpers that are called from extraction
  contexts but don't have extraction sinks themselves.

  Pattern: validate_withdraw<T> called from execute_withdraw<T> which has coin::take<T>.
  validate_withdraw doesn't extract, but its caller does - so it has validation responsibility."
  (setv all-facts (get-global-facts ctx f))
  (any (gfor fact all-facts
             (and (= (. fact name) "TypeReachesExtractionInCallers")
                  (= (get (. fact args) 0) f)))))

;; ============================================================================
;; Struct/Field Properties
;; ============================================================================

(defn is-capability? [r facts ctx]
  "Check if struct is a role/capability."
  (setv all-facts (get-all-file-facts ctx))
  (has-fact? all-facts "IsCapability" [r]))

(defn is-mutable-config-field? [struct field facts ctx]
  "Check if struct.field is classified as a mutable config field.
   Uses FieldClassification fact with category='mutable_config'."
  (setv all-facts (+ facts (get-all-file-facts ctx)))
  (for [fact all-facts]
    (when (and (= (. fact name) "FieldClassification")
               (= (len (. fact args)) 6)
               (= (get (. fact args) 0) struct)
               (= (get (. fact args) 1) field)
               (= (get (. fact args) 2) "mutable_config")
               (= (get (. fact args) 3) False))  ; negative=False means positive classification
      (return True)))
  False)

(defn is-protocol-invariant? [struct field facts ctx]
  "Check if struct.field is a protocol invariant (immutable by design).
   Uses FieldClassification fact with category='protocol_invariant'."
  (setv all-facts (+ facts (get-all-file-facts ctx)))
  (for [fact all-facts]
    (when (and (= (. fact name) "FieldClassification")
               (= (len (. fact args)) 6)
               (= (get (. fact args) 0) struct)
               (= (get (. fact args) 1) field)
               (= (get (. fact args) 2) "protocol_invariant")
               (= (get (. fact args) 3) False))  ; negative=False means positive classification
      (return True)))
  False)

(defn get-field-writers [struct field facts ctx]
  "Get all non-init functions that write to struct.field.
   Returns list of function names from WritesField/TransitiveWritesField facts."
  (setv all-facts (+ facts (get-all-file-facts ctx)))
  (setv writers [])
  ;; Collect init functions to exclude
  (setv init-funcs (set (gfor fact all-facts
                               :if (= (. fact name) "IsInit")
                               (get (. fact args) 0))))
  ;; Find writers
  (for [fact all-facts]
    (when (in (. fact name) ["WritesField" "TransitiveWritesField"])
      (setv writer-func (get (. fact args) 0))
      (setv write-struct (get (. fact args) 1))
      (setv write-field (get (. fact args) 2))
      ;; Match struct (by FQN or simple name)
      (setv struct-match (or (= write-struct struct)
                             (= write-struct (if (in "::" struct)
                                                 (get (.split struct "::") -1)
                                                 struct))
                             (= (if (in "::" write-struct)
                                    (get (.split write-struct "::") -1)
                                    write-struct)
                                struct)))
      ;; Match field (exact or top-level for nested paths)
      (setv field-match (or (= write-field field)
                            (= (get (.split write-field ".") 0) field)))
      (when (and struct-match field-match (not (in writer-func init-funcs)))
        (.append writers writer-func))))
  writers)

(defn has-privileged-setter? [struct field facts ctx]
  "Check if struct.field has a privileged setter function.
   First checks HasPrivilegedSetter fact (direct auth), then falls back to
   checking if any writer has transitive auth via checks-auth*?."
  (setv all-facts (+ facts (get-all-file-facts ctx)))
  ;; Fast path: check precomputed HasPrivilegedSetter fact (direct auth only)
  (when (has-fact? all-facts "HasPrivilegedSetter" [struct field])
    (return True))
  ;; Slow path: check if any writer has transitive auth
  (setv writers (get-field-writers struct field facts ctx))
  (for [writer writers]
    (when (checks-auth*? writer facts ctx)
      (return True)))
  False)

(defn is-user-asset? [struct-name facts ctx]
  "Check if struct is a user asset (NFT, receipt, ticket).
   User assets are intentionally immutable after creation.
   Uses IsUserAsset fact from LLM classification."
  (setv semantic-facts (get-semantic-facts ctx))
  (for [fact semantic-facts]
    (when (and (= (. fact name) "IsUserAsset")
               (= (len (. fact args)) 2)
               (= (get (. fact args) 1) True))
      (setv fact-struct (get (. fact args) 0))
      ;; Match by FQN or simple name
      (when (or (= struct-name fact-struct)
                (= struct-name (if (in "::" fact-struct) (get (.split fact-struct "::") -1) fact-struct)))
        (return True))))
  False)

(defn is-shared-object? [r facts ctx]
  "Check if struct is shared via transfer::share_object."
  (setv all-facts (get-all-file-facts ctx))
  (has-fact? all-facts "IsSharedObject" [r]))

(defn _strip-references [type-str]
  "Strip reference modifiers from type string.
   Mirrors move.types.strip_references() for use in Hy predicates.
   Examples: '&mut Pool' -> 'Pool', '&Pool' -> 'Pool', 'Pool' -> 'Pool'"
  (setv result type-str)
  (when (.startswith result "&mut ")
    (setv result (cut result 5 None)))
  (when (.startswith result "&")
    (setv result (cut result 1 None)))
  result)

(defn _parse-tuple-components [type-str]
  "Parse tuple components respecting nested angle brackets and parentheses.
   '(Coin<Balance<SUI>>, AdminCap)' -> ['Coin<Balance<SUI>>', 'AdminCap']
   '((Coin<SUI>, u64), AdminCap)' -> ['(Coin<SUI>, u64)', 'AdminCap']
   'AdminCap' -> [] (non-tuple returns empty list)
   Returns [] for malformed input (unbalanced brackets)."
  ;; C3 fix: Non-tuple input returns empty list
  (when (not (and (.startswith type-str "(") (.endswith type-str ")")))
    (return []))
  ;; Empty tuple case
  (when (< (len type-str) 2)
    (return []))
  (setv result [])
  (setv current "")
  (setv angle-depth 0)  ; Track <> nesting depth
  (setv paren-depth 0)  ; Track () nesting depth
  ;; Remove outer parentheses
  (setv inner (cut type-str 1 -1))
  (for [c inner]
    (cond
      (= c "<") (do (setv angle-depth (+ angle-depth 1)) (+= current c))
      (= c ">")
        (do
          (setv angle-depth (- angle-depth 1))
          ;; C4 fix: Negative depth means malformed input
          (when (< angle-depth 0) (return []))
          (+= current c))
      (= c "(") (do (setv paren-depth (+ paren-depth 1)) (+= current c))
      (= c ")")
        (do
          (setv paren-depth (- paren-depth 1))
          ;; C4 fix: Negative depth means malformed input
          (when (< paren-depth 0) (return []))
          (+= current c))
      (and (= c ",") (= angle-depth 0) (= paren-depth 0))
        (do
          (when (.strip current)
            (.append result (.strip current)))
          (setv current ""))
      True (+= current c)))
  ;; C5 fix: Unclosed brackets means malformed input
  (when (or (!= angle-depth 0) (!= paren-depth 0))
    (return []))
  (when (.strip current)
    (.append result (.strip current)))
  result)

(defn returns-privileged-type? [f facts ctx]
  "Check if function returns a privileged capability type.
   Cross-references FunReturnType with IsPrivileged.
   Handles tuple return types like (Treasury, AdminCap) and nested generics."
  (setv all-file-facts (get-all-file-facts ctx))
  ;; Get function's return type
  (setv return-type None)
  (for [fact facts]
    (when (and (= (. fact name) "FunReturnType")
               (= (get (. fact args) 0) f))
      (setv return-type (get (. fact args) 1))
      (break)))
  (when (is return-type None)
    (return False))
  ;; Strip module prefix from return type: "test::mod::(Coin<SUI>, AdminCap)" -> "(Coin<SUI>, AdminCap)"
  (setv tuple-start (.rfind return-type "::("))
  (setv return-type-clean
    (if (> tuple-start 0)
      (cut return-type (+ tuple-start 2) None)
      return-type))
  ;; Build FQN set for matching
  (setv privileged-fqns (set (gfor fact all-file-facts
                               :if (= (. fact name) "IsPrivileged")
                               (get (. fact args) 0))))
  ;; Strip reference prefix: FunReturnType may be "&Type" but IsPrivileged has "Type"
  (setv return-type-stripped (_strip-references return-type))
  ;; Non-tuple case: use FQN match only (simple name would cause false positives
  ;; when two modules have same-named but differently privileged structs)
  (when (in return-type-stripped privileged-fqns)
    (return True))
  ;; For tuple returns, parse components and match by simple name
  ;; (tuple components are simple names like "AdminCap", not FQNs)
  (when (.startswith return-type-clean "(")
    (setv components (_parse-tuple-components return-type-clean))
    ;; Build simple name set for tuple component matching
    (setv privileged-simple (set (gfor fqn privileged-fqns
                                   (_split-last fqn "::"))))
    (return (any (gfor comp components
                       (or (in comp privileged-fqns)
                           (in comp privileged-simple))))))
  False)

(defn is-factory-pattern? [f facts ctx]
  "Check if function is a factory that creates object + its capability.
   Factory pattern: function creates both a privileged capability AND a non-capability struct.
   This is a safe pattern where caller gets admin rights over objects they create."
  (setv all-file-facts (get-all-file-facts ctx))
  (setv all-facts (+ facts all-file-facts))
  ;; Get all structs this function packs
  (setv packed-structs (set (gfor fact all-facts
                              :if (and (= (. fact name) "PacksStruct")
                                       (= (get (. fact args) 0) f))
                              (get (. fact args) 1))))
  (when (not packed-structs)
    (return False))
  ;; Get all capability types (from IsCapability facts)
  (setv capabilities (set (gfor fact all-file-facts
                            :if (= (. fact name) "IsCapability")
                            (get (. fact args) 0))))
  ;; Factory pattern: creates BOTH a capability AND a non-capability struct
  (setv packs-cap (bool (& packed-structs capabilities)))
  (setv packs-non-cap (bool (- packed-structs capabilities)))
  (and packs-cap packs-non-cap))

