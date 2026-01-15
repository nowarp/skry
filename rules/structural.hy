;; Structural Rules
;;
;; Detects control flow and structural issues: double init, missing operations,
;; resource safety violations.

(require rules.hy.macros [defrule])
(import rules.hy.macros [fun])
(import rules.hy.bridge [double-init?
                         self-recursive? tainted-loop-bound?
                         version-check-inconsistent?
                         llm-classify-missing-transfer?
                         has-transfer-call? transfers-to-zero-address?
                         py-weak-randomness?])
(import rules.hy.builtins [has-mutable-param? is-public? is-entry? is-init?
                           has-transfer? has-value-extraction? returns-coin-type?
                           has-transfer*? has-value-extraction*?
                           checks-privileged? feature-version? is-friend?])

;; ---------------------------------------------------------------------------
;; double_init - Non-init function calls module init
;; ---------------------------------------------------------------------------
;; Detects when a public/entry function can trigger module re-initialization.
;; Module init should only be called by Sui runtime on publish.
(defrule double-init
  :severity :high
  :categories [:initialization :state-corruption]
  :description "Public function calls module init (re-initialization risk)"
  :match (fun)
  :filter (double-init? f facts ctx))

;; ---------------------------------------------------------------------------
;; missing_transfer - Value extraction without transfer
;; ---------------------------------------------------------------------------
;; Pre-filters: has value extraction (coin::take, balance::split, etc.),
;; no transfer sink, doesn't return Coin type, public/entry, not init
;; LLM determines if value actually reaches recipient through callees or other means
(defrule missing-transfer
  :severity :high
  :categories [:value-extraction :logic-error]
  :description "Value extraction without transfer to recipient"
  :match (fun :public)
  :filter (and
            (has-value-extraction*? f facts ctx)    ;; Must have value extraction sink (transitive)
            (not (has-transfer*? f facts ctx))      ;; No transfer sink in function or callees (transitive)
            (not (returns-coin-type? f facts ctx))  ;; Function doesn't return Coin/Balance
            (not (is-init? f facts ctx)))           ;; Skip init functions
  :classify (llm-classify-missing-transfer? f facts ctx))

;; ---------------------------------------------------------------------------
;; self_recursion - Self-recursive public function
;; ---------------------------------------------------------------------------
;; Self-recursive public function can lead to stack overflow or DoS.
;; Checks all public functions (entry and non-entry) since non-entry public
;; functions can be called from entry points in other modules.
(defrule self-recursion
  :severity :medium
  :categories [:dos :code-quality]
  :description "Self-recursive public function - potential stack overflow or DoS"
  :match (fun :public)
  :filter (self-recursive? f facts ctx))

;; ---------------------------------------------------------------------------
;; unbounded_loop - Loop bound controlled by user input
;; ---------------------------------------------------------------------------
(defrule unbounded-loop
  :severity :high
  :categories [:dos :gas-exhaustion]
  :description "Loop bound controlled by user input - potential DoS via gas exhaustion"
  :match (fun)
  :filter (and (is-public f)
               (is-entry f)
               (tainted-loop-bound? f facts ctx)))

;; ---------------------------------------------------------------------------
;; version_check_missing - Inconsistent version checks
;; ---------------------------------------------------------------------------
(defrule version-check-missing
  :severity :high
  :categories [:security :consistency :upgrade]
  :description "Public entry function missing version check while other module functions check version"
  :match (fun :entry)
  :filter (and (feature-version? facts ctx)
               (has-mutable-param? f facts ctx)
               (not (checks-privileged? f facts ctx))
               (not (is-init? f facts ctx))
               (version-check-inconsistent? f facts ctx)))

;; ---------------------------------------------------------------------------
;; weak_randomness - Predictable randomness source
;; ---------------------------------------------------------------------------
(defrule weak-randomness
  :severity :high
  :categories [:cryptographic :randomness]
  :description "Predictable values used as randomness (timestamp, epoch, sender)"
  :match (fun :public :entry)
  :filter (py-weak-randomness? f facts ctx))

;; ---------------------------------------------------------------------------
;; zero_address_sink - Transfer to zero address loses funds
;; ---------------------------------------------------------------------------
(defrule zero-address-sink
  :severity :high
  :categories [:asset-safety :value-extraction]
  :description "Value transferred to zero address is permanently lost"
  :match (fun :public)
  :filter (and (not (is-friend? f facts ctx))
               (has-transfer-call? f facts ctx)
               (transfers-to-zero-address? f facts ctx)))
