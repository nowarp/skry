;; Access Control Rules
;;
;; Detects vulnerabilities related to missing or insufficient authorization checks.

(require rules.hy.macros [defrule])
(import rules.hy.macros [fun capability mutable-config-field])
(import rules.hy.builtins [is-init? is-entry? checks-capability? checks-sender? checks-privileged?
                           checks-capability*? checks-sender*? calls-sender?  ;; Transitive versions for IPA
                           has-transfer-sink? tainted-recipient? has-any-sink?
                           has-tainted-sink-in-callchain?
                           operates-on-owned-only? operates-on-shared-object?
                           operates-on-state-container?  ;; State container operations
                           transfers-user-provided-value? transfers-user-asset?
                           transfers-from-sender? transfers-from-shared-object? transfers-from-shared-object-direct?
                           is-deposit-pattern?  ;; User deposits Coin into shared storage
                           has-sender-equality-check?
                           has-sensitive-sink? has-direct-sensitive-sink? has-theft-sink? writes-user-asset?
                           returns-mutable-ref? returns-coin-type?
                           value-exchange-function?
                           is-privileged? has-mutable-config-param? is-friend? is-externally-callable?
                           is-state-container? is-state-field?
                           feature-pause? checks-pause? is-pause-control?
                           has-value-extraction?
                           operates-on-user-creatable?
                           creates-user-creatable?  ;; Function creates/shares user-creatable struct
                           writes-privileged-field?  ;; Writes to privileged/config field
                           accesses-user-owned-asset?
                           has-generic-param? validates-generic-type? extracted-value-returned?
                           has-value-extraction*? type-reaches-extraction-in-callers?
                           is-capability? is-shared-object? returns-privileged-type?
                           is-test-only? is-factory-pattern?
                           accesses-user-asset? has-mutable-param?
                           is-mutable-config-field? has-privileged-setter? is-protocol-invariant? is-user-asset?
                           ;; Per-sink guard predicates
                           has-unguarded-recipient-no-capability?
                           has-unguarded-recipient-no-auth?
                           has-unguarded-state-write-no-auth?
                           has-unguarded-amount-no-auth?
                           has-unguarded-sink-no-auth?
                           has-unguarded-sink-no-pause?
                           has-unguarded-value-sink-no-pause?
                           ;; Capability destruction
                           destroys-capability?
                           has-unguarded-capability-destroy?
                           ;; Capability takeover
                           has-capability-takeover?
                           ;; Phantom type mismatch
                           has-phantom-type-mismatch?
                           ;; Capability leak via store
                           is-leaked-via-shared-object?])
(import rules.hy.bridge [has-transfer-call? tainted-amount? tainted-state-write?
                         llm-classify-vulnerable? llm-classify-arbitrary-drain?
                         llm-classify-sensitive-setter?
                         creates-privileged-cap? requires-parent-cap?
                         verifies-ownership? transfers-privileged-to-tainted?
                         single-step-ownership?
                         has-internal-callers? llm-classify-internal-helper-exposure?])

;; ---------------------------------------------------------------------------
;; arbitrary_recipient_drain - Transfer to user-controlled address without auth
;; ---------------------------------------------------------------------------
(defrule arbitrary-recipient-drain
  :severity :critical
  :categories [:access-control :value-extraction]
  :description "Transfer to user-controlled address without authorization"
  :match (fun :public)
  :filter (and
            (is-externally-callable? f facts ctx) ;; Exclude public(friend)
            (has-mutable-param? f facts ctx)      ;; Skip read-only functions
            (has-transfer-call? f facts ctx)
            ;; Per-sink: tainted recipient without role guard
            (has-unguarded-recipient-no-capability? f facts ctx)
            (not (is-init? f facts ctx))

            ;; Safe patterns - skip if user's own funds
            (not (transfers-user-provided-value? f facts ctx))
            (not (transfers-user-asset? f facts ctx))

            ;; Dangerous pattern - extracts from shared object
            (transfers-from-shared-object? f facts ctx)))

;; ---------------------------------------------------------------------------
;; tainted_amount_drain - User-controlled amount enables drain
;; ---------------------------------------------------------------------------
(defrule tainted-amount-drain
  :severity :high
  :categories [:access-control :input-validation :value-extraction]
  :description "User-controlled amount in coin::take enables drain"
  :match (fun :public :entry)
  :filter (and (tainted-amount? f facts ctx)
               (not (checks-capability? f facts ctx))
               (not (checks-sender*? f facts ctx))
               (not (transfers-user-provided-value? f facts ctx))
               (not (is-deposit-pattern? f facts ctx))  ;; Skip deposits (user provides Coin)
               (or (transfers-from-shared-object-direct? f facts ctx)
                   (not (transfers-from-sender? f facts ctx)))))

;; ---------------------------------------------------------------------------
;; tainted_state_modification - Unauth state writes
;; ---------------------------------------------------------------------------
;; Uses per-sink guard: has-unguarded-state-write-no-auth? checks if state write
;; sink is NOT protected by sender OR role.
(defrule tainted-state-modification
  :severity :high
  :categories [:access-control :state-corruption]
  :description "User-controlled data written to state without authorization"
  :match (fun :public :entry)
  :filter (and
            ;; Per-sink: tainted state write without auth guard
            ;; (excludes user deposit sinks: Coin/Balance -> balance::join)
            (has-unguarded-state-write-no-auth? f facts ctx)
            (not (is-init? f facts ctx))
            (not (operates-on-user-creatable? f facts ctx))
            ;; Creates user-creatable struct is only safe if no value extraction
            ;; AND no writes to privileged fields (create-and-corrupt pattern)
            (not (and (creates-user-creatable? f facts ctx)
                      (not (has-value-extraction? f facts ctx))
                      (not (writes-privileged-field? f facts ctx))))))

;; ---------------------------------------------------------------------------
;; missing-authorization - Entry function with dangerous sink, no auth check
;; ---------------------------------------------------------------------------
(defrule missing-authorization
  :severity :critical
  :categories [:access-control]
  :description "Entry function performs sensitive operation on shared state without authorization"
  :match (fun :public :entry)
  :filter (and
            (has-mutable-param? f facts ctx)     ;; Skip read-only functions
            ;; Per-sink: any tainted sink without auth guard
            (has-unguarded-sink-no-auth? f facts ctx)
            (not (is-init? f facts ctx))         ;; init only runs once

            ;; Skip safe ownership patterns
            (not (operates-on-owned-only? f facts ctx))        ;; only touches owned objects
            (not (operates-on-user-creatable? f facts ctx))    ;; user-mintable structs
            ;; Creates user-creatable struct is only safe if no value extraction
            ;; AND no writes to privileged fields (create-and-corrupt pattern)
            (not (and (creates-user-creatable? f facts ctx)
                      (not (has-value-extraction? f facts ctx))
                      (not (writes-privileged-field? f facts ctx))))
            (not (transfers-user-provided-value? f facts ctx)) ;; transfers user's Coin/Balance
            (not (transfers-user-asset? f facts ctx)))         ;; transfers user's receipt/ticket
  :classify (llm-classify-vulnerable? f facts ctx))

;; ---------------------------------------------------------------------------
;; unauth_sensitive_setter - Modifies shared state without auth
;; ---------------------------------------------------------------------------
;; Detects public functions that modify protocol-wide configuration on shared
;; objects without any role/capability check. Catches setters that dont have
;; transfer/extraction sinks (those are handled by missing-authorization).
(defrule unauth-sensitive-setter
  :severity :high
  :categories [:access-control :state-corruption]
  :description "Modifies shared protocol state without authorization"
  :match (fun :public)
  :filter (and
            (has-mutable-param? f facts ctx)         ;; Skip read-only functions
            (operates-on-shared-object? f facts ctx) ;; Must operate on shared object

            ;; Skip if protected by auth
            (not (checks-capability? f facts ctx))
            (not (checks-privileged? f facts ctx))
            (not (checks-sender? f facts ctx))
            (not (is-init? f facts ctx))
            (not (is-friend? f facts ctx))            ;; public(package) is internal

            (not (has-sensitive-sink? f facts ctx))   ;; Skip if has sensitive sink (handled by other rules)

            ;; Skip user-owned state
            (not (operates-on-user-creatable? f facts ctx))
            (not (writes-user-asset? f facts ctx)))
  :classify (llm-classify-sensitive-setter? f facts ctx))

;; ---------------------------------------------------------------------------
;; mutable-ref-escape - Internal state exposure via &mut return
;; ---------------------------------------------------------------------------
;; Public function returns &mut T to internal state.
;; Caller can modify protocol state directly, bypassing all access controls.
(defrule mutable-ref-escape
  :severity :high
  :categories [:access-control :state-corruption]
  :description "Public function returns mutable reference to internal state"
  :match (fun :public)
  :filter (and
            (returns-mutable-ref? f facts ctx)       ;; Returns &mut T
            (operates-on-shared-object? f facts ctx) ;; Operates on shared object (not owned)
            (not (checks-capability? f facts ctx))   ;; LLM-classified role param
            (not (checks-privileged? f facts ctx))   ;; LLM-classified privileged role
            (not (is-init? f facts ctx))
            (not (is-friend? f facts ctx))))         ;; public(package) is internal

;; ---------------------------------------------------------------------------
;; user-asset-write-without-ownership - Write to user's assets without ownership proof
;; ---------------------------------------------------------------------------
;; Function writes to user asset container without verifying caller owns it.
;; Attacker can modify/steal other users' deposited assets.
(defrule user-asset-write-without-ownership
  :severity :critical
  :categories [:access-control :theft]
  :description "Writes to user asset container without verifying caller ownership"
  :match (fun :public :entry)
  :filter (and
            (has-mutable-param? f facts ctx)     ;; Skip read-only functions
            ;; Writes to user asset container (direct param check)
            (writes-user-asset? f facts ctx)

            ;; Skip if ownership verified - check transitively for IPA
            (not (checks-sender*? f facts ctx))                 ;; owner == sender (self or callee)
            (not (transfers-user-provided-value? f facts ctx))  ;; source is user's owned Coin/Balance

            ;; Skip if protected by auth - check transitively for IPA
            (not (checks-capability*? f facts ctx))           ;; role check (self or callee)

            ;; Skip owned objects - Sui runtime enforces only owner can pass &mut
            (not (operates-on-owned-only? f facts ctx))
            (not (is-init? f facts ctx)))
  :classify (llm-classify-vulnerable? f facts ctx))

;; ---------------------------------------------------------------------------
;; returns-coin-without-auth - Public function returns Coin/Balance without auth
;; ---------------------------------------------------------------------------
;; Public function returns Coin<T> or Balance<T> without capability check.
;; Attacker can call function to extract protocol funds.
(defrule returns-coin-without-auth
  :severity :high
  :categories [:access-control :value-extraction]
  :description "Public function returns Coin/Balance without authorization check"
  :match (fun :public)
  :filter (and
            (returns-coin-type? f facts ctx) ;; Returns Coin/Balance/Token

            ;; Skip if protected by auth (transitive - checks callees too)
            (not (checks-capability*? f facts ctx)) ;; LLM-classified role param
            (not (checks-privileged? f facts ctx))  ;; LLM-classified privileged role
            (not (checks-sender*? f facts ctx))     ;; sender equality check
            (not (calls-sender? f facts ctx))       ;; PTB helper pattern (uses sender for implicit auth)
            (not (is-init? f facts ctx))
            (not (is-friend? f facts ctx))

            ;; Skip safe patterns
            (not (transfers-from-sender? f facts ctx))     ;; user's own funds
            (not (operates-on-owned-only? f facts ctx))    ;; only owned objects
            (not (value-exchange-function? f facts ctx)))) ;; swap/refund pattern

;; ---------------------------------------------------------------------------
;; config-write-without-privileged - Modifies config struct without privileged check
;; ---------------------------------------------------------------------------
;; Public function takes &mut Config parameter without privileged capability.
;; Attacker can modify protocol configuration (fees, limits, oracles, etc.).
(defrule config-write-without-privileged
  :severity :high
  :categories [:access-control :state-corruption]
  :description "Modifies protocol config without privileged authorization"
  :match (fun :public)
  :filter (and
            (has-mutable-config-param? f facts ctx) ;; Has &mut param to config struct
            (not (checks-capability? f facts ctx))  ;; Role param
            (not (checks-sender? f facts ctx))      ;; tx_context::sender check
            (not (is-init? f facts ctx))
            (not (is-friend? f facts ctx))))

;; ---------------------------------------------------------------------------
;; pause-check-missing - Sensitive op doesn't check global pause
;; ---------------------------------------------------------------------------
;; Protocol has global pause but sensitive function doesn't check it.
(defrule pause-check-missing
  :severity :high
  :categories [:access-control :emergency-response]
  :description "Sensitive operation doesn't check global pause"
  :match (fun :public :entry)
  :filter (and
            (feature-pause? facts ctx)                  ;; Has global pause mechanism
            ;; Per-sink: any tainted sink without pause guard
            (has-unguarded-sink-no-pause? f facts ctx)
            (not (is-init? f facts ctx))                ;; Skip init (runs once, no pause needed)
            (not (checks-capability? f facts ctx))))    ;; Skip role-gated (reported by admin-bypasses-pause)

;; ---------------------------------------------------------------------------
;; admin-bypasses-pause - Admin function ignores global pause
;; ---------------------------------------------------------------------------
;; Admin-gated functions can operate even when protocol is paused.
;; This may be intentional (emergency recovery) but is a centralization risk.
;; Only flags functions with VALUE sinks (transfer/extraction), not config setters.
(defrule admin-bypasses-pause
  :severity :info
  :categories [:centralization :emergency-response]
  :description "Admin function can operate during pause (centralization risk)"
  :match (fun :public)
  :filter (and
            (feature-pause? facts ctx)                         ;; Has global pause mechanism
            (checks-capability? f facts ctx)                   ;; Admin-gated function
            (has-unguarded-value-sink-no-pause? f facts ctx)   ;; Value sink without pause guard
            (not (is-init? f facts ctx))))                     ;; Skip init

;; ---------------------------------------------------------------------------
;; unprotected-pause - Pause control without authorization
;; ---------------------------------------------------------------------------
;; Function that can pause/unpause the protocol is publicly accessible without
;; admin authorization.
(defrule unprotected-pause
  :severity :critical
  :categories [:access-control :emergency-response]
  :description "Pause control function lacks authorization check"
  :match (fun :public)
  :filter (and
            (feature-pause? facts ctx)              ;; Has global pause mechanism
            (is-pause-control? f facts ctx)         ;; Function controls pause state
            (not (checks-capability? f facts ctx))  ;; No authorization check
            (not (is-init? f facts ctx))))          ;; Skip init

;; ---------------------------------------------------------------------------
;; missing-destroy-guard - Capability destruction without authorization
;; ---------------------------------------------------------------------------
;; Entry function that destroys capabilities without authorization checks.
(defrule missing-destroy-guard
  :severity :critical
  :categories [:access-control :dos]
  :description "Capability destroyed without authorization check"
  :match (fun :public :entry)
  :filter (and
            (destroys-capability? f facts ctx)              ;; Destroys a capability struct
            (has-unguarded-capability-destroy? f facts ctx) ;; Destroy not guarded by auth
            (not (is-init? f facts ctx))))                  ;; Skip init

;; ---------------------------------------------------------------------------
;; capability-takeover - Capability can be acquired by unauthorized address
;; ---------------------------------------------------------------------------
;; Entry function that allows transferring deployer-owned capability to TxSender.
(defrule capability-takeover
  :severity :critical
  :categories [:access-control :privilege-escalation]
  :description "Capability can be acquired by unauthorized address"
  :match (fun :public :entry)
  :filter (and
            (has-capability-takeover? f facts ctx)          ;; Has takeover path
            (not (is-init? f facts ctx))))                  ;; Skip init

;; ---------------------------------------------------------------------------
;; phantom-type-mismatch - Capability guard uses different phantom type than target
;; ---------------------------------------------------------------------------
;; Function has capability guard with phantom type T but operates on object with
;; different phantom type U. The capability doesn't actually protect the object.
(defrule phantom-type-mismatch
  :severity :critical
  :categories [:access-control :type-safety]
  :description "Capability guard phantom type differs from target object phantom type"
  :match (fun :public :entry)
  :filter (and
            (has-phantom-type-mismatch? f facts ctx)        ;; Guard/target phantom types differ
            (not (is-init? f facts ctx))))                  ;; Skip init

;; ---------------------------------------------------------------------------
;; capability-leak-via-store - Capability stored in shared object field
;; ---------------------------------------------------------------------------
;; A capability is stored as a field in a shared object. Since shared objects
;; are accessible to anyone, the capability becomes publicly accessible.
;; Attack: Access shared object to obtain stored admin capability.
;; Impact: Complete bypass of access control - anyone can use the capability.
(defrule capability-leak-via-store
  :severity :critical
  :categories [:access-control :initialization]
  :description "Capability stored in shared object field (accessible to anyone)"
  :match (capability)
  :filter (is-leaked-via-shared-object? f facts ctx))

;; ---------------------------------------------------------------------------
;; generic-type-mismatch - Generic type parameter without validation
;; ---------------------------------------------------------------------------
;; Public function with generic <T> parameter that extracts value without
;; validating T via type_name::get<T>(). Attacker can call with arbitrary type
;; to extract unexpected coin types.
(defrule generic-type-mismatch
  :severity :critical
  :categories [:access-control :type-safety]
  :description "Generic type parameter used without type_name::get validation"
  :match (fun :public)
  :filter (and
            (has-generic-param? f facts ctx)
            ;; Flag functions with extraction OR validation responsibility from callers
            (or (has-value-extraction*? f facts ctx)
                (type-reaches-extraction-in-callers? f facts ctx))
            (not (validates-generic-type? f facts ctx))
            (not (checks-capability? f facts ctx))
            (not (is-init? f facts ctx))
            ;; Exclude utility functions where extraction is returned (not transferred)
            (not (extracted-value-returned? f facts ctx))
            ;; Exclude read-only lookup functions (no &mut params)
            (has-mutable-param? f facts ctx)))

;; ---------------------------------------------------------------------------
;; shared-capability-exposure - Admin capability exposed as shared object
;; ---------------------------------------------------------------------------
;; Role/capability struct is shared via transfer::share_object instead of
;; transfer::transfer. This gives everyone unrestricted access to privileged
;; operations, effectively making the capability meaningless.
(defrule shared-capability-exposure
  :severity :critical
  :categories [:access-control :initialization]
  :description "Admin capability shared instead of transferred to owner"
  :match (capability)
  :filter (and
            (is-capability? f facts ctx)
            (is-shared-object? f facts ctx)
            (not (is-state-container? f facts ctx))))

;; ---------------------------------------------------------------------------
;; test-only-missing - Public function returns privileged capability without #[test_only]
;; ---------------------------------------------------------------------------
;; Public function creates/returns privileged capability without auth check
;; and without #[test_only] attribute.
(defrule test-only-missing
  :severity :critical
  :categories [:access-control :testing]
  :description "Public function returns privileged capability without #[test_only]"
  :match (fun :public)
  :filter (and
            (has-mutable-param? f facts ctx)        ;; Skip read-only functions
            (returns-privileged-type? f facts ctx)  ;; Returns privileged type (LLM-generated)
            (not (is-test-only? f facts ctx))       ;; Missing #[test_only]
            (not (is-init? f facts ctx))            ;; init() is allowed
            (not (checks-capability? f facts ctx))) ;; No role authorization
  :classify (llm-classify-vulnerable? f facts ctx))

;; ---------------------------------------------------------------------------
;; privilege-escalation - Public function creates privileged cap without parent cap
;; ---------------------------------------------------------------------------
;; Public function creates privileged capability without requiring parent
;; capability. This allows unauthorized privilege escalation.
(defrule privilege-escalation
  :severity :high
  :categories [:access-control :privilege-escalation]
  :description "Public function creates privileged capability without parent authorization"
  :match (fun :public)
  :filter (and
            (creates-privileged-cap? f facts ctx)     ;; Creates privileged capability
            (not (requires-parent-cap? f facts ctx))  ;; Does NOT require parent cap
            (not (is-init? f facts ctx))              ;; init is allowed
            (not (is-factory-pattern? f facts ctx)))) ;; Factory pattern is safe

;; ---------------------------------------------------------------------------
;; capability-leakage - Public function returns/transfers privileged type without checks
;; ---------------------------------------------------------------------------
;; Public function returns or transfers privileged capability to user-controlled
;; recipient without proper authorization. This leaks admin privileges.
(defrule capability-leakage
  :severity :high
  :categories [:access-control :capability-leak]
  :description "Public function returns or transfers privileged capability without authorization"
  :match (fun :public)
  :filter (and
            (or (returns-privileged-type? f facts ctx)
                (transfers-privileged-to-tainted? f facts ctx))
            (not (is-friend? f facts ctx))           ;; public(friend) is internal
            (not (checks-privileged? f facts ctx))   ;; No privileged cap check
            (not (is-init? f facts ctx))))           ;; init is allowed

;; ---------------------------------------------------------------------------
;; single-step-ownership - Privileged cap transferred without two-step confirmation
;; ---------------------------------------------------------------------------
;; Detects functions that transfer admin/owner capabilities in a single step
;; without requiring confirmation from the recipient.
(defrule single-step-ownership
  :severity :high
  :categories [:access-control :ownership-transfer]
  :description "Admin capability transferred without two-step confirmation"
  :match (fun :public)
  :filter (and
            (not (is-friend? f facts ctx))
            (not (is-init? f facts ctx))
            (single-step-ownership? f facts ctx)))

;; ---------------------------------------------------------------------------
;; cross-user-asset-theft - Public entry accesses user assets without ownership verification
;; ---------------------------------------------------------------------------
;; Public entry function accesses (reads/writes) user asset containers without
;; verifying caller owns the asset. Attacker can steal other users' assets.
(defrule cross-user-asset-theft
  :severity :high
  :categories [:access-control :theft :user-assets]
  :description "Public entry accesses user assets without ownership verification"
  :match (fun :public :entry)
  :filter (and
            (has-mutable-param? f facts ctx)             ;; Skip read-only functions
            (accesses-user-owned-asset? f facts ctx)     ;; Accesses user-owned asset (has ownership field)
            (not (verifies-ownership? f facts ctx))      ;; Does not verify ownership
            (not (checks-capability? f facts ctx))       ;; No admin capability check
            (not (operates-on-owned-only? f facts ctx))  ;; Not operating on owned-only objects
            (has-theft-sink? f facts ctx))               ;; Has theft sink (transfer/extract, not deposit)
  :classify (llm-classify-vulnerable? f facts ctx))

;; ---------------------------------------------------------------------------
;; missing-mutable-config-setter - Mutable config field with no privileged setter
;; ---------------------------------------------------------------------------
;; Mutable config fields (fee rates, admin addresses, limits) should have
;; privileged setter functions. Missing setters mean the protocol is stuck
;; with initial values forever, unable to adapt to changing conditions.
(defrule missing-mutable-config-setter
  :severity :medium
  :categories [:access-control :configuration]
  :description "Mutable config field has no privileged setter function"
  :match (mutable-config-field)
  :filter (and
            ;; Field is classified as mutable config (should be adjustable)
            (is-mutable-config-field? ?struct ?field facts ctx)
            ;; NOT a protocol invariant (immutable by design)
            (not (is-protocol-invariant? ?struct ?field facts ctx))
            ;; NOT a user asset (NFTs, receipts - intentionally immutable)
            (not (is-user-asset? ?struct facts ctx))
            ;; But has NO privileged setter
            (not (has-privileged-setter? ?struct ?field facts ctx))))

;; ---------------------------------------------------------------------------
;; mutable-protocol-invariant - Protocol invariant modified outside init
;; ---------------------------------------------------------------------------
;; Protocol invariants (exchange rates, decimals, conversion ratios) are values
;; that users expect to be immutable by design. Modifying them after init
;; breaks user trust and can cause financial losses.
(defrule mutable-protocol-invariant
  :severity :high
  :categories [:state-corruption :protocol-invariants]
  :description "Protocol invariant field modified outside init"
  :match (writes-protocol-invariant)
  :filter True)

;; ---------------------------------------------------------------------------
;; sensitive-internal-public-exposure - Internal helper exposed as public
;; ---------------------------------------------------------------------------
;; Detects internal helper functions that:
;; 1. Are called internally (have callers within the package)
;; 2. Handle sensitive operations (balance mutations, state updates)
;; 3. But have `public` visibility instead of `public(friend)` or `public(package)`
;;
;; Based on audit findings: V-VLT-VUL-001, POOL-01, STG-03
;;
;; TODO: Package detection uses first path component (e.g., "mypackage::module::func" -> "mypackage").
;;       This is a heuristic; multi-level package names may not be detected correctly but no these
;;       cases found in production yet.
(defrule sensitive-internal-public-exposure
  :severity :high
  :categories [:access-control :visibility]
  :description "Internal helper function exposed as public without access control"
  :match (fun :public)
  :filter (and
            (has-mutable-param? f facts ctx)  ;; Skip read-only functions
            ;; Core visibility checks
            (not (is-friend? f facts ctx))
            (not (is-entry? f facts ctx))  ;; Entry functions are user-facing, not internal helpers
            (not (is-init? f facts ctx))
            (not (is-test-only? f facts ctx))

            ;; Has internal callers (proves it's designed as internal)
            (has-internal-callers? f facts ctx)

            ;; No authorization
            (not (checks-capability? f facts ctx))
            (not (checks-sender? f facts ctx))

            ;; Performs direct sensitive operation (excludes IPA-propagated sinks)
            (has-direct-sensitive-sink? f facts ctx)

            ;; Exclude safe patterns
            (not (operates-on-owned-only? f facts ctx))
            ;; NOTE: Don't filter transfers-user-provided-value - deposit helpers should still be flagged
            ;; The vulnerability is exposure of internal helpers, not what they do with user input
            (not (is-factory-pattern? f facts ctx))
            (not (value-exchange-function? f facts ctx))
            (not (returns-privileged-type? f facts ctx)))
  :classify (llm-classify-internal-helper-exposure? f facts ctx))
