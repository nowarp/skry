;; Centralization Risk Rules
;;
;; Detects centralization risks where admin/privileged roles have excessive
;; power over user assets.

(require rules.hy.macros [defrule])
(import rules.hy.macros [fun])
(import rules.hy.bridge [llm-classify-arbitrary-drain?])
(import rules.hy.builtins [checks-privileged? writes-user-asset? tainted-recipient?
                           transfers-from-sender? transfers-from-shared-object?
                           project-category? is-public? is-entry? is-init?
                           checks-sender*? returns-coin-type? has-param-type?
                           emits-event? has-value-extraction?
                           is-pause-control? feature-pause?])

;; ---------------------------------------------------------------------------
;; admin_drain_risk - Admin can drain user assets
;; ---------------------------------------------------------------------------
;; Detects functions where admin role can transfer value from user asset
;; containers to arbitrary recipients.
(defrule admin-drain-risk
  :severity :high
  :categories [:centralization :access-control]
  :description "Admin-guarded function can drain user assets to arbitrary recipient"
  :match (fun :public :entry)
  :filter (and
            (checks-privileged? f facts ctx)            ;; Must be privileged-gated
            (writes-user-asset? f facts ctx)            ;; Must write to user asset container
            (tainted-recipient? f facts ctx)            ;; Must have tainted transfer recipient
            (not (transfers-from-sender? f facts ctx))  ;; Transfer must not go to sender (admin extracts)
            (not (is-init? f facts ctx)))               ;; Skip init functions
  :classify (llm-classify-arbitrary-drain? f facts ctx))

;; ---------------------------------------------------------------------------
;; centralized-reward-distribution - Admin picks lottery/game winners
;; ---------------------------------------------------------------------------
;; Gaming project where admin-controlled function distributes rewards to
;; admin-chosen recipients. No verifiable on-chain randomness - users must
;; trust the admin to be fair.
;; Impact: Unfair game - legitimate players never win.
(defrule centralized-reward-distribution
  :severity :medium
  :categories [:centralization :fairness]
  :description "Admin-controlled reward distribution - no verifiable winner selection"
  :match (fun :public)
  :filter (and
            (project-category? "gaming" facts ctx)        ;; Gaming/lottery/gambling project
            (checks-sender*? f facts ctx)                 ;; Admin-gated (transitive sender check)
            (transfers-from-shared-object? f facts ctx)   ;; Extracts from shared pool
            (has-param-type? f "address" facts ctx)       ;; Has address param = admin picks recipient
            (not (transfers-from-sender? f facts ctx))    ;; Not user withdrawing own funds
            (not (is-init? f facts ctx))))

;; ---------------------------------------------------------------------------
;; missing-admin-event - Privileged function without audit event
;; ---------------------------------------------------------------------------
;; Privileged functions that extract/transfer value should emit events.
;; Silent admin operations make abuse detection impossible.
;;
;; NOTE: Pure config setters are excluded to reduce noise. They're lower value
;; for audit - the state change itself is the record.
(defrule missing-admin-event
  :severity :info
  :categories [:centralization :audit-trail]
  :description "Privileged function extracts/transfers value without emitting event"
  :match (fun :public)
  :filter (and
            (checks-privileged? f facts ctx)              ;; Gated by privileged capability
            (or (has-value-extraction? f facts ctx)       ;; Extracts coins/balance
                (tainted-recipient? f facts ctx))         ;; or transfers to user address
            (not (emits-event? f facts ctx))              ;; No event emitted
            (not (is-init? f facts ctx))))
