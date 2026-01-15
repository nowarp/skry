;; Core macros for Skry rule DSL
;;
;; Usage:
;;   (require rules.hy.macros [defrule defprop])
;;   (import rules.hy.macros [fun capability event const])
;;
;;   (defrule my-rule
;;     :severity :high
;;     :match (fun :public :entry)
;;     :filter (and (transfers f)              ; Fact lookup - lispy-case, no 'facts ctx'
;;                  (not (is-init f)))          ; Structural checks only
;;     :classify (llm-classify? f facts ctx))  ; LLM/semantic checks (optional)

(import hy.models [Keyword Symbol Expression List])

;; ---------------------------------------------------------------------------
;; Internal helpers
;; ---------------------------------------------------------------------------

(defn _keyword-name [x]
  "Get name from keyword/symbol/string."
  (cond
    (isinstance x Keyword) (. x name)
    (isinstance x Symbol) (str x)
    True (str x)))

(defn _lispy-to-camel [s]
  "Convert lispy-case to CamelCase: is-public -> IsPublic"
  (setv parts (.split s "-"))
  (.join "" (lfor p parts (.capitalize p))))

;; Special forms that should NOT be treated as fact lookups
(setv _SPECIAL_FORMS #{"and" "or" "not" "if" "when" "cond" "let" "do" "setv"})

(defn _is-fact-lookup [expr]
  "Check if expression is a fact lookup (not a function call).

   Function calls end with 'facts ctx' args: (check? f facts ctx)
   Fact lookups don't: (is-public f) or (tainted-transfer-recipient f _ _)
   Special forms (and, or, not, etc.) are NOT fact lookups.
  "
  (when (not (isinstance expr Expression))
    (return False))
  (when (< (len expr) 2)
    (return False))
  ;; Check head - special forms are not fact lookups
  (setv head (get expr 0))
  (when (and (isinstance head Symbol)
             (in (str head) _SPECIAL_FORMS))
    (return False))
  ;; Check if last two args are 'facts' and 'ctx'
  (setv args (list (cut expr 1 None)))
  (when (< (len args) 2)
    ;; Less than 2 args - could be fact lookup
    (return True))
  ;; Check last two args
  (setv last-two (cut args -2 None))
  (setv is-func-call (and (= (len last-two) 2)
                          (isinstance (get last-two 0) Symbol)
                          (isinstance (get last-two 1) Symbol)
                          (= (str (get last-two 0)) "facts")
                          (= (str (get last-two 1)) "ctx")))
  (not is-func-call))

(defn _is-wildcard [x]
  "Check if x is wildcard symbol _"
  (and (isinstance x Symbol)
       (= (str x) "_")))

(defn _transform-fact-args [args]
  "Transform fact arguments, filtering wildcards."
  (lfor a args :if (not (_is-wildcard a)) a))

(defn _replace-symbols [expr replacements]
  "Replace symbols in expression according to replacements dict.
   replacements: {\"?struct\": new-symbol, \"?field\": new-symbol}"
  (cond
    ;; Symbol - check for replacement
    (isinstance expr Symbol)
      (let [s (str expr)]
        (if (in s replacements)
          (get replacements s)
          expr))
    ;; Expression - recurse
    (isinstance expr Expression)
      (Expression (lfor e expr (_replace-symbols e replacements)))
    ;; List - recurse
    (isinstance expr List)
      (List (lfor e expr (_replace-symbols e replacements)))
    ;; Anything else - return as-is
    True expr))

(defn _transform-clause [expr]
  "Transform fact lookups in filter/classify clauses.

   Fact lookups like (is-public f) become:
   (has-fact? facts \"IsPublic\" [f])

   Detection: expressions NOT ending with 'facts ctx' are fact lookups.
   Conversion: lispy-case -> CamelCase (is-public -> IsPublic)
   Wildcards _ are filtered out for prefix matching.
  "
  (cond
    ;; Expression (function call or fact lookup)
    (isinstance expr Expression)
      (if (> (len expr) 0)
        (let [head (get expr 0)]
          (if (and (isinstance head Symbol)
                   (_is-fact-lookup expr))
            ;; Fact lookup - convert lispy-case to CamelCase
            (let [fact-name (_lispy-to-camel (str head))
                  args (cut expr 1 None)
                  filtered-args (_transform-fact-args args)]
              ;; Generate has-fact? call
              `(has-fact? facts ~fact-name [~@filtered-args]))
            ;; Function call - recurse into args
            (Expression (lfor e expr (_transform-clause e)))))
        expr)
    ;; List - recurse
    (isinstance expr List)
      (List (lfor e expr (_transform-clause e)))
    ;; Anything else - return as-is
    True expr))

;; ---------------------------------------------------------------------------
;; Pattern helper functions - return dicts describing what to match
;; ---------------------------------------------------------------------------

(defn fun [#* modifiers]
  "Match functions with optional modifiers (:public, :entry)."
  {:type "fun" :modifiers (list (map _keyword-name modifiers))})

(defn capability []
  "Match capability structs."
  {:type "capability" :modifiers []})

(defn event []
  "Match event structs."
  {:type "event" :modifiers []})

(defn const []
  "Match module constants."
  {:type "const" :modifiers []})

(defn mutable-config-field []
  "Match mutable config fields (struct.field pairs from IsMutableConfigField facts)."
  {:type "mutable-config-field" :modifiers []})

(defn writes-protocol-invariant []
  "Match protocol invariant violations (func, struct, field triples from WritesProtocolInvariant facts)."
  {:type "writes-protocol-invariant" :modifiers []})

(defn _parse-match-spec [match-spec]
  "Parse match spec into [pattern modifiers].

   Supports two formats:
   - New: (fun :public :entry) -> dict with :type and :modifiers
   - Legacy: [:public :entry] -> list of keywords (assumes fun)
  "
  ;; New format: dict from pattern helper
  (when (isinstance match-spec dict)
    (return [(.get match-spec "type" "fun")
             (.get match-spec "modifiers" [])]))

  ;; Legacy format: list of keywords
  (setv pattern "fun")
  (setv modifiers [])
  (for [m match-spec]
    (setv m-str (_keyword-name m))
    (cond
      (= m-str "public") (.append modifiers "public")
      (= m-str "entry") (.append modifiers "entry")
      (= m-str "capability") (setv pattern "capability")
      (= m-str "event") (setv pattern "event")
      (= m-str "const") (setv pattern "const")
      (= m-str "mutable-config-field") (setv pattern "mutable-config-field")
      (= m-str "writes-protocol-invariant") (setv pattern "writes-protocol-invariant")
      (= m-str "fun") (setv pattern "fun")))
  [pattern modifiers])

;; Valid severity levels
(setv _VALID_SEVERITIES #{"info" "low" "medium" "high" "critical"})

;; Feature-dependent functions: function-name -> feature-name
;; Names match fact names for consistency (feature-version? -> FeatureVersion)
(setv _FEATURE_FUNCTIONS {
  "project-category?" "category"
  "feature-version?" "version"
  "feature-pause?" "pause"
})

(defn _extract-features [expr]
  "Extract required features from an expression by scanning for feature-dependent functions.
   Returns a set of feature names."
  (setv features (set))
  (defn walk [e]
    (cond
      ;; Expression - check head and recurse into args
      (isinstance e Expression)
        (when (> (len e) 0)
          (setv head (get e 0))
          (when (isinstance head Symbol)
            (setv fn-name (str head))
            (when (in fn-name _FEATURE_FUNCTIONS)
              (.add features (get _FEATURE_FUNCTIONS fn-name))))
          (for [arg e]
            (walk arg)))
      ;; List - recurse
      (isinstance e List)
        (for [item e]
          (walk item))))
  (walk expr)
  features)

(defmacro defrule [rule-name #* body]
  "Define a security rule.

   A rule has two clause types:
   - :filter - Structural checks (fast, no LLM). Returns candidates.
   - :classify - Semantic checks (may use LLM). Runs only on filter candidates.

   In clauses:
   - Fact lookups: (is-public f), (tainted-transfer-recipient f _ _)
     Converted to CamelCase: is-public -> IsPublic
   - Function calls end with 'facts ctx': (some-check? f facts ctx)
   - Use _ as wildcard for prefix matching
  "
  ;; Parse body into dict
  (setv parsed {})
  (setv body-list (list body))
  (setv i 0)
  (while (< i (len body-list))
    (when (< (+ i 1) (len body-list))
      (setv key (_keyword-name (get body-list i)))
      (setv val (get body-list (+ i 1)))
      (setv (get parsed key) val))
    (setv i (+ i 2)))

  ;; Extract values
  (setv severity (_keyword-name (.get parsed "severity" "medium")))
  (setv categories (.get parsed "categories" []))
  (setv description (.get parsed "description" ""))
  (setv match-spec (.get parsed "match" []))
  (setv filter-expr (.get parsed "filter" 'True))
  (setv classify-expr (.get parsed "classify" None))

  ;; Validate severity at macro expansion time
  (when (not (in severity _VALID_SEVERITIES))
    (raise (ValueError f"Invalid severity '{severity}' in rule '{rule-name}'. Must be one of: info, low, medium, high, critical")))

  ;; Parse match
  (setv #(pattern modifiers) (_parse-match-spec match-spec))

  ;; Convert categories
  (setv cat-strs (lfor c categories (_keyword-name c)))

  ;; Transform clauses - convert fact lookups and handle variable replacements
  ;; For mutable-config-field pattern, replace ?struct and ?field with unpacked vars
  ;; For writes-protocol-invariant pattern, replace ?func, ?struct and ?field with unpacked vars
  (setv filter-to-transform filter-expr)
  (setv classify-to-transform classify-expr)
  (when (= pattern "mutable-config-field")
    (setv replacements {"?struct" (Symbol "struct") "?field" (Symbol "field")})
    (setv filter-to-transform (_replace-symbols filter-expr replacements))
    (when classify-expr
      (setv classify-to-transform (_replace-symbols classify-expr replacements))))
  (when (= pattern "writes-protocol-invariant")
    (setv replacements {"?func" (Symbol "func") "?struct" (Symbol "struct") "?field" (Symbol "field")})
    (setv filter-to-transform (_replace-symbols filter-expr replacements))
    (when classify-expr
      (setv classify-to-transform (_replace-symbols classify-expr replacements))))

  (setv transformed-filter (_transform-clause filter-to-transform))
  (setv transformed-classify (when classify-to-transform (_transform-clause classify-to-transform)))

  ;; Extract required features from clauses
  (setv features (set))
  (.update features (_extract-features filter-expr))
  (when classify-expr
    (.update features (_extract-features classify-expr)))
  (setv features-list (list features))

  ;; Generate filter/classify clause lambdas based on pattern type
  (setv filter-lambda
    (cond
      (= pattern "mutable-config-field")
        ;; Unpack tuple for struct-field patterns
        `(fn [f facts ctx]
           (setv #(struct field) f)
           ~transformed-filter)
      (= pattern "writes-protocol-invariant")
        ;; Unpack triple for func-struct-field patterns
        `(fn [f facts ctx]
           (setv #(func struct field) f)
           ~transformed-filter)
      True
        ;; Standard single-value binding
        `(fn [f facts ctx] ~transformed-filter)))

  (setv classify-lambda
    (when transformed-classify
      (cond
        (= pattern "mutable-config-field")
          `(fn [f facts ctx]
             (setv #(struct field) f)
             ~transformed-classify)
        (= pattern "writes-protocol-invariant")
          `(fn [f facts ctx]
             (setv #(func struct field) f)
             ~transformed-classify)
        True
          `(fn [f facts ctx] ~transformed-classify))))

  ;; Generate code
  (if classify-lambda
    ;; Both filter and classify
    `(do
       (import rules.hy_loader [register-rule HyRule severity-from-keyword])
       (import rules.hy.builtins [has-fact?])
       (register-rule
         (HyRule
           :name ~(str rule-name)
           :severity (severity-from-keyword ~severity)
           :categories ~cat-strs
           :description ~description
           :match-pattern ~pattern
           :match-modifiers ~modifiers
           :match-binding "f"
           :filter-clause ~filter-lambda
           :classify-clause ~classify-lambda
           :features ~features-list)))
    ;; Only filter (structural-only rule)
    `(do
       (import rules.hy_loader [register-rule HyRule severity-from-keyword])
       (import rules.hy.builtins [has-fact?])
       (register-rule
         (HyRule
           :name ~(str rule-name)
           :severity (severity-from-keyword ~severity)
           :categories ~cat-strs
           :description ~description
           :match-pattern ~pattern
           :match-modifiers ~modifiers
           :match-binding "f"
           :filter-clause ~filter-lambda
           :features ~features-list)))))


(defmacro defprop [prop-name args docstring #* body]
  "Define a reusable property."
  `(defn ~prop-name ~args ~docstring ~@body))
