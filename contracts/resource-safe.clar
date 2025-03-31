;; ===================================================================
;; StacksResourceSafe
;; Enables trust-based resource distribution with milestone verification

;; ===================================================================

;; Primary administrative settings
(define-constant ADMIN tx-sender)
(define-constant ERR_UNAUTHORIZED (err u401))
(define-constant ERR_ITEM_NOT_FOUND (err u404))
(define-constant ERR_FUNDS_ALREADY_RELEASED (err u409))
(define-constant ERR_TRANSFER_UNSUCCESSFUL (err u500))
(define-constant ERR_TRUST_ID_INVALID (err u422))
(define-constant ERR_AMOUNT_INVALID (err u400))
(define-constant ERR_MILESTONE_INVALID (err u405))
(define-constant ERR_TRUST_EXPIRED (err u410))
(define-constant TRUST_DURATION u1008) ;; Approximately 1 week duration in blocks

;; Security protocol parameters
(define-constant SECURITY_TIMEOUT_PERIOD u720) ;; Cooldown period ~5 days
(define-constant ERR_SECURITY_PROTOCOL_ACTIVE (err u503))
(define-constant ERR_SECURITY_COOLDOWN_ACTIVE (err u429))
(define-constant RECIPIENT_LIMIT u5)
(define-constant ERR_TOO_MANY_RECIPIENTS (err u413))
(define-constant ERR_DISTRIBUTION_INVALID (err u412))
(define-constant ERR_ALREADY_EXPIRED (err u410))
(define-constant EXTENSION_LIMIT u1008) ;; Maximum extension period
(define-constant ERR_PROGRESS_ALREADY_NOTED (err u423))
(define-constant ERR_PROXY_EXISTS (err u409))
(define-constant ERR_BATCH_FAILED (err u500))
(define-constant ERR_RATE_EXCEEDED (err u429))
(define-constant RATE_PERIOD u144) ;; Rate limiting window (~24 hours)
(define-constant MAX_TRUSTS_PER_PERIOD u5)
(define-constant ERR_SUSPICIOUS_PATTERN (err u451))
(define-constant SUSPICIOUS_AMOUNT_THRESHOLD u1000000000) ;; High-value threshold
(define-constant SUSPICIOUS_RATE_THRESHOLD u3) ;; Consecutive actions threshold
(define-constant ERR_AUDIT_EXISTS (err u409))
(define-constant ERR_AUDIT_PERIOD_CLOSED (err u410))
(define-constant AUDIT_TIMEFRAME u1008) ;; Audit window
(define-constant AUDIT_DEPOSIT u1000000) ;; Required deposit for audits

;; Main data storage
(define-map TrustVaults
  { trust-id: uint }
  {
    grantor: principal,
    recipient: principal,
    amount: uint,
    status: (string-ascii 10),
    created-at: uint,
    terminates-at: uint,
    milestones: (list 5 uint),
    verified-milestones: uint
  }
)

(define-data-var current-trust-id uint u0)

;; Security validation helpers
(define-private (is-recipient-valid (recipient principal))
  (not (is-eq recipient tx-sender))
)

(define-private (is-trust-id-valid (trust-id uint))
  (<= trust-id (var-get current-trust-id))
)

;; Multi-recipient data structure
(define-map MultiRecipientTrusts
  { group-trust-id: uint }
  {
    grantor: principal,
    beneficiaries: (list 5 { recipient: principal, share: uint }),
    total-amount: uint,
    created-at: uint,
    status: (string-ascii 10)
  }
)

(define-data-var current-group-trust-id uint u0)

;; Recipient verification registry
(define-map ApprovedRecipients
  { recipient: principal }
  { approved: bool }
)

;; Milestone tracking system
(define-map MilestoneTracking
  { trust-id: uint, milestone-index: uint }
  {
    progress-level: uint,
    details: (string-ascii 200),
    timestamp: uint,
    proof-hash: (buff 32)
  }
)

;; Trust delegation registry
(define-map TrustProxies
  { trust-id: uint }
  {
    delegate: principal,
    can-cancel: bool,
    can-extend: bool,
    can-increase: bool,
    delegation-expires: uint
  }
)

;; Platform status control
(define-data-var platform-frozen bool false)

;; Security monitoring system
(define-map FlaggedTrusts
  { trust-id: uint }
  { 
    reason: (string-ascii 20),
    flagged-by: principal,
    resolved: bool
  }
)

;; Grantor activity monitoring
(define-map GrantorActivityTracker
  { grantor: principal }
  {
    last-trust-block: uint,
    trusts-in-period: uint
  }
)

;; Community audit system
(define-map TrustAudits
  { trust-id: uint }
  {
    auditor: principal,
    findings: (string-ascii 200),
    deposit-amount: uint,
    completed: bool,
    findings-validated: bool,
    submission-time: uint
  }
)

;; Emergency recovery system
(define-map AssetRecoveryRequests
  { trust-id: uint }
  { 
    admin-approved: bool,
    grantor-approved: bool,
    reason: (string-ascii 100)
  }
)

;; Helper function to calculate shares
(define-private (calculate-share (beneficiary { recipient: principal, share: uint }))
  (get share beneficiary)
)


;; ===================================================================
;; Primary API Functions
;; ===================================================================

;; Create a new asset trust with milestone-based verification
(define-public (create-trust (recipient principal) (amount uint) (milestones (list 5 uint)))
  (let
    (
      (trust-id (+ (var-get current-trust-id) u1))
      (termination-time (+ block-height TRUST_DURATION))
    )
    (asserts! (> amount u0) ERR_AMOUNT_INVALID)
    (asserts! (is-recipient-valid recipient) ERR_MILESTONE_INVALID)
    (asserts! (> (len milestones) u0) ERR_MILESTONE_INVALID)
    (match (stx-transfer? amount tx-sender (as-contract tx-sender))
      success
        (begin
          (map-set TrustVaults
            { trust-id: trust-id }
            {
              grantor: tx-sender,
              recipient: recipient,
              amount: amount,
              status: "active",
              created-at: block-height,
              terminates-at: termination-time,
              milestones: milestones,
              verified-milestones: u0
            }
          )
          (var-set current-trust-id trust-id)
          (ok trust-id)
        )
      error ERR_TRANSFER_UNSUCCESSFUL
    )
  )
)

;; ===================================================================
;; Batch Processing Functions
;; ===================================================================

;; Verify multiple milestones in batch
(define-public (batch-verify-milestones (trust-ids (list 10 uint)))
  (begin
    (asserts! (is-eq tx-sender ADMIN) ERR_UNAUTHORIZED)
    (let
      (
        (result (fold process-milestone-batch trust-ids (ok true)))
      )
      result
    )
  )
)

;; Helper for batch operations
(define-private (process-milestone-batch (trust-id uint) (prev-result (response bool uint)))
  (begin
    (match prev-result
      success
        (match (verify-milestone trust-id)
          inner-success (ok true)
          inner-error (err inner-error)
        )
      error (err error)
    )
  )
)

;; Verify milestone completion and release proportional funds
(define-public (verify-milestone (trust-id uint))
  (begin
    (asserts! (is-trust-id-valid trust-id) ERR_TRUST_ID_INVALID)
    (let
      (
        (trust (unwrap! (map-get? TrustVaults { trust-id: trust-id }) ERR_ITEM_NOT_FOUND))
        (milestones (get milestones trust))
        (verified-count (get verified-milestones trust))
        (recipient (get recipient trust))
        (total-amount (get amount trust))
        (release-amount (/ total-amount (len milestones)))
      )
      (asserts! (< verified-count (len milestones)) ERR_FUNDS_ALREADY_RELEASED)
      (asserts! (is-eq tx-sender ADMIN) ERR_UNAUTHORIZED)
      (match (stx-transfer? release-amount (as-contract tx-sender) recipient)
        success
          (begin
            (map-set TrustVaults
              { trust-id: trust-id }
              (merge trust { verified-milestones: (+ verified-count u1) })
            )
            (ok true)
          )
        error ERR_TRANSFER_UNSUCCESSFUL
      )
    )
  )
)

;; Revert trust assets to grantor after expiration
(define-public (revert-assets (trust-id uint))
  (begin
    (asserts! (is-trust-id-valid trust-id) ERR_TRUST_ID_INVALID)
    (let
      (
        (trust (unwrap! (map-get? TrustVaults { trust-id: trust-id }) ERR_ITEM_NOT_FOUND))
        (grantor (get grantor trust))
        (amount (get amount trust))
      )
      (asserts! (is-eq tx-sender ADMIN) ERR_UNAUTHORIZED)
      (asserts! (> block-height (get terminates-at trust)) ERR_TRUST_EXPIRED)
      (match (stx-transfer? amount (as-contract tx-sender) grantor)
        success
          (begin
            (map-set TrustVaults
              { trust-id: trust-id }
              (merge trust { status: "reverted" })
            )
            (ok true)
          )
        error ERR_TRANSFER_UNSUCCESSFUL
      )
    )
  )
)

;; Cancel an active trust - grantor-only operation
(define-public (cancel-trust (trust-id uint))
  (begin
    (asserts! (is-trust-id-valid trust-id) ERR_TRUST_ID_INVALID)
    (let
      (
        (trust (unwrap! (map-get? TrustVaults { trust-id: trust-id }) ERR_ITEM_NOT_FOUND))
        (grantor (get grantor trust))
        (amount (get amount trust))
        (verified-count (get verified-milestones trust))
        (remaining-amount (- amount (* (/ amount (len (get milestones trust))) verified-count)))
      )
      (asserts! (is-eq tx-sender grantor) ERR_UNAUTHORIZED)
      (asserts! (< block-height (get terminates-at trust)) ERR_TRUST_EXPIRED)
      (asserts! (is-eq (get status trust) "active") ERR_FUNDS_ALREADY_RELEASED)
      (match (stx-transfer? remaining-amount (as-contract tx-sender) grantor)
        success
          (begin
            (map-set TrustVaults
              { trust-id: trust-id }
              (merge trust { status: "cancelled" })
            )
            (ok true)
          )
        error ERR_TRANSFER_UNSUCCESSFUL
      )
    )
  )
)

;; ===================================================================
;; Advanced Trust Management Functions
;; ===================================================================

;; Create multi-recipient trust with percentage-based allocation
(define-public (create-split-trust (beneficiaries (list 5 { recipient: principal, share: uint })) (amount uint))
  (begin
    (asserts! (> amount u0) ERR_AMOUNT_INVALID)
    (asserts! (> (len beneficiaries) u0) ERR_TRUST_ID_INVALID)
    (asserts! (<= (len beneficiaries) RECIPIENT_LIMIT) ERR_TOO_MANY_RECIPIENTS)

    ;; Validate share distribution totals 100%
    (let
      (
        (total-shares (fold + (map calculate-share beneficiaries) u0))
      )
      (asserts! (is-eq total-shares u100) ERR_DISTRIBUTION_INVALID)

      ;; Process the asset transfer and create trust
      (match (stx-transfer? amount tx-sender (as-contract tx-sender))
        success
          (let
            (
              (group-id (+ (var-get current-group-trust-id) u1))
            )
            (map-set MultiRecipientTrusts
              { group-trust-id: group-id }
              {
                grantor: tx-sender,
                beneficiaries: beneficiaries,
                total-amount: amount,
                created-at: block-height,
                status: "active"
              }
            )
            (var-set current-group-trust-id group-id)
            (ok group-id)
          )
        error ERR_TRANSFER_UNSUCCESSFUL
      )
    )
  )
)


;; ===================================================================
;; Administrative Functions
;; ===================================================================

;; Set platform operational status
(define-public (set-platform-status (new-status bool))
  (begin
    (asserts! (is-eq tx-sender ADMIN) ERR_UNAUTHORIZED)
    (ok new-status)
  )
)

;; Query recipient verification status
(define-read-only (is-recipient-approved (recipient principal))
  (default-to false (get approved (map-get? ApprovedRecipients { recipient: recipient })))
)

;; ===================================================================
;; Enhanced Trust Management Functions
;; ===================================================================

;; Extend trust duration
(define-public (extend-trust-duration (trust-id uint) (extension-blocks uint))
  (begin
    (asserts! (is-trust-id-valid trust-id) ERR_TRUST_ID_INVALID)
    (asserts! (<= extension-blocks EXTENSION_LIMIT) ERR_AMOUNT_INVALID)
    (let
      (
        (trust (unwrap! (map-get? TrustVaults { trust-id: trust-id }) ERR_ITEM_NOT_FOUND))
        (grantor (get grantor trust))
        (current-termination (get terminates-at trust))
      )
      (asserts! (is-eq tx-sender grantor) ERR_UNAUTHORIZED)
      (asserts! (< block-height current-termination) ERR_ALREADY_EXPIRED)
      (map-set TrustVaults
        { trust-id: trust-id }
        (merge trust { terminates-at: (+ current-termination extension-blocks) })
      )
      (ok true)
    )
  )
)

;; Increase trust amount
(define-public (increase-trust-amount (trust-id uint) (additional-amount uint))
  (begin
    (asserts! (is-trust-id-valid trust-id) ERR_TRUST_ID_INVALID)
    (asserts! (> additional-amount u0) ERR_AMOUNT_INVALID)
    (let
      (
        (trust (unwrap! (map-get? TrustVaults { trust-id: trust-id }) ERR_ITEM_NOT_FOUND))
        (grantor (get grantor trust))
        (current-amount (get amount trust))
      )
      (asserts! (is-eq tx-sender grantor) ERR_UNAUTHORIZED)
      (asserts! (< block-height (get terminates-at trust)) ERR_TRUST_EXPIRED)
      (match (stx-transfer? additional-amount tx-sender (as-contract tx-sender))
        success
          (begin
            (map-set TrustVaults
              { trust-id: trust-id }
              (merge trust { amount: (+ current-amount additional-amount) })
            )
            (ok true)
          )
        error ERR_TRANSFER_UNSUCCESSFUL
      )
    )
  )
)

;; ===================================================================
;; Security and Rate-limiting Functions
;; ===================================================================

;; Rate-limited trust creation with abuse prevention
(define-public (secure-trust-creation (recipient principal) (amount uint) (milestones (list 5 uint)))
  (let
    (
      (grantor-activity (default-to 
                        { last-trust-block: u0, trusts-in-period: u0 }
                        (map-get? GrantorActivityTracker { grantor: tx-sender })))
      (last-block (get last-trust-block grantor-activity))
      (period-count (get trusts-in-period grantor-activity))
      (new-period (> (- block-height last-block) RATE_PERIOD))
      (updated-count (if new-period u1 (+ period-count u1)))
    )
    ;; Rate limit check
    (asserts! (or new-period (< period-count MAX_TRUSTS_PER_PERIOD)) ERR_RATE_EXCEEDED)

    ;; Check for suspicious high-value transactions
    (if (> amount SUSPICIOUS_AMOUNT_THRESHOLD)
      (if (>= period-count SUSPICIOUS_RATE_THRESHOLD)
        (asserts! false ERR_SUSPICIOUS_PATTERN)
        true
      )
      true
    )

    ;; Update tracking
    (map-set GrantorActivityTracker
      { grantor: tx-sender }
      {
        last-trust-block: block-height,
        trusts-in-period: updated-count
      }
    )

    ;; Proceed with enhanced verification
    (protected-trust-creation recipient amount milestones)
  )
)

;; Enhanced security trust creation
(define-public (protected-trust-creation (recipient principal) (amount uint) (milestones (list 5 uint)))
  (begin
    (asserts! (not (var-get platform-frozen)) ERR_UNAUTHORIZED)
    (asserts! (is-recipient-approved recipient) ERR_UNAUTHORIZED)
    (asserts! (> amount u0) ERR_AMOUNT_INVALID)
    (asserts! (is-recipient-valid recipient) ERR_MILESTONE_INVALID)
    (asserts! (> (len milestones) u0) ERR_MILESTONE_INVALID)

    (let
      (
        (trust-id (+ (var-get current-trust-id) u1))
        (termination-time (+ block-height TRUST_DURATION))
      )
      (match (stx-transfer? amount tx-sender (as-contract tx-sender))
        success
          (begin
            (map-set TrustVaults
              { trust-id: trust-id }
              {
                grantor: tx-sender,
                recipient: recipient,
                amount: amount,
                status: "active",
                created-at: block-height,
                terminates-at: termination-time,
                milestones: milestones,
                verified-milestones: u0
              }
            )
            (var-set current-trust-id trust-id)
            (ok trust-id)
          )
        error ERR_TRANSFER_UNSUCCESSFUL
      )
    )
  )
)

;; ===================================================================
;; Security Monitoring Functions
;; ===================================================================

;; Flag suspicious trust activity
(define-public (flag-suspicious-trust (trust-id uint) (reason (string-ascii 20)))
  (begin
    (asserts! (is-trust-id-valid trust-id) ERR_TRUST_ID_INVALID)

    ;; Only admin or the recipient can flag trusts
    (let
      (
        (trust (unwrap! (map-get? TrustVaults { trust-id: trust-id }) ERR_ITEM_NOT_FOUND))
        (recipient (get recipient trust))
      )
      (asserts! (or (is-eq tx-sender ADMIN) (is-eq tx-sender recipient)) ERR_UNAUTHORIZED)

      ;; Update trust status
      (map-set TrustVaults
        { trust-id: trust-id }
        (merge trust { status: "flagged" })
      )

      (ok true)
    )
  )
)

;; ===================================================================
;; Community Oversight Functions
;; ===================================================================

;; Submit trust audit with findings
(define-public (submit-trust-audit 
                (trust-id uint)
                (findings (string-ascii 200)))
  (begin
    (asserts! (is-trust-id-valid trust-id) ERR_TRUST_ID_INVALID)
    (let
      (
        (trust (unwrap! (map-get? TrustVaults { trust-id: trust-id }) ERR_ITEM_NOT_FOUND))
      )
      ;; Check for existing audit
      (match (map-get? TrustAudits { trust-id: trust-id })
        existing-audit (asserts! false ERR_AUDIT_EXISTS)
        true
      )

      ;; Transfer audit deposit
      (match (stx-transfer? AUDIT_DEPOSIT tx-sender (as-contract tx-sender))
        success
          (begin
            (ok true)
          )
        error ERR_TRANSFER_UNSUCCESSFUL
      )
    )
  )
)
