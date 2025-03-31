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

