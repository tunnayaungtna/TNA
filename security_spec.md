# Security Specification (Phase 0: Payload-First Security TDD)

## 1. Data Invariants
1. **Strict Ownership Isolation**: Every `/userBackups/{userId}` document and `/userBackups/{userId}/transactions/{txId}` subcollection document can ONLY be read, created, updated, or deleted by the authenticated user whose `request.auth.uid == userId` and `request.auth.token.email_verified == true`.
2. **Relational Master Gate**: A `TransactionRecord` under `/userBackups/{userId}/transactions/{txId}` can only be accessed or mutated if the parent `/userBackups/{userId}` document exists and its `ownerId == request.auth.uid`.
3. **Immutable Identity & Creation Timestamps**: `ownerId`, `id`, and `createdAt` can never be mutated during an `update`.
4. **Temporal Integrity**: `createdAt` (on create) and `updatedAt` (on create and update) must strictly equal `request.time`.
5. **Volumetric & Regex Guards**: All document IDs (`userId`, `txId`) and string fields must obey strict `.size()` and regex boundaries defined in `firebase-blueprint.json`.

## 2. The "Dirty Dozen" Payloads
1. **Unauthenticated Write**: Writing to `/userBackups/user_1` with `request.auth == null`.
2. **Unverified Email Spoof**: Writing to `/userBackups/user_1` with `email_verified: false`.
3. **Cross-User Read (PII/Financial Leak)**: `user_2` reading `/userBackups/user_1`.
4. **Identity Spoofing on Create**: `user_1` creating `/userBackups/user_1` with `ownerId: "user_2"`.
5. **Shadow Field Injection**: Creating `/userBackups/user_1` with an extra field `isAdmin: true`.
6. **Immutable Field Mutation**: Updating `/userBackups/user_1` by changing `createdAt` or `ownerId`.
7. **Forged Client Timestamp**: Updating `/userBackups/user_1` with a past/future `updatedAt` != `request.time`.
8. **Orphaned Subcollection Write**: Creating `/userBackups/user_1/transactions/tx_1` when `/userBackups/user_1` does not exist.
9. **ID Poisoning Attack**: Creating a transaction with a 2,000-character ID or special characters (`tx/../../hack`).
10. **Value Poisoning on Update**: Updating `cashMMK` with a string `"1000000"` instead of a number.
11. **Oversized String Exhaustion**: Creating a transaction with a 10,000-character `note` (exceeding `maxLength: 500`).
12. **Unauthorized List Scraping**: Listing `/userBackups/user_1/transactions` as `user_2` or without matching `resource.data.ownerId == request.auth.uid`.
