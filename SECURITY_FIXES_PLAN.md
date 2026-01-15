# Security Fixes Plan

## Bug Fixes

### 1. Inconsistent Pattern Length Message
**Issue**: Top says "8+ unique clicks" but bottom says "need >=12 unique"
**Location**: `src/app.rs` - Initial creation UI
**Fix**: Update the UI text to consistently say "12+ unique clicks" to match `MIN_PATTERN_LENGTH`

### 2. Tic-Tac-Toe Game Not Accessible
**Issue**: Game only appears in main vault UI after login, not discoverable
**Location**: `src/app.rs` - Password generation section
**Current**: Game button only shows in password generation panel after logging into a vault
**Note**: User needs to create/open a vault first, then the game appears in password generation area

---

## Security Fixes

### 3. Game Entropy Disclaimer (HIGH)
**Issue**: Users may think the game improves cryptographic security
**Location**: `src/app.rs` - Entropy game UI section
**Fix**:
- Change checkbox label to clarify it's for fun
- Add tooltip disclaimer
- Add warning text in game window

### 4. USB Path Validation (HIGH)
**Issue**: No filename length limits or path escape prevention
**Location**: `src/usb_export.rs:103-126`
**Fixes**:
- Limit sanitized vault name to 50 characters
- Validate total filename length <= 255
- Verify final path doesn't escape mount point

### 5. Custom Field Limits (MEDIUM)
**Issue**: No limits on field name or value length
**Location**: `src/vault.rs` and `src/app.rs`
**Fixes**:
- MAX_FIELD_NAME_LEN = 100
- MAX_FIELD_VALUE_LEN = 10,000 bytes
- Validate in UI before adding field

### 6. USB Device Verification (MEDIUM)
**Issue**: Could export to system directories
**Location**: `src/usb_export.rs`
**Fixes**:
- Block system directories: /, /System, C:\Windows, etc.
- Require minimum 1MB free space
- Verify mount point is writable

---

## Implementation Order

1. Fix pattern message inconsistency
2. Add game entropy disclaimer
3. Add USB path validation
4. Add USB device verification
5. Add custom field limits
6. Test all changes
7. Commit and push

---

## Files to Modify

| File | Changes |
|------|---------|
| src/app.rs | Fix pattern text, add game disclaimer, field length validation |
| src/usb_export.rs | Path validation, device verification, blocked paths |
