### [H-1] Storing the password on-chaine makes it visible to anyone, and no longer private.

**Description:** All data stored on-chain is visible to anyone, and can be read directly from the blockchain. The `PasswordStore::s_password` variable is intended to be a private variable and only accessed through the `PasswordStore::getPassword` function, which is intended to be only called by the owner of the contract.

We show one such method of reading any data off chain below.

**Impact:** Anyone can read the private password, severely breaking the functionality of the protocol.

**Proof of Concept:** (Proof of Code)

The below test case shows how anyone can read the password directly from the blockchain.

**Recommended Mitigation:** Due to this, the overall architecture of the contract should be rethought. One could encrypt the password off-chain, and then store the encrypted password on-chain. This would require the user to remember another password off-chain to decrypt the password. However, you'd also likely want to remove the view function as you wouldn't want to the user to accidentally send a transaction with the password that decrypts your password.

## Likelihood & Impact:
- Impact: HIGH
- Likelihood: HIGH
- Severity: HIGH

### [H-2] `PasswordStore::setPassword` has no access controls, meaning a non-owner could change the password

**Description:** The `PasswordStore::setPassword` function is set to be an `external` function, however, the natspec of the function and overall purpose of the smart contract is that `This function allows only the owner to set a new password.`

```javascript
    function setPassword(string memory newPassword) external {
        // @audit - There are no access controls
        s_password = newPassword;
        emit SetNetPassword();
    }
```

**Impact:** Anyone can set/change the password of the contract, severly breaking the contract intended functionality.

**Proof of Concept:**

**Recommended Mitigation:** Add an access control conditional to the `setPassword` function.

```javascript
if(msg.sender != s_owner) {
    revert PasswordStore__NotOwner();
}
```

## Likelihood & Impact:
- Impact: HIGH
- Likelihood: HIGH
- Severity: HIGH

### [I-1] The `PasswordStore::getPassword` natspec indicates a parameter that doesn't exists, causing the natspec to be incorrect

**Description:** 

```javascript
    /*
     * @notice this allows only the owner to retrieve the password.
     * @param newPassword The new password is set
    */
   function getPassword() external view returns (string memory)
 ```

The `PasswordStore::getPassword` function signature is `getPassword()` which the natspec says it should be `getPassword(string)`. 

**Impact:** The natspec is incorrect.

**Recommended Mitigation:** Remove the incorrect natspec line.

```diff
-     * @param newPassword The new password to set.
```

## Likelihood & Impact:
- Impact: NONE
- Likelihood: HIGH
- Severity: Information/Gas/Non-crits

Informational: This isn't a bug but you should know about it.