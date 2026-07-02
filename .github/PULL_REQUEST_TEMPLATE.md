## Description
Briefly describe the changes introduced by this PR. Include the problem it solves or the feature it adds.

## Related Issue
Fixes # (issue number)

## Architecture Checklist
- [ ] My code respects the Hexagonal Architecture boundaries.
- [ ] I have not leaked any external dependencies into the `src/domain/` layer.
- [ ] All new Adapters implement their respective Interfaces in `src/core/contracts.py`.

## Testing
- [ ] I have added/updated unit tests for this logic.
- [ ] All tests pass locally (`pytest`).

## OPSEC
- [ ] I have verified that no sensitive target data, IP addresses, or real-world endpoints are leaked in these changes.
