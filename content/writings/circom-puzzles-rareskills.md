+++
title = "RareSkills Circom Puzzles - Spoilers"
date = "2025-11-06"

[taxonomies]
tags=["web3", "zk", "circom"]

[extra]

+++


Solutions to the RareSkills Circom puzzles from the [zero-knowledge-puzzles](https://github.com/TheMj0ln1r/zero-knowledge-puzzles) repository.

## 1. Addition

**Problem**: Create a constraint that enforces `in[0]` equals the sum of `in[1]` and `in[2]`.

**Solution**: Used a simple constraint `in[0] === in[1] + in[2]` to verify the addition relationship.

**Concepts covered**: Basic constraint syntax in Circom and expressing arithmetic relationships directly.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/Addition/Add.circom)

---

## 2. Multiply No Output

**Problem**: Constrain the third signal to be the product of the first two signals without using an output signal.

**Solution**: Directly constrained `in[2] === in[0] * in[1]` to verify the multiplication.

**Concepts covered**: Constraints can verify relationships without explicit output signals.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/MultiplyNoOut/MultiplyNoOut.circom)

---

## 3. Compile

**Problem**: Learn how to compile a Circom circuit to R1CS and generate a Solidity verifier contract.

**Solution**: Created a simple multiplier circuit with public input `a` and private input `b` that computes `c = a * b`.

**Concepts covered**: The compilation pipeline from Circom to on-chain verification, and the distinction between public and private inputs.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/Compile/Mul.circom)

[Life Cycle of ZK circuit](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/Compile/Notes.md)

---

## 4. Binary XY

**Problem**: Create constraints that enforce two input signals are binary (0 or 1).

**Solution**: Used the constraint `in[i] * (in[i] - 1) === 0` for each input. This works because only 0 and 1 satisfy this equation.

**Concepts covered**: Quadratic constraints for range checking. A binary value multiplied by itself minus one always equals zero.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/BinaryXY/BinaryXY.circom)

---

## 5. All Binary

**Problem**: Extend binary checking to work with an array of n signals.

**Solution**: Looped through the array and applied the binary constraint `in[i] * (in[i] - 1) === 0` to each element.

**Concepts covered**: Using loops to apply constraints to array elements and creating parameterized templates.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/AllBinary/AllBinary.circom)

---

## 6. For Loop

**Problem**: Add `a[0]` and `a[1]` four times using a for loop.

**Solution**: Used an intermediate signal array to accumulate the sum. Initialized with `sum[0] = a[0]`, then looped to compute `sum[i+1] = sum[i] + a[1]` four times.

**Concepts covered**: Managing intermediate signals in loops. Each constraint creates a new signal assignment.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/ForLoop/ForLoop.circom)

---

## 7. Summation

**Problem**: Constrain that a sum equals the total of all elements in an array of length n.

**Solution**: Created intermediate signals to accumulate the sum progressively: `summ[i] = summ[i-1] + in[i]`, then constrained the final sum.

**Concepts covered**: Accumulation pattern in Circom where each step builds on the previous using intermediate signals.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/Summation/Summation.circom)

---

## 8. Equality

**Problem**: Check if three values in an array are all equal.

**Solution**: Implemented `IsZero` template that checks if a value is zero by finding its modular inverse. Used `IsEqual` which applies `IsZero` to the difference of two values. Combined two `IsEqual` checks with multiplication - both must return 1 for all three values to be equal.

**Concepts covered**:
- Using modular inverse to check if a value is zero in a finite field
- The pattern: `out = -in * inv + 1` forces out=1 when in=0 and out=0 when in`0
- The constraint `in * out === 0` additionally ensures the inverse is computed correctly
- Why simple assignments without constraints create underconstrained circuits

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/Equality/Equality.circom)

---

## 9. Not Equal

**Problem**: Check if two values are not equal, output 1 if different, 0 if same.

**Solution**: Used the `IsEqual` component and negated its result: `c = 1 - ise.out`.

**Concepts covered**: Boolean negation in circuits through arithmetic subtraction from 1.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/NotEqual/NotEqual.circom)

---

## 10. Multi AND

**Problem**: Return 1 if all signals in an array are 1, otherwise return 0. Ensure all inputs are binary.

**Solution**: First constrained all inputs to be binary, then computed the product of all elements - the result is 1 only if all elements are 1.

**Concepts covered**: AND operation as multiplication in binary arithmetic. Accumulating products through intermediate signals.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/MultiAND/MultiAND.circom)

---

## 11. Multi AND No Output

**Problem**: Verify that all signals in an array equal 1, without an output signal.

**Solution**: Simply constrained each element directly: `in[i] === 1` in a loop.

**Concepts covered**: Constraints can verify conditions without producing outputs. Simpler when you only need to verify, not compute.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/MultiANDNoOut/MultiANDNoOut.circom)

---

## 12. Multi OR

**Problem**: Return 1 if at least one signal is 1, return 0 if all are 0. Inputs must be binary.

**Solution**: Constrained inputs to binary, then computed OR iteratively using: `found[i] = found[i-1] + in[i] - found[i-1]*in[i]`. This implements `A OR B = A + B - A*B`.

**Concepts covered**: OR operation in arithmetic circuits using the algebraic formula that avoids exceeding 1 when both inputs are 1.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/MultiOR/MultiOR.circom)

---

## 13. Four Bit Binary

**Problem**: Verify that a 4-element array represents the binary form of a number n (0-15).

**Solution**: Constrained each element to be binary, then computed the decimal value: `bin_sum[i+1] = bin_sum[i] + in[i] * (1 << i)`. Finally constrained the sum equals n.

**Concepts covered**: Converting binary representation to decimal in circuits using positional notation with powers of 2.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/FourBitBinary/FourBitBinary.circom)

---

## 14. Has At Least One

**Problem**: Return 1 if a value k exists in an array, otherwise 0.

**Solution**: Used `IsEqual` to check each element against k, then ORed all results together using: `found[i+1] = found[i] + ise[i].out - found[i]*ise[i].out`.

**Concepts covered**: Combining equality checks with OR logic to implement membership testing in arrays.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/HasAtLeastOne/HasAtLeastOne.circom)

---

## 15. Increasing Distance

**Problem**: Enforce constraints where `in1[i] * in2[i] === in3[i] + i` for each index i.

**Solution**: Looped through arrays and applied the constraint directly: `in1[i] * in2[i] === in3[i] + i`.

**Concepts covered**: Creating dynamic constraints that vary based on loop iteration index.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/IncreasingDistance/IncreasingDistance.circom)

---

## 16. Is Sorted

**Problem**: Verify that a 4-element array is sorted in non-decreasing order.

**Solution**: Used `LessEqThan` comparator to verify `in[i] <= in[i+1]` for each consecutive pair.

**Concepts covered**: Verifying ordering relationships using comparison circuits from circomlib.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/IsSorted/IsSorted.circom)

---

## 17. Is Tribonacci

**Problem**: Verify that an array follows the Tribonacci sequence (0, 1, 1, 2, 4, 7, 13, ...).

**Solution**: Constrained the first three elements to 0, 1, 1, then constrained each subsequent element to be the sum of the previous three: `in[i] === in[i-1] + in[i-2] + in[i-3]`.

**Concepts covered**: Expressing recursive sequences as constraints in zero-knowledge circuits.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/IsTribonacci/IsTribonacci.circom)

---

## 18. Integer Division

**Problem**: Verify that numerator, denominator, quotient, and remainder represent a valid integer division.

**Solution**: Applied three key constraints:
1. `denominator != 0` using `IsZero`
2. `remainder < denominator` using `LessThan`
3. `numerator = denominator * quotient + remainder`

**Concepts covered**: Verifying division without computing it directly. Division properties can be checked through multiplication and comparison constraints.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/IntDiv/IntDiv.circom)

---

## 19. Integer Division Output

**Problem**: Same as Integer Division but compute the quotient as output.

**Solution**: Used `<--` to compute quotient and remainder off-circuit (`quotient <-- numerator \ denominator`), then applied the same three constraints from IntDiv to verify correctness.

**Concepts covered**: The "compute then constrain" pattern - use `<--` for witness computation, then `<==` and `===` to constrain the computed values.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/IntDivOut/IntDivOut.circom)

---

## 20. Integer Square Root

**Problem**: Verify that `in[0]` is the floor of the integer square root of `in[1]`.

**Solution**: A value b is the integer square root of a if:
- `b <= a` (floor property)
- `(b+1)*(b+1) > a` (can't go higher)
- `b < 2^125` (overflow prevention)

Implemented using `LessEqThan`, `GreaterThan` and range check to prevent finite field overflow.

**Concepts covered**:
- Verifying integer square roots without computing them
- Finite field overflow issues: if input is too large (>126 bits), the squared value wraps around modulo p
- Why `b < 2^125`: prevents `(b+1)*(b+1)` from exceeding the 252-bit comparator limit

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/IntSqrt/IntSqrt.circom)

---

## 21. Integer Square Root Output

**Problem**: Compute the integer square root and constrain it using the logic from IntSqrt.

**Solution**: Implemented Babylonian/Heron's method in a Circom function to compute the square root off-circuit. The algorithm iteratively computes `new_guess = (guess + n/guess) / 2`, which converges to the square root. Then applied the same constraints from IntSqrt to verify the result.

**Concepts covered**:
- Implementing iterative algorithms in Circom functions (executed at compile/witness generation time)
- The Babylonian method: imagine a rectangle with area n, width x, and height n/x - averaging these dimensions converges to n
- Separating computation (function) from verification (constraints)

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/IntSqrtOut/IntSqrtOut.circom)

---

## 22. Quadratic Equation

**Problem**: Verify a quadratic equation `ax� + bx + c = res`.

**Solution**: Used intermediate signals to satisfy the "at most one multiplication per constraint" rule:
- `x_squared <== x * x`
- `a_x_squared <== a * x_squared`
- `computed_res <== a_x_squared + b * x + c`
- Checked if `computed_res == res` using `IsEqual`

**Concepts covered**: Breaking down complex expressions into quadratic constraints. Each constraint in Circom can have at most one multiplication.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/QuadraticEquation/QuadraticEquation.circom)

---

## 23. Power

**Problem**: Compute `a[0]^a[1]` where the exponent can be 0-10.

**Solution**: Pre-computed all powers (a^0 through a^10) in a loop. Then used `IsEqual` to find which power index matches the exponent, multiplied that result by the corresponding power value, and summed to get the final answer.

**Concepts covered**:
- Implementing power operations when direct exponentiation isn't available
- The selection pattern: pre-compute all possibilities, use equality checks to select the correct one
- One component instance needed per loop iteration in Circom

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/Power/pow.circom)

---

## 24. Range Check

**Problem**: Verify that a value falls within a given range [lowerbound, upperbound].

**Solution**: Implemented custom comparator templates from scratch:
- `MyLessThan(n)`: Uses bit decomposition - compute `Lambda = 2^n + (a-b)` and check the MSB. If a < b, then Lambda < 2^n so MSB=0, otherwise MSB=1.
- Built other comparators on top: `LessThanOrEqual(a,b) = LessThan(a, b+1)`, `GreaterThan(a,b) = LessThan(b,a)`, etc.
- Final check: `(a >= lowerbound) AND (a <= upperbound)` using multiplication.

**Concepts covered**:
- How comparison works in ZK circuits using bit decomposition
- The midpoint trick: adding 2^n creates a reference point to check if a number is above or below it based on MSB
- Why 2^(n-1) is the smallest n-bit number with MSB=1

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/Range/Range.circom)

---

## 25. Poseidon Hash

**Problem**: Hash four input values using the Poseidon hash function from circomlib.

**Solution**: Imported the Poseidon template from circomlib, instantiated it with parameter 4 (number of inputs), wired the inputs to `pose.inputs[0..3]`, and connected the output.

**Concepts covered**: Using circomlib's ZK-friendly hash functions. Poseidon is optimized for arithmetic circuits unlike traditional hashes like SHA-256.

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/Poseidon/Poseidon.circom)

---

## 26. Salt

**Problem**: Hash two values (a, b) with a secret salt to prevent brute force attacks.

**Solution**: Used MiMCSponge hash with 2 inputs and 220 rounds. Passed `a` and `b` as inputs, and `salt` as the key parameter.

**Concepts covered**:
- MiMCSponge as another ZK-friendly hash function
- All inputs are private by default in Circom unless explicitly marked public

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/Salt/Salt.circom)

---

## 27. Sudoku (4x4)

**Problem**: Verify a 4x4 Sudoku solution against a given question.

**Solution**: Built comprehensive verification with multiple constraint layers:
1. **Input validation**: Solution matches non-zero question cells
2. **Range checks**: All values are 1-4
3. **Row constraints**: Each row sums to 10 and has unique values
4. **Column constraints**: Each column sums to 10 and has unique values
5. **Box constraints**: Each 2x2 box sums to 10 and has unique values
6. **Uniqueness checks**: For each row/column/box, verified all pairs are different using nested loops

**Concepts covered**:
- Building complex verification logic by layering multiple constraint types
- Chained array lookups don't work in Circom - must use intermediate variables
- Using AND logic (multiplication) to combine multiple boolean checks into final output
- Comprehensive constraint coverage prevents false proofs

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/Sudoku/Sudoku.circom)

---

## 28. Sujiko

**Problem**: Verify a 3x3 Sujiko puzzle where four central circles show sums of their surrounding 2x2 blocks.

**Solution**:
1. Constrained each of the 4 circle values equals the sum of its surrounding 4 cells
2. Verified each number 1-9 appears exactly once using a double loop: outer loop iterates 1-9, inner loop counts occurrences of that number in the solution
3. Used `assert` to validate solution values are in range 1-9

**Concepts covered**:
- Expressing puzzle rules as arithmetic constraints
- Using nested loops with `IsEqual` to verify uniqueness across a set
- The difference between `assert` (compile-time check) and constraints (proof-time check)

[Solution](https://github.com/TheMj0ln1r/zero-knowledge-puzzles/blob/main/Sujiko/Sujiko.circom)

---

## Key Takeaways

Throughout these puzzles, you will learn:

1. **Constraint Design Patterns**: Compute-then-constrain, indicate-then-constrain
2. **Finite Field Arithmetic**: How operations work modulo p and potential overflow issues
3. **Quadratic Constraints**: Each constraint can have at most one multiplication
4. **Intermediate Signals**: Essential for complex computations and accumulation patterns
5. **Boolean Logic in Arithmetic**: AND (multiplication), OR (A+B-A*B), NOT (1-A)
6. **Circomlib Components**: IsZero, IsEqual, LessThan, Poseidon, MiMCSponge, etc.
7. **Security Considerations**: Proper constraint coverage prevents underconstrained circuits and fake proofs
8. **Compute vs Verify**: Functions for computation, constraints for verification