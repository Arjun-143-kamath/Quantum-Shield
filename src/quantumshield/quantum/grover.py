
"""
QuantumShield - Grover's Search Algorithm

Demonstrates quantum amplitude amplification
for a small unstructured search space.
"""

import math

from qiskit import QuantumCircuit, transpile
from qiskit.circuit.library import grover_operator
from qiskit_aer import AerSimulator


# =====================================================
# VALIDATION
# =====================================================

def validate_inputs(
    num_qubits: int,
    target_value: int,
    shots: int
):

    if not isinstance(num_qubits, int) or not 2 <= num_qubits <= 8:
        raise ValueError("Qubit count must be between 2 and 8.")

    if (
        not isinstance(target_value, int)
        or not 0 <= target_value < 2**num_qubits
    ):
        raise ValueError("Target value is outside the search space.")

    if not isinstance(shots, int) or not 256 <= shots <= 10000:
        raise ValueError("Shots must be between 256 and 10000.")


# =====================================================
# CREATE ORACLE
# =====================================================

def create_oracle(marked_state: str):
    """
    Build an oracle that marks one computational basis state.

    Example:
        marked_state = '101'
    """

    num_qubits = len(marked_state)

    if num_qubits < 2:
        raise ValueError("Oracle requires at least two qubits.")

    if any(bit not in "01" for bit in marked_state):
        raise ValueError("Marked state must be a binary string.")

    oracle = QuantumCircuit(num_qubits, name="Oracle")

    # Convert the target state into the all-ones state.
    for index, bit in enumerate(marked_state):

        qubit = num_qubits - 1 - index

        if bit == "0":
            oracle.x(qubit)

    # Multi-controlled Z using H-MCX-H.
    target_qubit = num_qubits - 1
    control_qubits = list(range(num_qubits - 1))

    oracle.h(target_qubit)

    oracle.mcx(
        control_qubits,
        target_qubit
    )

    oracle.h(target_qubit)

    # Restore the original computational basis.
    for index, bit in enumerate(marked_state):

        qubit = num_qubits - 1 - index

        if bit == "0":
            oracle.x(qubit)

    return oracle


# =====================================================
# OPTIMAL ITERATIONS
# =====================================================


def calculate_optimal_iterations(
    num_qubits: int,
    marked_states: int = 1
) -> int:
    """
    Calculate the approximately optimal number of
    Grover iterations.

    Uses nearest-integer rounding of:

        pi / (4 * theta) - 0.5

    This simplifies to:

        floor(pi / (4 * theta))
    """

    if not isinstance(num_qubits, int) or num_qubits < 1:
        raise ValueError("Invalid number of qubits.")

    total_states = 2**num_qubits

    if (
        not isinstance(marked_states, int)
        or not 1 <= marked_states < total_states
    ):
        raise ValueError("Invalid number of marked states.")

    theta = math.asin(
        math.sqrt(marked_states / total_states)
    )

    iterations = math.floor(
        math.pi / (4 * theta)
    )

    return max(0, iterations)

# =====================================================
# RUN GROVER'S ALGORITHM
# =====================================================

def run_grover_search(
    num_qubits: int,
    target_value: int,
    shots: int = 2048,
    seed: int = 42
):
    """
    Run Grover's algorithm using a local Aer simulator.

    Returns:
        Measurement counts, target probability,
        oracle, circuit and iteration count.
    """

    validate_inputs(
        num_qubits,
        target_value,
        shots
    )

    target_state = format(
        target_value,
        f"0{num_qubits}b"
    )

    total_states = 2**num_qubits

    iterations = calculate_optimal_iterations(
        num_qubits
    )

    # 1. Construct oracle.
    oracle = create_oracle(target_state)

    # 2. Construct Grover operator.
    grover_op = grover_operator(oracle)

    # 3. Initialize circuit.
    circuit = QuantumCircuit(num_qubits)

    circuit.h(range(num_qubits))

    # 4. Apply amplitude amplification.
    circuit.compose(
        grover_op.power(iterations),
        inplace=True
    )

    # 5. Measure all qubits.
    circuit.measure_all()

    # 6. Run simulation.
    simulator = AerSimulator()

    compiled_circuit = transpile(
        circuit,
        simulator,
        optimization_level=1
    )

    result = simulator.run(
        compiled_circuit,
        shots=shots,
        seed_simulator=seed
    ).result()

    counts = result.get_counts(compiled_circuit)

    target_hits = counts.get(target_state, 0)

    probability = target_hits / shots

    return {
        "target": target_state,
        "target_value": target_value,
        "num_qubits": num_qubits,
        "search_space": total_states,
        "iterations": iterations,
        "shots": shots,
        "counts": counts,
        "target_hits": target_hits,
        "success_probability": probability,
        "circuit": circuit,
        "oracle": oracle
    }

