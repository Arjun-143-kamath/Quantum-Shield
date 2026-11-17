
"""
QuantumShield - Shor's Algorithm

Educational implementation of quantum order finding
for factoring N=15 using Qiskit and AerSimulator.

This is a specialized small-number demonstration,
not a scalable RSA-breaking implementation.
"""

from fractions import Fraction
from math import gcd

from qiskit import (
    QuantumCircuit,
    QuantumRegister,
    ClassicalRegister,
    transpile
)

from qiskit.circuit.library import QFTGate
from qiskit_aer import AerSimulator


# =====================================================
# CONFIGURATION
# =====================================================

DEFAULT_NUMBER = 15
DEFAULT_BASE = 2

NUM_TARGET = 4
NUM_CONTROL = 8


# =====================================================
# MODULAR MULTIPLICATION GATES
# =====================================================

def m2_mod15():
    """
    Construct multiplication by 2 modulo 15.

    This permutation can be represented using
    three SWAP gates.
    """

    circuit = QuantumCircuit(4)

    circuit.swap(2, 3)
    circuit.swap(1, 2)
    circuit.swap(0, 1)

    gate = circuit.to_gate()
    gate.name = "M_2"

    return gate


def m4_mod15():
    """
    Construct multiplication by 4 modulo 15.
    """

    circuit = QuantumCircuit(4)

    circuit.swap(1, 3)
    circuit.swap(0, 2)

    gate = circuit.to_gate()
    gate.name = "M_4"

    return gate


# =====================================================
# BUILD ORDER-FINDING CIRCUIT
# =====================================================

def build_shor_circuit():
    """
    Construct the 8-qubit phase estimation circuit
    and 4-qubit modular multiplication register.
    """

    control = QuantumRegister(NUM_CONTROL, "C")
    target = QuantumRegister(NUM_TARGET, "T")

    output = ClassicalRegister(NUM_CONTROL, "out")

    circuit = QuantumCircuit(control, target, output)

    # Initialize target register to |1>.
    circuit.x(NUM_CONTROL)

    m2 = m2_mod15().control()
    m4 = m4_mod15().control()

    # Hadamard and controlled modular multiplication.
    for k, qubit in enumerate(control):

        circuit.h(qubit)

        multiplier = pow(
            DEFAULT_BASE,
            2**k,
            DEFAULT_NUMBER
        )

        if multiplier == 2:

            circuit.compose(
                m2,
                qubits=[qubit] + list(target),
                inplace=True
            )

        elif multiplier == 4:

            circuit.compose(
                m4,
                qubits=[qubit] + list(target),
                inplace=True
            )

        # Multiplication by 1 is the identity operation.

    # Inverse quantum Fourier transform.
    circuit.compose(
        QFTGate(NUM_CONTROL).inverse(),
        qubits=control,
        inplace=True
    )
    # Measure control register.
    circuit.measure(control, output)

    return circuit


# =====================================================
# CLASSICAL POST-PROCESSING
# =====================================================

def extract_factors(counts: dict):
    """
    Process measured phases using continued fractions.

    Attempts to recover the order and calculate
    non-trivial factors of 15.
    """

    for bitstring, frequency in sorted(
        counts.items(),
        key=lambda item: item[1],
        reverse=True
    ):

        measured_value = int(bitstring.replace(" ", ""), 2)

        if measured_value == 0:
            continue

        phase = Fraction(
            measured_value,
            2**NUM_CONTROL
        )

        approximation = phase.limit_denominator(
            DEFAULT_NUMBER
        )

        estimated_order = approximation.denominator

        # A phase may provide only a divisor of the
        # true order. Check its multiples.
        for order in range(
            estimated_order,
            DEFAULT_NUMBER + 1,
            estimated_order
        ):

            if pow(DEFAULT_BASE, order, DEFAULT_NUMBER) != 1:
                continue

            if order % 2 != 0:
                continue

            x = pow(
                DEFAULT_BASE,
                order // 2,
                DEFAULT_NUMBER
            )

            if x in (1, DEFAULT_NUMBER - 1):
                continue

            factor1 = gcd(x - 1, DEFAULT_NUMBER)
            factor2 = gcd(x + 1, DEFAULT_NUMBER)

            if (
                factor1 > 1
                and factor2 > 1
                and factor1 * factor2 == DEFAULT_NUMBER
            ):

                return {
                    "factors": sorted([factor1, factor2]),
                    "order": order,
                    "phase": float(phase),
                    "measurement": bitstring,
                    "frequency": frequency
                }

    return None


# =====================================================
# RUN SHOR'S ALGORITHM
# =====================================================

def run_shor_demo(shots: int = 2048, seed: int = 42):
    """
    Execute Shor's educational factoring circuit.

    Returns:
        Circuit, counts, factors and phase information.
    """

    if not isinstance(shots, int) or not 256 <= shots <= 10000:
        raise ValueError("Shots must be between 256 and 10000.")

    circuit = build_shor_circuit()

    simulator = AerSimulator()

    compiled_circuit = transpile(
        circuit,
        simulator,
        optimization_level=1
    )

    job = simulator.run(
        compiled_circuit,
        shots=shots,
        seed_simulator=seed
    )

    result = job.result()

    counts = result.get_counts(compiled_circuit)

    factor_result = extract_factors(counts)

    phase_results = []

    for bitstring, frequency in counts.items():

        measured_value = int(bitstring.replace(" ", ""), 2)

        phase = Fraction(
            measured_value,
            2**NUM_CONTROL
        )

        approximation = phase.limit_denominator(
            DEFAULT_NUMBER
        )

        phase_results.append({
            "measurement": bitstring,
            "frequency": frequency,
            "phase": float(phase),
            "fraction": (
                f"{approximation.numerator}/"
                f"{approximation.denominator}"
            ),
            "estimated_order": approximation.denominator
        })

    phase_results.sort(
        key=lambda item: item["frequency"],
        reverse=True
    )

    return {
        "number": DEFAULT_NUMBER,
        "base": DEFAULT_BASE,
        "shots": shots,
        "counts": counts,
        "factors": (
            factor_result["factors"]
            if factor_result else None
        ),
        "order": (
            factor_result["order"]
            if factor_result else None
        ),
        "phase_results": phase_results,
        "circuit": circuit
    }

