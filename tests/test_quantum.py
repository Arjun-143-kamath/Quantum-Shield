
import pytest

from quantumshield.quantum.shor import run_shor_demo

from quantumshield.quantum.grover import (
    run_grover_search,
    calculate_optimal_iterations,
    create_oracle
)

def test_shor_factors_15():

    result = run_shor_demo(
        shots=2048,
        seed=42
    )

    assert result["number"] == 15
    assert result["factors"] == [3, 5]
    assert result["order"] == 4

def test_grover_finds_target():

    result = run_grover_search(
        num_qubits=3,
        target_value=5,
        shots=2048,
        seed=42
    )

    assert result["target"] == "101"
    assert result["search_space"] == 8
    assert result["iterations"] == 2

    assert result["target_hits"] > 0
    assert result["success_probability"] > 0.85

def test_grover_iteration_calculation():

    assert calculate_optimal_iterations(2) == 1
    assert calculate_optimal_iterations(3) == 2
    assert calculate_optimal_iterations(4) == 3

def test_grover_invalid_target():

    with pytest.raises(ValueError):

        run_grover_search(
            num_qubits=3,
            target_value=8
        )


def test_grover_invalid_qubit_count():

    with pytest.raises(ValueError):

        run_grover_search(
            num_qubits=1,
            target_value=0
        )


def test_oracle_invalid_state():

    with pytest.raises(ValueError):
        create_oracle("10X1")

