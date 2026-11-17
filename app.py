
import streamlit as st

from pathlib import Path

from quantumshield.transfer.service import (
    initialize_user,
    initialize_pqc_user,
    user_initialized,
    user_pqc_initialized,
    send_file,
    list_incoming_transfers,
    receive_file
)

from quantumshield.benchmark.dashboard import (
    render_benchmark_dashboard
)

import pandas as pd

from quantumshield.quantum.shor import run_shor_demo

from quantumshield.quantum.grover import run_grover_search

from quantumshield.storage.security_store import (
    get_audit_events,
    initialize_security_store
)

# =====================================================
# CONFIGURATION
# =====================================================

BASE_DIR = Path(__file__).resolve().parent

RECEIVED_DIR = BASE_DIR / "data" / "received"


st.set_page_config(
    page_title="QuantumShield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =====================================================
# STYLING
# =====================================================

st.markdown("""
<style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }

    [data-testid="stSidebar"] {
        background-color: #141a1c;
    }

    .main-title {
        font-size: 2.4rem;
        font-weight: 800;
        letter-spacing: -1px;
    }

    .subtitle {
        color: #8a9ea0;
        font-size: 1rem;
    }

    div[data-testid="stMetric"] {
        background: #1e2829;
        padding: 16px;
        border-radius: 12px;
        border: 1px solid #4a6b6f;
    }
</style>
""", unsafe_allow_html=True)


# =====================================================
# SIDEBAR
# =====================================================

st.sidebar.title("🛡️ QuantumShield")

st.sidebar.caption(
    "Quantum-Safe Secure File Transfer"
)

st.sidebar.divider()

pages = [
    "Dashboard",
    "Identity Setup",
    "Send File",
    "Receive File",
    "Quantum Attack Lab",
    "Cryptography Comparison",
    "Security Reports"
]

selected_page = st.sidebar.radio(
    "Navigation",
    pages
)

st.sidebar.divider()

st.sidebar.caption("LOCAL PROTOTYPE")
st.sidebar.caption("Version 0.3.0")


# =====================================================
# DASHBOARD
# =====================================================

if selected_page == "Dashboard":

    st.markdown(
        '<div class="main-title">QuantumShield</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">'
        'A Quantum-Safe Secure File Transfer System'
        '</div>',
        unsafe_allow_html=True
    )

    st.divider()

    users = ["alice", "bob"]

    classical_users = sum(
        user_initialized(user)
        for user in users
    )

    pqc_users = sum(
        user_pqc_initialized(user)
        for user in users
    )

    incoming_count = len(
        list_incoming_transfers("bob")
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Classical Identities",
            f"{classical_users}/2"
        )

    with col2:
        st.metric(
            "PQC Identities",
            f"{pqc_users}/2"
        )

    with col3:
        st.metric(
            "Bob's Pending Transfers",
            incoming_count
        )

    st.divider()

    st.subheader("User Identities")

    for username in users:

        col1, col2, col3 = st.columns(3)

        with col1:
            st.write(username.capitalize())

        with col2:
            if user_initialized(username):
                st.success("RSA Ready")
            else:
                st.warning("RSA Setup Required")

        with col3:
            if user_pqc_initialized(username):
                st.success("PQC Ready")
            else:
                st.warning("PQC Setup Required")

    st.divider()

    st.subheader("Available Cryptographic Modes")

    classical, pqc = st.columns(2)

    with classical:

        st.info(
            """
            **Traditional Cryptography**

            - RSA-2048
            - RSA-OAEP
            - AES-256-GCM
            - RSA-PSS
            """
        )

    with pqc:

        st.success(
            """
            **Post-Quantum Cryptography**

            - ML-KEM-768
            - HKDF-SHA256
            - AES-256-GCM
            - ML-DSA-65
            """
        )


# =====================================================
# IDENTITY SETUP
# =====================================================

elif selected_page == "Identity Setup":

    st.title("🔑 Identity Setup")

    st.write(
        "Generate classical and post-quantum identities "
        "for Alice and Bob."
    )

    st.warning(
        "Use a strong password and keep it safe. "
        "Private keys are encrypted before being stored."
    )

    for username in ["alice", "bob"]:

        with st.expander(
            username.capitalize() + " — Key Management",
            expanded=True
        ):

            st.subheader("Classical Identity")

            if user_initialized(username):

                st.success(
                    "RSA-2048 key pair already initialized."
                )

            else:

                with st.form(
                    f"classical_setup_{username}"
                ):

                    classical_password = st.text_input(
                        "RSA private key password",
                        type="password"
                    )

                    classical_confirm = st.text_input(
                        "Confirm RSA password",
                        type="password"
                    )

                    classical_submit = st.form_submit_button(
                        "Generate RSA Keys"
                    )

                    if classical_submit:

                        if classical_password != classical_confirm:
                            st.error("Passwords do not match.")

                        elif len(classical_password) < 12:
                            st.error(
                                "Password must contain at least 12 characters."
                            )

                        else:

                            try:

                                initialize_user(
                                    username,
                                    classical_password
                                )

                                st.success(
                                    "RSA keys generated successfully!"
                                )

                                st.rerun()

                            except Exception as error:
                                st.error(str(error))

            st.divider()

            st.subheader("Post-Quantum Identity")

            if user_pqc_initialized(username):

                st.success(
                    "ML-KEM-768 and ML-DSA-65 keys initialized."
                )

                st.caption(
                    "PQC private keys are password-encrypted."
                )

            else:

                with st.form(
                    f"pqc_setup_{username}"
                ):

                    pqc_password = st.text_input(
                        "PQC private key password",
                        type="password"
                    )

                    pqc_confirm = st.text_input(
                        "Confirm PQC password",
                        type="password"
                    )

                    pqc_submit = st.form_submit_button(
                        "Generate PQC Keys"
                    )

                    if pqc_submit:

                        if pqc_password != pqc_confirm:
                            st.error("Passwords do not match.")

                        elif len(pqc_password) < 12:
                            st.error(
                                "Password must contain at least 12 characters."
                            )

                        else:

                            try:

                                with st.spinner(
                                    "Generating ML-KEM and ML-DSA keys..."
                                ):

                                    initialize_pqc_user(
                                        username,
                                        pqc_password
                                    )

                                st.success(
                                    "Post-quantum keys generated successfully!"
                                )

                                st.rerun()

                            except Exception as error:
                                st.error(str(error))


# =====================================================
# SEND FILE
# =====================================================

elif selected_page == "Send File":

    st.title("📤 Secure File Transfer")

    st.write(
        "Choose a cryptographic mode and send an encrypted file."
    )

    with st.form("send_file_form"):

        mode_label = st.radio(
            "Select Cryptographic Mode",
            [
                "Traditional (RSA + AES)",
                "Quantum-safe (ML-KEM + ML-DSA)"
            ]
        )

        mode = (
            "classical"
            if mode_label.startswith("Traditional")
            else "pqc"
        )

        sender = st.selectbox(
            "Sender",
            ["alice", "bob"]
        )

        recipient = (
            "bob" if sender == "alice" else "alice"
        )

        st.text_input(
            "Recipient",
            value=recipient.capitalize(),
            disabled=True
        )

        uploaded_file = st.file_uploader(
            "Select a file to transfer"
        )

        password = st.text_input(
            "Sender's private key password",
            type="password"
        )

        submitted = st.form_submit_button(
            "🔒 Encrypt and Send",
            use_container_width=True
        )

    if submitted:

        classical_ready = (
            user_initialized(sender)
            and user_initialized(recipient)
        )

        pqc_ready = (
            user_pqc_initialized(sender)
            and user_pqc_initialized(recipient)
        )

        if uploaded_file is None:

            st.error("Please select a file.")

        elif not password:

            st.error("Please enter the sender's password.")

        elif mode == "classical" and not classical_ready:

            st.error(
                "Both users need initialized RSA identities."
            )

        elif mode == "pqc" and not pqc_ready:

            st.error(
                "Both users need initialized PQC identities."
            )

        else:

            try:

                with st.spinner(
                    "Encrypting and creating transfer package..."
                ):

                    result = send_file(
                        uploaded_file.getvalue(),
                        uploaded_file.name,
                        sender,
                        recipient,
                        password,
                        mode=mode
                    )

                st.success(
                    "File successfully encrypted and transferred!"
                )

                st.subheader("Transfer Information")

                col1, col2, col3 = st.columns(3)

                with col1:
                    st.metric(
                        "File Size",
                        f"{result['size']:,} bytes"
                    )

                with col2:
                    st.metric(
                        "Encryption Mode",
                        "Quantum-safe" if mode == "pqc" else "Traditional"
                    )

                with col3:
                    st.metric(
                        "Status",
                        "Encrypted"
                    )

                st.write("**Transfer ID**")

                st.code(result["transfer_id"])

                st.write("**Algorithm**")

                st.code(result["algorithm"])

                st.info(
                    f"Transferred from {sender.capitalize()} "
                    f"to {recipient.capitalize()}."
                )

            except Exception as error:

                st.error(
                    f"Transfer failed: {error}"
                )


# =====================================================
# RECEIVE FILE
# =====================================================

elif selected_page == "Receive File":

    st.title("📥 Receive File")

    st.write(
        "View incoming transfers, verify signatures "
        "and decrypt encrypted files."
    )

    receiver = st.selectbox(
        "Receiver",
        ["alice", "bob"]
    )

    transfers = list_incoming_transfers(receiver)

    if not transfers:

        st.info("No incoming transfers found.")

    else:

        transfer_options = {}

        for item in transfers:

            label = (
                f"{item['filename']} | "
                f"From: {item['sender']} | "
                f"Mode: {item['mode']} | "
                f"ID: {item['transfer_id'][:8]}"
            )

            transfer_options[label] = item

        st.subheader("Incoming Transfers")

        selected_label = st.selectbox(
            "Select a transfer",
            list(transfer_options.keys())
        )

        selected_transfer = transfer_options[selected_label]

        st.write("**Transfer Details**")

        col1, col2 = st.columns(2)

        with col1:
            st.write(
                f"Sender: {selected_transfer['sender']}"
            )

            st.write(
                f"Filename: {selected_transfer['filename']}"
            )

        with col2:
            st.write(
                f"Mode: {selected_transfer['mode'].upper()}"
            )

            st.write(
                f"Algorithm: {selected_transfer['algorithm']}"
            )

        st.divider()

        with st.form("receive_file_form"):

            password = st.text_input(
                "Receiver's private key password",
                type="password"
            )

            submitted = st.form_submit_button(
                "🔓 Verify and Decrypt",
                use_container_width=True
            )

        if submitted:

            if not password:

                st.error("Please enter the recipient's password.")

            else:

                try:

                    output_directory = (
                        RECEIVED_DIR / receiver
                    )

                    with st.spinner(
                        "Verifying signature and decrypting file..."
                    ):

                        result = receive_file(
                            selected_transfer["path"],
                            receiver,
                            password,
                            str(output_directory)
                        )

                    st.success(
                        "Signature verified and file decrypted successfully!"
                    )

                    st.subheader("Verification Results")

                    st.success("Digital signature: VALID")
                    st.success("File integrity: VERIFIED")

                    st.write(
                        f"Sender: {result['sender']}"
                    )

                    st.write(
                        f"Encryption mode: {result['mode'].upper()}"
                    )

                    st.write(
                        f"File size: {result['size']:,} bytes"
                    )

                    output_path = Path(result["output_path"])

                    st.download_button(
                        "⬇️ Download Original File",
                        data=output_path.read_bytes(),
                        file_name=result["filename"],
                        mime="application/octet-stream"
                    )

                except Exception as error:

                    st.error(
                        f"Verification or decryption failed: {error}"
                    )


# =====================================================
# QUANTUM ATTACK LAB
# =====================================================


elif selected_page == "Quantum Attack Lab":

    st.title("⚛️ Quantum Attack Lab")

    st.write(
        "Explore quantum algorithms and understand "
        "their implications for conventional cryptography."
    )

    st.warning(
        "Educational simulations only. These experiments "
        "do not attack the application's actual encryption keys."
    )

    shor_tab, grover_tab = st.tabs([
        "Shor's Algorithm",
        "Grover's Algorithm"
    ])

    # =================================================
    # SHOR'S ALGORITHM
    # =================================================

    with shor_tab:

        st.subheader("Integer Factorization using Shor's Algorithm")

        st.markdown("""
        Shor's algorithm demonstrates how a sufficiently
        powerful quantum computer could threaten RSA
        by efficiently solving integer factorization.

        For this demonstration, we use:

        - Number: **15**
        - Base: **2**
        - Expected factors: **3 and 5**
        """)

        col1, col2 = st.columns(2)

        with col1:
            st.metric("Number to Factor", "15")

        with col2:
            st.metric("Quantum Base", "2")

        shots = st.select_slider(
            "Number of quantum measurements",
            options=[512, 1024, 2048, 4096],
            value=2048,
            key="shor_measurements"
        )

        if st.button(
            "▶ Run Shor's Algorithm",
            use_container_width=True,
            key="shor_run"
        ):

            try:

                with st.spinner(
                    "Executing quantum order-finding circuit..."
                ):

                    st.session_state["shor_result"] = (
                        run_shor_demo(
                            shots=shots,
                            seed=42
                        )
                    )

            except Exception as error:

                st.error(f"Shor simulation failed: {error}")

        shor_result = st.session_state.get("shor_result")

        if shor_result:

            st.divider()

            st.subheader("Factorization Results")

            if shor_result["factors"]:

                factor1, factor2 = shor_result["factors"]

                st.success(
                    f"Factorization successful: "
                    f"15 = {factor1} × {factor2}"
                )

                col1, col2, col3 = st.columns(3)

                with col1:
                    st.metric("Factor 1", factor1)

                with col2:
                    st.metric("Factor 2", factor2)

                with col3:
                    st.metric("Order Found", shor_result["order"])

            else:

                st.warning(
                    "No valid factorization was recovered. "
                    "Try another measurement count."
                )

            st.subheader("Quantum Measurement Distribution")

            shor_df = pd.DataFrame(
                list(shor_result["counts"].items()),
                columns=["Measurement", "Frequency"]
            )

            shor_df = shor_df.sort_values(
                "Frequency",
                ascending=False
            )

            st.bar_chart(
                shor_df.set_index("Measurement")
            )

            st.subheader("Phase Estimation Results")

            st.dataframe(
                pd.DataFrame(shor_result["phase_results"]),
                use_container_width=True,
                hide_index=True
            )

            with st.expander("View Quantum Circuit"):

                st.code(
                    str(
                        shor_result["circuit"].draw(
                            output="text",
                            fold=120
                        )
                    ),
                    language="text"
                )

            st.info(
                "Shor's algorithm uses quantum order finding, "
                "followed by classical continued-fraction and "
                "GCD calculations to recover the factors."
            )

    # =================================================
    # GROVER'S ALGORITHM
    # =================================================

    with grover_tab:

        st.subheader("Quantum Search using Grover's Algorithm")

        st.markdown("""
        Grover's algorithm demonstrates how quantum
        amplitude amplification can accelerate an
        unstructured search.

        Select a search-space size and a target value.
        The quantum circuit will attempt to identify
        the marked state.
        """)

        num_qubits = st.slider(
            "Number of Qubits",
            min_value=2,
            max_value=8,
            value=4,
            key="grover_qubits"
        )

        search_space = 2**num_qubits

        target_value = st.number_input(
            "Target Value",
            min_value=0,
            max_value=search_space - 1,
            value=min(5, search_space - 1),
            step=1,
            key="grover_target"
        )

        target_binary = format(
            int(target_value),
            f"0{num_qubits}b"
        )

        st.info(
            f"Search space: {search_space} possibilities | "
            f"Target state: {target_binary}"
        )

        grover_shots = st.select_slider(
            "Number of measurements",
            options=[512, 1024, 2048, 4096],
            value=2048,
            key="grover_measurements"
        )

        if st.button(
            "▶ Run Grover's Algorithm",
            use_container_width=True,
            key="grover_run"
        ):

            try:

                with st.spinner(
                    "Executing Grover quantum search..."
                ):

                    st.session_state["grover_result"] = (
                        run_grover_search(
                            num_qubits=num_qubits,
                            target_value=int(target_value),
                            shots=grover_shots,
                            seed=42
                        )
                    )

                    st.session_state["grover_config"] = (
                        num_qubits,
                        int(target_value),
                        grover_shots
                    )

            except Exception as error:

                st.error(f"Grover simulation failed: {error}")

        grover_result = st.session_state.get("grover_result")

        current_config = (
            num_qubits,
            int(target_value),
            grover_shots
        )

        previous_config = st.session_state.get("grover_config")

        if grover_result and current_config == previous_config:

            st.divider()

            st.subheader("Quantum Search Results")

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric(
                    "Search Space",
                    grover_result["search_space"]
                )

            with col2:
                st.metric(
                    "Grover Iterations",
                    grover_result["iterations"]
                )

            with col3:
                st.metric(
                    "Target Probability",
                    f"{grover_result['success_probability']:.2%}"
                )

            st.success(
                f"Target state {grover_result['target']} "
                f"was measured {grover_result['target_hits']} "
                f"times out of {grover_result['shots']} measurements."
            )

            st.subheader("Measurement Distribution")

            grover_df = pd.DataFrame(
                list(grover_result["counts"].items()),
                columns=["Quantum State", "Frequency"]
            )

            grover_df = grover_df.sort_values(
                "Frequency",
                ascending=False
            )

            st.bar_chart(
                grover_df.set_index("Quantum State")
            )

            with st.expander("View Oracle Circuit"):

                st.code(
                    str(
                        grover_result["oracle"].draw(
                            output="text",
                            fold=120
                        )
                    ),
                    language="text"
                )

            with st.expander("View Complete Quantum Circuit"):

                st.code(
                    str(
                        grover_result["circuit"].draw(
                            output="text",
                            fold=120
                        )
                    ),
                    language="text"
                )

            st.info(
                "Grover's algorithm provides a quadratic "
                "query-complexity speedup for unstructured search. "
                "This demonstration uses a small simulated search space."
            )

        elif grover_result and current_config != previous_config:

            st.caption(
                "Change the parameters and run the simulation "
                "again to generate updated results."
            )


# =====================================================
# CRYPTOGRAPHY COMPARISON
# =====================================================

elif selected_page == "Cryptography Comparison":

    render_benchmark_dashboard()

# =====================================================
# SECURITY REPORTS
# =====================================================


elif selected_page == "Security Reports":

    st.title("🛡️ Security Reports")

    st.write(
        "Monitor QuantumShield transfer activity "
        "and security-related events."
    )

    initialize_security_store()

    events = get_audit_events(limit=200)

    if not events:

        st.info(
            "No security events have been recorded yet."
        )

    else:

        df = pd.DataFrame(events)

        total_events = len(df)

        successful = len(
            df[df["outcome"] == "success"]
        )

        blocked = len(
            df[df["outcome"] == "blocked"]
        )

        failed = len(
            df[df["outcome"] == "failure"]
        )

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Events", total_events)

        with col2:
            st.metric("Successful", successful)

        with col3:
            st.metric("Blocked", blocked)

        with col4:
            st.metric("Failed", failed)

        st.divider()

        st.subheader("Security Event History")

        event_filter = st.selectbox(
            "Filter events",
            [
                "All",
                "Success",
                "Blocked",
                "Failure"
            ]
        )

        if event_filter != "All":

            df = df[
                df["outcome"] == event_filter.lower()
            ]

        display_columns = [
            "timestamp",
            "event_type",
            "username",
            "transfer_id",
            "mode",
            "outcome",
            "details"
        ]

        st.dataframe(
            df[display_columns],
            use_container_width=True,
            hide_index=True
        )

        st.download_button(
            "⬇️ Export Security Audit Log",
            data=df[display_columns].to_csv(index=False),
            file_name="quantumshield_security_audit.csv",
            mime="text/csv"
        )

        st.caption(
            "Audit logs contain event metadata only. "
            "Passwords, private keys and original file contents "
            "are not included."
        )

