import streamlit as st

st.set_page_config(
    page_title="Cybercrime Analysis",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Cybercrime Analysis System")
st.write("Cybercrime awareness, reporting and analysis dashboard")

st.sidebar.title("Navigation")
page = st.sidebar.radio(
    "Choose a page",
    ["Home", "Report an Incident", "Cyber Safety"]
)

if page == "Home":
    st.subheader("Dashboard")
    st.info("Welcome to the Cybercrime Analysis System.")
    st.write("Use the menu to explore the available features.")

elif page == "Report an Incident":
    st.subheader("Report a Cybercrime")
    with st.form("incident_form"):
        incident_type = st.selectbox(
            "Incident type",
            ["Phishing", "Online Fraud", "Identity Theft", "Other"]
        )
        description = st.text_area("Incident description")
        submitted = st.form_submit_button("Submit Report")

        if submitted:
            if description.strip():
                st.success("Demo form submitted successfully.")
                st.write("Incident type:", incident_type)
            else:
                st.warning("Please enter a description.")

elif page == "Cyber Safety":
    st.subheader("Cyber Safety Tips")
    st.write("- Never share your OTP or password.")
    st.write("- Verify links before clicking.")
    st.write("- Use strong, unique passwords.")
    st.write("- Report suspicious online activity.")