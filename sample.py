import streamlit as st
import whois
import tldextract
from datetime import datetime

st.set_page_config(page_title="Phishing Email Domain Checker", layout="centered")

st.title("🔎 Phishing — Email Domain Checker")
st.markdown(
    "Enter an email address below. The app will extract the domain and fetch WHOIS/history details (creation, update, expiry, registrar, name servers)."
)


def extract_domain_from_email(email: str) -> str | None:
    try:
        domain_part = email.split("@")[1]
        ext = tldextract.extract(domain_part)
        root_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        return root_domain
    except Exception:
        return None


def get_domain_history(domain: str) -> dict:
    """Return a dictionary of WHOIS-related fields for display and further processing."""
    w = whois.whois(domain)

    def _pick_date(d):
        if isinstance(d, list):
            d = d[0]
        return d

    created = _pick_date(w.creation_date) if getattr(w, "creation_date", None) else None
    updated = _pick_date(w.updated_date) if getattr(w, "updated_date", None) else None
    expiry = _pick_date(w.expiration_date) if getattr(w, "expiration_date", None) else None

    data = {
        "domain": domain,
        "registrar": getattr(w, "registrar", None),
        "creation_date": created.strftime("%d %B %Y") if isinstance(created, datetime) else str(created) if created else None,
        "updated_date": updated.strftime("%d %B %Y") if isinstance(updated, datetime) else str(updated) if updated else None,
        "expiry_date": expiry.strftime("%d %B %Y") if isinstance(expiry, datetime) else str(expiry) if expiry else None,
        "name_servers": list(getattr(w, "name_servers", []) or []),
        # include the raw WHOIS object for debugging (as string)
        "raw_whois": str(w)
    }

    return data


# --- UI ---
email = st.text_input("Enter an Email:", placeholder="example@domain.com")
col1, col2 = st.columns([1, 1])

with col1:
    check = st.button("Check Domain")
with col2:
    clear = st.button("Clear")

if clear:
    st.experimental_rerun()

if check:
    if not email:
        st.error("Please enter an email address.")
    else:
        with st.spinner("Extracting domain and fetching WHOIS..."):
            domain = extract_domain_from_email(email.strip())
            if not domain:
                st.error("Could not extract a valid domain from that email.")
            else:
                st.success(f"Extracted domain: **{domain}**")
                try:
                    info = get_domain_history(domain)

                    st.subheader("Domain History / WHOIS Summary")
                    st.write("**Registrar:**", info.get("registrar") or "—")
                    st.write("**Creation date:**", info.get("creation_date") or "—")
                    st.write("**Last updated:**", info.get("updated_date") or "—")
                    st.write("**Expires on:**", info.get("expiry_date") or "—")

                    if info.get("name_servers"):
                        st.write("**Name servers:**")
                        st.write(", ".join(info.get("name_servers")))

                    # Raw WHOIS (collapsible)
                    with st.expander("Show raw WHOIS output"):
                        st.code(info.get("raw_whois"))

                    # Offer to download results as text
                    txt = (
                        f"Domain: {info.get('domain')}\n"
                        f"Registrar: {info.get('registrar')}\n"
                        f"Creation date: {info.get('creation_date')}\n"
                        f"Last updated: {info.get('updated_date')}\n"
                        f"Expiry date: {info.get('expiry_date')}\n"
                        f"Name servers: {', '.join(info.get('name_servers') or [])}\n\n"
                        f"Raw WHOIS:\n{info.get('raw_whois')}"
                    )

                    st.download_button("Download WHOIS report (.txt)", txt, file_name=f"{domain}_whois.txt")

                except Exception as e:
                    st.error(f"Error fetching WHOIS info: {e}")


st.markdown("---")
st.caption("Built with Streamlit — uses the `whois` and `tldextract` Python packages.")
