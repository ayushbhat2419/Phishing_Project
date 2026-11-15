# Dataset Provenance, Preprocessing & Validation Specification (Phase 2)

**Document Version:** 1.0.0  
**Status:** Implemented  

---

## 1. Overview of Data Sources

To train robust, production-grade detection engines without synthetic bias or data fabrication, our system utilizes established cybersecurity benchmark corpora for both URL and Email classification.

### 1.1 URL Datasets
| Dataset Source | Category | Target Label | Description |
| :--- | :--- | :--- | :--- |
| **PhishTank** (Open Threat Feed) | Phishing | `1` (Phishing) | Verified, human-vetted active and historical phishing URLs capturing real-world credential harvesting, banking impersonation, and zero-hour scams. |
| **OpenPhish** (Community Feed) | Phishing | `1` (Phishing) | Continuously updated autonomous feed of live malicious phishing URLs across diverse top-level domains. |
| **ISCX / Kaggle Phishing URLs** | Phishing & Benign | `1` & `0` | Standard benchmark datasets curated by the University of New Brunswick and cybersecurity researchers. |
| **Tranco Top 100K / Benign Alexa Corpus** | Benign / Legitimate | `0` (Legitimate) | Top global authoritative domains with realistic deep URLs, HTTPS configurations, documentation links, API paths, and e-commerce portals. |

### 1.2 Email Datasets
| Dataset Source | Category | Target Label | Description |
| :--- | :--- | :--- | :--- |
| **Jose Nazario Phishing Corpus** | Phishing | `1` (Phishing) | Recognized academic collection of real phishing emails targeting financial institutions, webmail accounts, and enterprise credentials. |
| **SpamAssassin / Apache Public Corpus** | Phishing & Spam | `1` (Phishing/Spam) | Historical collection of flagged email spam and social engineering attacks. |
| **Enron Email Corpus (Cleaned Subset)** | Benign / Legitimate | `0` (Legitimate) | Real-world business communications covering scheduling, status reports, vendor communications, and internal project updates. |
| **Kaggle Phishing Email Benchmark** | Phishing & Benign | `1` & `0` | Cleaned and labeled collection of modern phishing attacks, tech-support scams, and genuine notifications. |

---

## 2. Dataset Schemas & Columns

### 2.1 Cleaned URL Dataset Schema (`ml/datasets/processed/urls_processed.csv`)
| Column Name | Data Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `url` | String | Raw candidate URL (normalized scheme/casing) | `https://secure-login.bank.com.co.vu/auth` |
| `label` | Integer | Binary ground truth (`1` = Phishing, `0` = Legitimate) | `1` |
| `domain` | String | Extracted fully qualified domain name (FQDN) | `secure-login.bank.com.co.vu` |
| `tld` | String | Extracted top-level domain | `vu` |
| `source` | String | Corpus provenance indicator | `phishtank` / `tranco` |

### 2.2 Cleaned Email Dataset Schema (`ml/datasets/processed/emails_processed.csv`)
| Column Name | Data Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `id` | String | Unique hash identifier (SHA-256) | `e2a7b1...` |
| `sender` | String | Sender email or display header | `security@account-update.xyz` |
| `subject` | String | Email subject line | `URGENT: Verify your account within 24h` |
| `body` | String | Raw text body of the email | `Dear user, your access has expired...` |
| `cleaned_text`| String | Normalized, lowercased, lemmatized tokens | `dear user access expire verify immediately` |
| `label` | Integer | Binary classification (`1` = Phishing, `0` = Legitimate) | `1` |
| `has_links` | Boolean | Presence of embedded hyperlinks | `True` |

---

## 3. Data Cleaning, Imbalance & Leakage Prevention Pipeline

```
Raw Sources (PhishTank, Tranco, Enron, Nazario)
                      │
                      ▼
        [1. Deduplication & Sanitization]
         - Strip leading/trailing whitespaces
         - Case-normalize schemes & hostnames
         - Drop duplicate URL strings and duplicate email bodies
                      │
                      ▼
        [2. Anomaly & Corruption Filtering]
         - Remove unparseable URLs (null bytes, invalid characters)
         - Drop empty email subjects/bodies (< 10 characters)
         - Strip exact personal identifier artifacts
                      │
                      ▼
        [3. Class Balance Enforcement]
         - Subsample majority class to maintain balanced ratio (e.g. 50/50 or 60/40)
         - Ensure diverse representation across TLDs and threat categories
                      │
                      ▼
        [4. Stratified Train / Validation / Test Splitting]
         - 80% Training Set, 20% Held-Out Test Set (Stratified on target label)
         - ZERO data leakage: Feature scalers, TF-IDF vectorizers, and imputation
           parameters are fit EXCLUSIVELY on the Training split!
```

### 3.1 Strict Data Leakage Safeguards
1. **No Domain Overlap in URL Splits:** Where applicable, URLs from the exact same high-volume domain are prevented from spanning across train and test sets to avoid synthetic over-optimistic memorization.
2. **Vectorization Boundary:** The TF-IDF vectorizer vocabulary and IDF weights are computed strictly on `X_train`. Unseen test tokens are gracefully handled via standard out-of-vocabulary smoothing.
3. **Reproducibility Guarantee:** All splits use explicit random seeds (`random_state=42`) allowing bit-for-bit reproducible runs across developer environments.
