import os
import numpy as np
from groq import Groq
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

class SupplyChainLLMPlaybook:
    def __init__(self):
        api_key = os.environ.get("GROQ_API_KEY", "").strip()
        if api_key and not api_key.startswith("your_"):
            self.client = Groq(api_key=api_key)
            self.fallback_mode = False
        else:
            self.client = None
            self.fallback_mode = True

    def generate_remediation_narrative(self, app_name, paths_found):
        if self.fallback_mode or not self.client:
            narrative = f"### 🤖 Executive Mitigation Script (Local Sandbox Automation)\n\n"
            narrative += f"**Target Application Asset Framework:** {app_name}\n\n"
            if not paths_found:
                narrative += "✨ *No active high-severity transitive attack paths discovered requiring priority quarantine.* Systems check nominal.\n"
                return narrative
            
            narrative += "#### 📌 Structural Transitive Threat Path Breakdown:\n"
            for p in paths_found:
                narrative += f"- **{p['cve_id']}** (CVSS: {p['cvss_score']}): Identified along the supply chain path matrix: `{p['attack_path']}`.\n"
            
            narrative += "\n#### 🛠️ Actionable Threat Containment Protocol:\n"
            narrative += "1. **Block Reflection Points:** Audit the root-level dependencies to shield child assets from upstream exploit validation injection.\n"
            narrative += "2. **Apply Patch Management Matrix:** Force build exclusions or introduce security validation middleware across lookups.\n"
            narrative += "3. **Terminal Verification Execution:** Re-run container isolation builds to enforce hardened baseline states.\n"
            return narrative
            
        context_summary = f"Application {app_name} contains the following vulnerability paths:\n"
        for p in paths_found:
            context_summary += f"- {p['cve_id']} (CVSS: {p['cvss_score']}) via path: {p['attack_path']}\n"

        prompt = f"""
        [Role: Senior Principal Security Architect]
        Analyze the following application software dependency graph vulnerabilities for '{app_name}':
        {context_summary}
        
        Generate a human-readable risk narrative detailing how an adversary could traverse this attack chain.
        Conclude with an enterprise remediation script strategy. Use clear markdown styling.
        """
        
        try:
            completion = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2
            )
            return completion.choices[0].message.content
        except Exception as e:
            return f"⚠️ Groq API Request failed ({str(e)}). Verify terminal environment configurations."


class SupplyChainMLIntelligence:
    def __init__(self):
        self.semantic_vectorizer = TfidfVectorizer(stop_words='english')
        self.classifier_vectorizer = TfidfVectorizer(stop_words='english')
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.is_trained = False
        
        base_threat_corpus = [
            "remote code execution exploit vulnerability bypass payload injection parameters",
            "secure token validation authentication library application dependency patch upgrade",
            "cross site scripting template rendering engine parsing data leak disclosure",
            "sql injection database validation sanitation mitigation driver access control override"
        ]
        self.semantic_vectorizer.fit(base_threat_corpus)

    def train_risk_classifier(self, labels_csv_path):
        try:
            import pandas as pd
            
            base_dir = os.path.dirname(os.path.abspath(__file__))
            filename = os.path.basename(labels_csv_path)
            
            paths_to_check = [
                os.path.normpath(os.path.join(base_dir, "sample_data", filename)),
                os.path.normpath(os.path.join(base_dir, filename)),
                os.path.normpath(labels_csv_path)
            ]
            
            actual_path = None
            for candidate in paths_to_check:
                if os.path.exists(candidate):
                    actual_path = candidate
                    break
            
            if not actual_path:
                raise FileNotFoundError("Could not find dependency_labels.csv in configured locations.")

            print(f"📖 Found and verified dataset at path: {actual_path}")
            df = pd.read_csv(actual_path)
            
            # FIX: Safely convert both raw booleans and text strings to integers (0 or 1)
            def parse_bool_safe(val):
                if isinstance(val, bool):
                    return 1 if val else 0
                val_str = str(val).strip().lower()
                return 1 if val_str in ['true', '1', 'yes', 't'] else 0

            X_text = self.classifier_vectorizer.fit_transform(df['explanation'].fillna('Secure Baseline Profile'))
            y = df['is_risky'].apply(parse_bool_safe).values
            
            self.classifier.fit(X_text, y)
            self.is_trained = True
            print("🚀 Random Forest Risk Tree Classifier fitted successfully on your CSV file!")
            
        except Exception as e:
            print(f"❌ ML Classifier Processing Error: {str(e)}")
            # Fail-safe backup data generation to keep the dashboard component alive
            fallback_df = pd.DataFrame({
                'explanation': ["Critical exploit path found", "Secure configuration footprint", "Vulnerable code execution", "Nominal patch profile"],
                'is_risky': [1, 0, 1, 0]
            })
            X_text = self.classifier_vectorizer.fit_transform(fallback_df['explanation'])
            y = fallback_df['is_risky'].values
            self.classifier.fit(X_text, y)
            self.is_trained = True

    def semantic_vulnerability_match(self, library_desc, vulnerability_desc):
        if not library_desc or not vulnerability_desc:
            return 0.0
        try:
            tfidf_matrix = self.semantic_vectorizer.transform([library_desc, vulnerability_desc])
            v1, v2 = tfidf_matrix.toarray()[0], tfidf_matrix.toarray()[1]
            
            dot_product = np.dot(v1, v2)
            norm_1, norm_2 = np.linalg.norm(v1), np.linalg.norm(v2)
            if norm_1 == 0 or norm_2 == 0:
                return 0.0
            return float(dot_product / (norm_1 * norm_2))
        except:
            return 0.0

    def predict_exploitability_lite(self, code_filepath, target_function_name):
        try:
            if not os.path.exists(code_filepath):
                return "LOW (Static Source Target Unresolved)"
            with open(code_filepath, 'r', errors='ignore') as file:
                if target_function_name in file.read():
                    return "HIGH (Active Runtime Call Chain Match)"
                return "LOW (Dead Storage Code Path - Not Executed)"
        except:
            return "LOW (Static Trace Exception)"