# VITyarthi-Project
import re
import math
from typing import Dict, Tuple, List

class PasswordStrengthChecker:
    def __init__(self):
        # Common patterns to detect
        self.common_passwords = {
            "password", "123456", "123456789", "qwerty", "abc123",
            "password123", "admin", "letmein", "welcome", "iloveyou"
        }
        
        # Common patterns
        self.patterns = {
            'sequential': r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)',
            'repeated': r'(.)\1\1\1',  # 4 or more repeated chars
            'keyboard': r'(qwe|rty|asd|fgh|zxc|vbn|qwerty|asdfg|zxcvb)',
        }

    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>?/~`]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        return len(password) * math.log2(charset_size)

    def check_common_password(self, password: str) -> bool:
        return password.lower() in self.common_passwords

    def check_patterns(self, password: str) -> List[str]:
        issues = []
        lower_pass = password.lower()
        
        for name, pattern in self.patterns.items():
            if re.search(pattern, lower_pass):
                issues.append(name)
        
        return issues

    def check_personal_info(self, password: str, username: str = "", email: str = "", name: str = "") -> List[str]:
        issues = []
        checks = [s.lower() for s in [username, email.split('@')[0] if email else "", name] if s]
        
        for info in checks:
            if info and len(info) >= 3 and info in password.lower():
                issues.append(f"Contains personal info: {info}")
        return issues

    def assess_strength(self, password: str, username: str = "", email: str = "", name: str = "") -> Dict:
        if not password:
            return {"score": 0, "strength": "Empty", "feedback": ["Password cannot be empty"]}

        length = len(password)
        feedback = []
        warnings = []

        # 1. Too short
        if length < 8:
            feedback.append("Password is too short (minimum 8 characters)")
        elif length < 12:
            feedback.append("Consider using 12+ characters for better security")

        # 2. Common password check
        if self.check_common_password(password):
            warnings.append("This is a very common password")

        # 3. Character variety
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>?/~`]', password))

        variety_count = sum([has_lower, has_upper, has_digit, has_special])
        
        if variety_count < 3:
            feedback.append("Use a mix of uppercase, lowercase, numbers, and symbols")

        # 4. Patterns
        patterns_found = self.check_patterns(password)
        for pattern in patterns_found:
            if pattern == "sequential":
                feedback.append("Avoid sequential characters (like 'abc' or '123')")
            elif pattern == "repeated":
                feedback.append("Avoid repeated characters (like 'aaaa')")
            elif pattern == "keyboard":
                feedback.append("Avoid keyboard patterns (like 'qwerty' or 'asdf')")

        # 5. Personal info
        personal_issues = self.check_personal_info(password, username, email, name)
        warnings.extend(personal_issues)

        # 6. Entropy calculation
        entropy = self.calculate_entropy(password)

        # Final scoring (0-100)
        score = 0
        if length >= 8:   score += 20
        if length >= 12:  score += 20
        if length >= 16:  score += 10
        if variety_count >= 3: score += 20
        if variety_count >= 4: score += 10
        if entropy >= 60: score += 20
        if not patterns_found: score += 10
        if not self.check_common_password(password): score += 10

        # Deductions
        if length < 8: score = min(score, 20)
        if self.check_common_password(password): score = 10

        # Determine strength level
        if score >= 90 and entropy >= 70:
            strength = "Very Strong"
        elif score >= 70:
            strength = "Strong"
        elif score >= 50:
            strength = "Moderate"
        elif score >= 30:
            strength = "Weak"
        else:
            strength = "Very Weak"

        return {
            "score": min(score, 100),
            "strength": strength,
            "entropy": round(entropy, 1),
            "length": length,
            "has_uppercase": has_upper,
            "has_lowercase": has_lower,
            "has_digits": has_digit,
            "has_special": has_special,
            "feedback": feedback or ["Great password!"],
            "warnings": warnings,
            "crack_time": self.estimate_crack_time(entropy)
        }

    def estimate_crack_time(self, entropy: float) -> str:
        """Rough estimate of online cracking time"""
        if entropy < 28:
            return "Less than a second"
        elif entropy < 36:
            return "Seconds"
        elif entropy < 50:
            return "Minutes to hours"
        elif entropy < 60:
            return "Days to months"
        elif entropy < 80:
            return "Years to centuries"
        elif entropy < 100:
            return "Thousands to millions of years"
        else:
            return "Virtually impossible"

# === Usage Example ===
if __name__ == "__main__":
    checker = PasswordStrengthChecker()
    
    while True:
        pwd = input("\nEnter a password (or 'quit' to exit): ").strip()
        if pwd.lower() == 'quit':
            break
            
        result = checker.assess_strength(
            password=pwd,
            username="john_doe",
            email="john@example.com",
            name="John"
        )
        
        print(f"\nPassword: {'*' * len(pwd)}")
        print(f"Strength: {result['strength']} (Score: {result['score']}/100)")
        print(f"Entropy: {result['entropy']} bits")
        print(f"Estimated crack time: {result['crack_time']}")
        
        if result['warnings']:
            print(" WARNINGS:")
            for w in result['warnings']:
                print(f"   â€¢ {w}")
                
        print(" Suggestions:")
        for f in result['feedback']:
            print(f"  {f}")
