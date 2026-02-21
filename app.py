from flask import Flask, render_template, request, session, redirect, url_for, jsonify, flash
from config import Config
import os

app = Flask(__name__)
app.config.from_object(Config)

# Game State Constants
MODULE_DATA = {
    1: {
        "title": "Introduction to InfoSec",
        "type": "infosec",
        "theory": "Information Security relies on the CIA Triad: Confidentiality (keeping data secret), Integrity (ensuring data isn't tampered with), and Availability (ensuring access). Authentication verifies identity, while Non-repudiation prevents denial of actions.",
        "tool_name": "CyberChef (Base64)",
        "external_tool_url": "https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)",
        "mission_cipher": "Q09ORklERU5USUFMSVRZX0lOVEVHUklUWV9BVkFJTEFCSUxJVFk=",
        "correct_answer": "CONFIDENTIALITY_INTEGRITY_AVAILABILITY",
        "hint": "The flag is encoded in Base64. It represents the CIA triad components joined by underscores.",
        "reference_links": [
            {"label": "Base64 (MDN Glossary)", "url": "https://developer.mozilla.org/en-US/docs/Glossary/Base64"},
            {"label": "CIA Triad (Information Security - Wikipedia)", "url": "https://en.wikipedia.org/wiki/Information_security#CIA_triad"}
        ]
    },
    2: {
        "title": "Math Foundations",
        "type": "math",
        "theory": "Cryptography relies on mathematical concepts like Bijections (one-to-one correspondence) and Trapdoor Functions (easy to compute one way, hard the other). Plaintext is the original message; Ciphertext is the scrambled result.",
        "tool_name": "WolframAlpha",
        "external_tool_url": "https://www.wolframalpha.com/",
        "mission_cipher": "Find x if 3x + 7 = 4 (mod 26).",
        "correct_answer": "25",
        "hint": "Solve 3x + 7 ≡ 4 (mod 26). 3x ≡ -3 ≡ 23 (mod 26). Multiply by modular inverse of 3.",
        "reference_links": [
            {"label": "Modular Arithmetic (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Modular_arithmetic"},
            {"label": "Modular Multiplicative Inverse (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Modular_multiplicative_inverse"}
        ]
    },
    3: {
        "title": "Encryption Paradigms",
        "type": "theory",
        "theory": "Symmetric encryption uses the SAME key for encryption and decryption (fast, but key exchange is hard). Asymmetric uses a Public/Private key pair (slower, solves key exchange). Hybrid systems use Asymmetric to exchange a Symmetric key.",
        "tool_name": "AES Encryption Tool",
        "external_tool_url": "https://www.devglan.com/online-tools/aes-encryption-decryption",
        "mission_cipher": "Alice encrypts with Bob's Public Key. Bob decrypts with his Private Key. What paradigm is this?",
        "correct_answer": "ASYMMETRIC",
        "hint": "Is it Symmetric, Asymmetric, or Hybrid?",
        "reference_links": [
            {"label": "Public-Key Cryptography (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Public-key_cryptography"},
            {"label": "Symmetric-Key Algorithm (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Symmetric-key_algorithm"}
        ]
    },
    4: {
        "title": "Advanced Math",
        "type": "math",
        "theory": "Complexity Theory classifies problems by difficulty (P vs NP). 'Work Factor' is the effort to break a system. Algebraic Structures like Groups, Rings, and Fields form the basis of many algorithms.",
        "tool_name": "Big Number Calculator",
        "external_tool_url": "https://www.calculator.net/big-number-calculator.html",
        "mission_cipher": "Calculate 2^10 mod 11.",
        "correct_answer": "1",
        "hint": "Fermat's Little Theorem: a^(p-1) ≡ 1 (mod p) if p is prime.",
        "reference_links": [
            {"label": "Fermat's Little Theorem (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Fermat%27s_little_theorem"},
            {"label": "Modular Exponentiation (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Modular_exponentiation"}
        ]
    },
    5: {
        "title": "Probability & Number Theory",
        "type": "math",
        "theory": "Entropy measures randomness/unpredictability. Modular Arithmetic (clock math) is central to crypto. The Greatest Common Divisor (GCD) is used in algorithms like RSA (Extended Euclidean Algorithm).",
        "tool_name": "GCD Calculator",
        "external_tool_url": "https://www.alcula.com/calculators/math/gcd/#gsc.tab=0",
        "mission_cipher": "Calculate GCD(1071, 462)",
        "correct_answer": "21",
        "hint": "Use the Euclidean algorithm.",
        "reference_links": [
            {"label": "Euclidean Algorithm (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Euclidean_algorithm"},
            {"label": "Greatest Common Divisor (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Greatest_common_divisor"}
        ]
    },
    6: {
        "title": "Number-Theoretic Problems",
        "type": "math",
        "theory": "Integer Factorization (breaking a composite number into primes) is the hardness assumption behind RSA. Discrete Logarithm is the basis for Diffie-Hellman and ElGamal.",
        "tool_name": "FactorDB",
        "external_tool_url": "http://factordb.com/",
        "mission_cipher": "Factorize: 3233",
        "correct_answer": "53, 61",
        "hint": "The factors are two prime numbers. Input as 'small, large' (e.g., 3, 5).",
        "reference_links": [
            {"label": "Integer Factorization (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Integer_factorization"},
            {"label": "Fundamental Theorem of Arithmetic (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Fundamental_theorem_of_arithmetic"}
        ]
    },
    7: {
        "title": "RSA & Quadratic Residuosity",
        "type": "rsa",
        "theory": "RSA security relies on the e-th root problem. Quadratic Residuosity involves determining if a number is a perfect square modulo n. These hard problems secure data against unauthorized decryption.",
        "tool_name": "RSA Calculator",
        "external_tool_url": "https://www.cs.drexel.edu/~popyack/Courses/CSP/Fa17/notes/10.1_Cryptography/RSAWorksheetv4e.html",
        "mission_cipher": {"p": 61, "q": 53, "e": 17},
        "correct_answer": "2753",
        "hint": "d is the modular inverse of e mod (p-1)(q-1).",
        "reference_links": [
            {"label": "RSA Cryptosystem (Wikipedia)", "url": "https://en.wikipedia.org/wiki/RSA_cryptosystem"},
            {"label": "Modular Multiplicative Inverse (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Modular_multiplicative_inverse"}
        ]
    },
    8: {
        "title": "Parameters & Primality",
        "type": "math",
        "theory": "Secure prime selection is critical. We use probabilistic tests like Fermat and Miller-Rabin to find 'industrial grade' primes quickly, as deterministic testing is too slow for large numbers.",
        "tool_name": "Miller-Rabin Calculator",
        "external_tool_url": "https://planetcalc.com/8995/",
        "mission_cipher": "Is 7919 a prime number? (YES/NO)",
        "correct_answer": "YES",
        "hint": "It is the 1000th prime number.",
        "reference_links": [
            {"label": "Primality Test (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Primality_test"},
            {"label": "Miller–Rabin Primality Test (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test"}
        ]
    },
    9: {
        "title": "Prime Generation & Stream Ciphers",
        "type": "crypto",
        "theory": "Stream ciphers encrypt data bit-by-bit using a pseudorandom keystream combined with plaintext (usually via XOR). High-bit-length primes are generated for keys.",
        "tool_name": "CyberChef (XOR)",
        "external_tool_url": "https://xor.pw/#",
        "mission_cipher": "Plaintext 0x41 XOR Key 0x35",
        "correct_answer": "74",
        "hint": "Result in Hex. 41 ^ 35.",
        "reference_links": [
            {"label": "Exclusive OR (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Exclusive_or"},
            {"label": "Hexadecimal (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Hexadecimal"}
        ]
    },
    10: {
        "title": "LFSRs",
        "type": "crypto",
        "theory": "Linear Feedback Shift Registers (LFSRs) are used to generate pseudo-random numbers for stream ciphers. They shift bits and use feedback taps to determine the next input bit.",
        "tool_name": "LFSR Simulator",
        "external_tool_url": "https://www.dcode.fr/linear-feedback-shift-register",
        "mission_cipher": "3-bit LFSR (x^3 + x + 1). Start: 100. Next state?",
        "correct_answer": "001",
        "hint": "Shift right. New bit (MSB or LSB depending on convention, assume standard) comes from taps.",
        "reference_links": [
            {"label": "Linear-Feedback Shift Register (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Linear-feedback_shift_register"},
            {"label": "Shift Register (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Shift_register"}
        ]
    },
    11: {
        "title": "Block Ciphers",
        "type": "crypto",
        "theory": "Block ciphers operate on fixed-length groups of bits (blocks). Modes of operation like ECB (Electronic Codebook) and CBC (Cipher Block Chaining) determine how multiple blocks are handled.",
        "tool_name": "AES Encryption",
        "external_tool_url": "https://the-x.cn/en-US/cryptography/Aes.aspx",
        "mission_cipher": "Does ECB hide data patterns in images? (YES/NO)",
        "correct_answer": "NO",
        "hint": "Think of the famous Linux Penguin image encrypted with ECB.",
        "reference_links": [
            {"label": "Block Cipher Mode of Operation (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation"},
            {"label": "Electronic Code Book (TechTarget)", "url": "https://www.techtarget.com/searchsecurity/definition/Electronic-Code-Book"}
        ]
    },
    12: {
        "title": "Classical Evolution",
        "type": "caesar",
        "theory": "Classical ciphers like Caesar (shift) and Vigenère (polyalphabetic) relied on security through obscurity. Frequency analysis broke them, leading to modern Public-Key cryptography.",
        "tool_name": "Cryptii (Caesar)",
        "external_tool_url": "https://cryptii.com/pipes/caesar-cipher",
        "mission_cipher": "WKH SDVVZRUG LV VHFXUHBQRGH",
        "correct_answer": "THE PASSWORD IS SECUREYNODE",
        "hint": "Shift -3.",
        "reference_links": [
            {"label": "Caesar Cipher (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Caesar_cipher"},
            {"label": "Caesar Cipher (CryptoMuseum)", "url": "https://www.cryptomuseum.com/crypto/caesar/cipher.htm"}
        ]
    },
    13: {
        "title": "Core Public-Key Algorithms",
        "type": "crypto",
        "theory": "RSA, Rabin, and El Gamal are core public-key algorithms. RSA relies on factorization, El Gamal on Discrete Logarithms. They enable secure communication without pre-shared keys.",
        "tool_name": "ElGamal Calculator",
        "external_tool_url": "https://www.calculator.net/big-number-calculator.html",
        "mission_cipher": "ElGamal: p=23, g=5, x=3. Find h = g^x mod p.",
        "correct_answer": "10",
        "hint": "Calculate 5^3 mod 23.",
        "reference_links": [
            {"label": "ElGamal Encryption (Wikipedia)", "url": "https://en.wikipedia.org/wiki/ElGamal_encryption"},
            {"label": "Modular Exponentiation (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Modular_exponentiation"}
        ]
    },
    14: {
        "title": "Hash Functions",
        "type": "hash",
        "theory": "Hash functions (MDCs, MACs) provide one-way mapping and collision resistance. They ensure data integrity. Common algorithms: MD5 (broken), SHA-256 (secure).",
        "tool_name": "CrackStation",
        "external_tool_url": "https://crackstation.net/",
        "mission_cipher": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "correct_answer": "password",
        "hint": "SHA-256 of a common word.",
        "reference_links": [
            {"label": "SHA-2 (Wikipedia)", "url": "https://en.wikipedia.org/wiki/SHA-2"},
            {"label": "NIST FIPS 180-4 (Secure Hash Standard)", "url": "https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf"}
        ]
    },
    15: {
        "title": "Identification & Authentication",
        "type": "auth",
        "theory": "Authentication proves identity (passwords, biometrics). Dictionary attacks try common passwords. Challenge-Response protocols (like CHAP) prevent replay attacks.",
        "tool_name": "Password Strength Checker",
        "external_tool_url": "https://howsecureismypassword.net/",
        "mission_cipher": "What attack tries every word in a predefined list?",
        "correct_answer": "DICTIONARY ATTACK",
        "hint": "Two words. First word is a book of words.",
        "reference_links": [
            {"label": "Dictionary Attack (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Dictionary_attack"},
            {"label": "Password Cracking (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Password_cracking"}
        ]
    },
    16: {
        "title": "Extended Euclidean Algorithm",
        "type": "math",
        "theory": "The Extended Euclidean Algorithm finds integers x and y such that ax + by = gcd(a, b). These coefficients are crucial for computing modular inverses used in RSA and other cryptosystems.",
        "tool_name": "PlanetCalc Extended Euclidean",
        "external_tool_url": "https://planetcalc.com/3298/",
        "mission_cipher": "For a = 4864 and b = 3458, find x and y such that 4864x + 3458y = gcd(4864, 3458).",
        "correct_answer": "32,-45",
        "hint": "Extended Euclid gives gcd = 38. Enter as x,y with no spaces.",
        "reference_links": [
            {"label": "Extended Euclidean Algorithm (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm"},
            {"label": "Extended Euclidean Algorithm (CP-Algorithms)", "url": "https://cp-algorithms.com/algebra/extended-euclid-algorithm.html"}
        ]
    },
    17: {
        "title": "Modular Exponentiation",
        "type": "math",
        "theory": "The repeated square-and-multiply algorithm efficiently computes a^k mod n by scanning the bits of k and combining squaring with selective multiplication.",
        "tool_name": "PlanetCalc Modular Exponentiation",
        "external_tool_url": "https://planetcalc.com/8979/",
        "mission_cipher": "Compute 5^596 mod 1234 using the repeated square-and-multiply algorithm.",
        "correct_answer": "1013",
        "hint": "This matches the example result shown in standard modular exponentiation tables.",
        "reference_links": [
            {"label": "Modular Exponentiation (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Modular_exponentiation"},
            {"label": "Binary Exponentiation (CP-Algorithms)", "url": "https://cp-algorithms.com/algebra/binary-exp.html"}
        ]
    },
    18: {
        "title": "Rabin Public-Key Encryption",
        "type": "crypto",
        "theory": "Rabin encryption represents the message as an integer m in [0, n-1] and computes the ciphertext c = m^2 mod n using the public key n.",
        "tool_name": "PlanetCalc Modular Arithmetic",
        "external_tool_url": "https://planetcalc.com/8326/",
        "mission_cipher": "Rabin encryption: n = 899, message m = 123. Compute c = m^2 mod n.",
        "correct_answer": "745",
        "hint": "Square the message and reduce modulo n.",
        "reference_links": [
            {"label": "Rabin Cryptosystem (Wikipedia)", "url": "https://en.wikipedia.org/wiki/Rabin_cryptosystem"},
            {"label": "Rabin Cryptosystem Lecture Notes (BU CS 538)", "url": "https://www.cs.bu.edu/~reyzin/teaching/cryptonotes/notes-5.pdf"}
        ]
    }
}


@app.route('/')
def index():
    return render_template('index.html', modules=MODULE_DATA)


@app.route('/module/<int:module_id>', methods=['GET', 'POST'])
def module(module_id):
    module_data = MODULE_DATA.get(module_id)
    if not module_data:
        return redirect(url_for('index'))

    if request.method == 'POST':
        user_input = request.form.get('answer', '').strip()

        # Check answer
        is_correct = False

        # Normalize comparison (case-insensitive for text)
        if str(user_input).upper() == str(module_data['correct_answer']).upper():
            is_correct = True

        if is_correct:
            flash("Access Granted. Integrity Verified.", "success")
            return jsonify({"status": "success", "message": "Access Granted"})
        else:
            return jsonify({"status": "fail", "message": "Integrity Check Failed."})

    return render_template('module.html', module=module_data, module_id=module_id)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
