from flask import Blueprint, render_template, request, flash, session, jsonify
from .pqc import generate_keys, encrypt_message, decrypt_message, aes_encrypt, aes_decrypt

main = Blueprint('main', __name__)

@main.route("/", methods=["GET", "POST"])
def index():
    context = {
        'public_key': session.get('public_key', ''),
        'private_key': session.get('private_key', ''),
        'original_message': '',
        'kyber_ciphertext': '',
        'aes_ciphertext': '',
        'decrypted_message': '',
        'encryption_shared_secret': '',
        'decryption_shared_secret': ''
    }
    
    if request.method == "POST":
        action = request.form.get("action")

        try:
            if action == "generate":
                pk, sk = generate_keys()
                if pk and sk:
                    session['public_key'] = pk
                    session['private_key'] = sk
                    flash("Keys generated successfully!", "success")
                else:
                    flash("Error generating keys", "danger")

            elif action == "encrypt":
                msg = request.form.get("message", "").strip()
                context['original_message'] = msg
                pk = request.form.get("public_key", "").strip()
                
                if not msg or not pk:
                    flash("Both message and public key are required", "danger")
                else:
                    kyber_ct, shared_secret = encrypt_message(msg, pk)
                    if "error" in kyber_ct.lower():
                        flash(kyber_ct, "danger")
                        return render_template("index.html", **context)
                    
                    aes_ct = aes_encrypt(msg, shared_secret)
                    context.update({
                        'kyber_ciphertext': kyber_ct,
                        'aes_ciphertext': aes_ct,
                        'encryption_shared_secret': shared_secret
                    })
                    flash("Message encrypted!", "success")

            elif action == "decrypt":
                kyber_ct = request.form.get("kyber_ciphertext", "").strip()
                aes_ct = request.form.get("aes_ciphertext", "").strip()
                sk = request.form.get("private_key", "").strip()
                
                if not kyber_ct or not aes_ct or not sk:
                    flash("All fields are required for decryption", "danger")
                else:
                    shared_secret = decrypt_message(kyber_ct, sk)
                    if "error" in shared_secret.lower():
                        flash(shared_secret, "danger")
                        return render_template("index.html", **context)
                    
                    decrypted = aes_decrypt(aes_ct, shared_secret)
                    context.update({
                        'decrypted_message': decrypted,
                        'decryption_shared_secret': shared_secret,
                        'kyber_ciphertext': kyber_ct,
                        'aes_ciphertext': aes_ct
                    })
                    flash("Message decrypted!", "success")

        except Exception as e:
            flash(f"Error: {str(e)}", "danger")

    return render_template("index.html", **context)

