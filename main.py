from flask import Flask, request, jsonify, send_file
import requests
import os

app = Flask(__name__)

# Supabase configuration
SUPABASE_URL = os.environ.get('SUPABASE_URL')  # e.g., https://xxxxx.supabase.co
SUPABASE_KEY = os.environ.get('SUPABASE_ANON_KEY')

@app.route('/')
def index():
    """Serve the reset password page"""
    return send_file('reset.html')

@app.route('/api/auth/user/reset-confirm', methods=['POST'])
def reset_confirm():
    """Complete password reset using recovery token from email"""
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('new_password')
        
        if not token or not new_password:
            return jsonify({'error': 'Token and new password are required'}), 400
        
        # Validate password length
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        # Use the recovery token to update the user's password in Supabase Auth
        headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': f'Bearer {token}',  # Use the recovery token
            'Content-Type': 'application/json'
        }
        
        # Update password using Supabase GoTrue API
        response = requests.put(
            f'{SUPABASE_URL}/auth/v1/user',
            headers=headers,
            json={'password': new_password}
        )
        
        if response.status_code == 200:
            return jsonify({'message': 'Password updated successfully'}), 200
        else:
            error_data = response.json()
            error_msg = error_data.get('msg') or error_data.get('error_description') or 'Failed to update password'
            return jsonify({'error': error_msg}), response.status_code
            
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Network error: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500
        
@app.route('/api/auth/user/reset', methods=['POST'])
def reset_password():
    """Send password reset email"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        headers = {
            'apikey': SUPABASE_KEY,
            'Content-Type': 'application/json'
        }
        
        # Send recovery email with proper redirect URL
        response = requests.post(
            f'{SUPABASE_URL}/auth/v1/recover',
            headers=headers,
            json={
                'email': email,
                'options': {
                    'redirectTo': 'https://reset-production.up.railway.app'
                }
            }
        )
        
        if response.status_code in [200, 201]:
            return jsonify({'message': 'Reset email sent'}), 200
        else:
            error_msg = response.json().get('msg', 'Failed to send reset email')
            return jsonify({'error': error_msg}), response.status_code
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
